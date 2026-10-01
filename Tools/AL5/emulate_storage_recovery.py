"""Offline caller execution with synthetic atomic storage operations only.

No flash implementation is loaded/executed. Host hooks model bank changes;
operation-boundary interruptions do not establish physical recovery safety.
"""
import argparse
import json
from pathlib import Path
from al5_segment import sha256
from checksum import crc16
from emulate_storage_selection import Selection, RANGES, BASE, STACK, RETURN, CONTEXT_SIZE

VALIDATION_RANGES = [(0x5B92E, 0x5B96E), (0xA95D0, 0xA960A)]


def require_programmable(old, payload):
    if len(old) != len(payload) or any((a & b) != b for a, b in zip(old, payload)):
        raise ValueError('synthetic program requires an erase (zero-to-one transition)')


def begin(session, entry, arguments=b''):
    from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_A5, UC_M68K_REG_SR
    session.observed = {'storage_trap': None}
    session.uc.mem_write(STACK, RETURN.to_bytes(4, 'big')+arguments)
    session.uc.reg_write(UC_M68K_REG_SR, 0x2000)
    session.uc.reg_write(UC_M68K_REG_A7, STACK)
    session.uc.reg_write(UC_M68K_REG_A5, BASE)
    session.uc.emu_start(entry, RETURN, timeout=5_000_000, count=100_000)


class Validation(Selection):
    def __init__(self, low, high, **kwargs):
        super().__init__(low, high, **kwargs)
        data = low+high
        for a, b in VALIDATION_RANGES: self.uc.mem_write(a, data[a:b])
        self.uc.mem_write(0xAA610, data[0xAA610:0xAA810])
        self.stop = None

    def hook(self, machine, pc, size, user_data):
        from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_PC
        if pc in (0x5B96E, 0x5B96C, 0x5BA24):
            self.stop = hex(pc)
            machine.emu_stop()
        elif pc == 0x21D08:
            # Status-mask helper is bypassed only on the CRC-error path.
            sp = machine.reg_read(UC_M68K_REG_A7)
            machine.reg_write(UC_M68K_REG_PC, int.from_bytes(machine.mem_read(sp, 4), 'big'))
            machine.reg_write(UC_M68K_REG_A7, sp+4)
        elif not any(a <= pc < b for a, b in VALIDATION_RANGES):
            super().hook(machine, pc, size, user_data)

    def validate(self):
        begin(self, 0x5B92E)
        if self.stop is None and self.observed['storage_trap'] is None:
            raise RuntimeError('validation did not reach a bounded endpoint')
        return {'stop_pc': self.stop,
                'marker': hex(int.from_bytes(self.uc.mem_read(BASE, 2), 'big')),
                'storage_trap': self.observed['storage_trap'],
                'banks_unchanged': all(sha256(bytes(self.uc.mem_read(int(a, 0), 0x2000))) == h for a, h in self.bank_hashes.items())}


class Update(Selection):
    def __init__(self, low, high, *, active_bank, cut_after=None, **kwargs):
        super().__init__(low, high, marker1=0xFFAA if active_bank == 0x4000 else 0,
                         marker2=0xFFAA if active_bank == 0x6000 else 0, **kwargs)
        self.operations = []
        self.cut_after = cut_after
        self.interrupted = False
        self.original_banks = {}
        for bank in (0x4000, 0x6000):
            image = bytearray(self.uc.mem_read(bank, 0x2000))
            image[6:0x28] = bytes((i*13+(bank >> 12)) & 255 for i in range(0x22))
            image[0xA4C:] = bytes((i*7+(bank >> 12)) & 255 for i in range(0x15B4))
            self.original_banks[bank] = bytes(image)
            self.uc.mem_write(bank, bytes(image))
        context = bytearray((i*17+91) & 255 for i in range(CONTEXT_SIZE))
        context[-2:] = crc16(context[:-2]).to_bytes(2, 'big')
        self.new_context = bytes(context)
        self.uc.mem_write(BASE+0x140, self.new_context)

    def hook(self, machine, pc, size, user_data):
        from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_PC
        if pc not in (0x22B18, 0x22C3C, 0x22CF0):
            return super().hook(machine, pc, size, user_data)
        sp = machine.reg_read(UC_M68K_REG_A7)
        count = 2 if pc == 0x22B18 else 4
        args = [int.from_bytes(machine.mem_read(sp+4+i*4, 4), 'big') for i in range(count)]
        if pc == 0x22B18:
            status, destination = args
            length, source = 0x2000, None
            payload = b'\xff'*length
            kind = 'synthetic_erase'
        else:
            status, source, destination, words = args
            length = 2*(words & 0xFFFF)
            payload = bytes(machine.mem_read(source, length))
            old = bytes(machine.mem_read(destination, length))
            require_programmable(old, payload)
            kind = 'synthetic_tail_copy' if pc == 0x22CF0 else 'synthetic_program'
        if not any(a <= destination and destination+length <= a+0x2000 for a in (0x4000, 0x6000)):
            raise RuntimeError('model operation escaped synthetic banks')
        # Host writes bypass ROM protection; firmware writes remain prohibited.
        machine.mem_write(destination, payload)
        machine.mem_write(status, b'\x00\x00')
        self.operations.append({'entry': hex(pc), 'kind': kind, 'destination': hex(destination),
                                'bytes': length, 'source': hex(source) if source is not None else None,
                                'payload_sha256': sha256(payload),
                                'word': payload.hex() if length == 2 else None,
                                'implementation_executed': False})
        if self.cut_after == len(self.operations):
            self.interrupted = True
            machine.emu_stop()
            return
        machine.reg_write(UC_M68K_REG_PC, int.from_bytes(machine.mem_read(sp, 4), 'big'))
        machine.reg_write(UC_M68K_REG_A7, sp+4)

    def update(self):
        from unicorn.m68k_const import UC_M68K_REG_PC
        if self.cut_after == 0:
            self.interrupted = True
        else:
            begin(self, 0x226F0, (BASE+0x140).to_bytes(4, 'big'))
            if not self.interrupted and self.uc.reg_read(UC_M68K_REG_PC) != RETURN:
                raise RuntimeError('update caller did not return within limits')
        return {a: bytes(self.uc.mem_read(a, 0x2000)) for a in (0x4000, 0x6000)}


def reboot(low, high, banks):
    session = Selection(low, high)
    for a, bank in banks.items():
        session.uc.mem_write(a, bank)
        session.bank_hashes[hex(a)] = sha256(bank)
    observed = session.run('select')
    selected = int(observed['return_d0'], 0) if observed['returned'] else None
    context_hash = None
    if selected in (0x4028, 0x6028):
        context_hash = sha256(banks[selected-0x28][0x2A:0x2A+CONTEXT_SIZE])
    return {'selected_record': observed['return_d0'],
            'selected_context_sha256': context_hash,
            'storage_trap': observed['storage_trap'],
            'banks_unchanged_during_selection': observed['synthetic_banks_unchanged']}


def run_cases(low, high):
    validation = []
    for label, inputs, stop, marker in [
        ('committed_valid_crc', {}, '0x5b96e', '0x0'),
        ('committed_bad_crc', {'bad_context_crc': True}, '0x5b96c', '0x8c9b'),
        ('pending_bypasses_crc_path', {'marker1': 0xAA}, '0x5ba24', '0x0'),
    ]:
        observed = Validation(low, high, **inputs).validate()
        passed = observed['stop_pc'] == stop and observed['marker'] == marker and observed['banks_unchanged']
        validation.append({'case': label, 'observed': observed, 'pass': passed})
    transactions = []
    for active in (0x4000, 0x6000):
        for cut in range(8):
            session = Update(low, high, active_bank=active, cut_after=cut)
            banks = session.update()
            observed = reboot(low, high, banks)
            other = 0x6000 if active == 0x4000 else 0x4000
            expected = None if cut in (1, 2) else (0x4000 if cut == 6 else (other if cut == 7 else active))
            passed = observed['selected_record'] == (hex(expected+0x28) if expected else None)
            if expected is None:
                passed &= observed['storage_trap']['entry'] == '0x22b18'
                passed &= observed['storage_trap']['arguments'][1] == '0x4000'
            else:
                expected_hash = sha256(session.new_context if expected == other else session.contexts[active])
                passed &= observed['selected_context_sha256'] == expected_hash
            passed &= observed['banks_unchanged_during_selection']
            transactions.append({'active_bank': hex(active), 'interrupt_after_operations': cut,
                                 'expected_selected_record': hex(expected+0x28) if expected else None,
                                 'operations': session.operations, 'reboot_selection': observed,
                                 'pass': bool(passed)})
        session = Update(low, high, active_bank=active)
        banks = session.update()
        observed = reboot(low, high, banks)
        other = 0x6000 if active == 0x4000 else 0x4000
        expected = [(other, 0x2000, None), (other+0xA4C, 0x15B4, None),
                    (other, 40, None), (other+0x28, 2, 'fffe'),
                    (other+0x2A, CONTEXT_SIZE, None), (other+0x28, 2, 'ffaa'),
                    (active+0x28, 2, '0000')]
        actual = [(int(o['destination'], 0), o['bytes'], o['word']) for o in session.operations]
        passed = actual == expected and observed['selected_record'] == hex(other+0x28)
        passed &= observed['selected_context_sha256'] == sha256(session.new_context)
        passed &= int.from_bytes(session.uc.mem_read(BASE+0xE64, 4), 'big') == 0
        passed &= observed['banks_unchanged_during_selection']
        preservation = {
            'tail_matches_old_active_bank': banks[other][0xA4C:] == session.original_banks[active][0xA4C:],
            'header_metadata_matches_bank_4000': banks[other][6:0x28] == session.original_banks[0x4000][6:0x28],
            'generation_word': int.from_bytes(banks[other][4:6], 'big')}
        passed &= preservation['tail_matches_old_active_bank'] and preservation['header_metadata_matches_bank_4000']
        passed &= preservation['generation_word'] == 11
        transactions.append({'active_bank': hex(active), 'interrupt_after_operations': None,
                             'operations': session.operations, 'reboot_selection': observed,
                             'synthetic_preservation': preservation, 'pass': bool(passed)})
    records = validation+transactions
    return {'low_sha256': sha256(low), 'high_sha256': sha256(high),
            'code_sha256': {hex(a): sha256((low+high)[a:b]) for a, b in RANGES+VALIDATION_RANGES},
            'scope': 'Bounded real callers/CRC; storage effects modeled atomically by host hooks. No flash implementation or hardware execution.',
            'model_limits': 'Successful atomic calls only; no partial-word effects, physical erase geometry, timing, status failures or completed repair emulation.',
            'validation_cases': validation, 'transaction_cases': transactions,
            'all_pass': all(c['pass'] for c in records),
            'flash_implementation_executed': False, 'physical_recovery_verified': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('low', 'high', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    report = run_cases(args.low.read_bytes(), args.high.read_bytes())
    args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
    print(json.dumps({'all_pass': report['all_pass'], 'validation_cases': len(report['validation_cases']),
                      'transaction_cases': len(report['transaction_cases'])}))
    raise SystemExit(0 if report['all_pass'] else 1)
