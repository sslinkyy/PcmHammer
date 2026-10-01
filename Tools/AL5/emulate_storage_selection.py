"""Offline storage selector/restore caller with destructive calls trapped.

Synthetic banks are read-only to firmware. No erase/program implementation,
adapter API, transport or vehicle access is available.
"""
import argparse
import json
from pathlib import Path
from al5_segment import sha256
from checksum import crc16
from emulate_application_boot import LOW_HASH, HIGH_HASH

RANGES = [(0x22250, 0x2266A), (0x2266C, 0x226F0), (0x226F0, 0x228D8)]
BASE, STACK, RETURN = 0xFF8000, 0x208800, 0x300000
CONTEXT_SIZE = 0x9F2


class Selection:
    def __init__(self, low, high, *, marker1=0xFFAA, marker2=0,
                 bad_header1=False, bad_header2=False, count1=10, count2=9,
                 cached=0, bad_context_crc=False):
        from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_PROT_READ, UC_PROT_EXEC
        from unicorn.m68k_const import UC_CPU_M68K_M68020
        if sha256(low) != LOW_HASH or sha256(high) != HIGH_HASH:
            raise ValueError('unexpected saved firmware evidence')
        self.uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
        self.uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
        self.uc.mem_map(0, 0x100000)
        data = low+high
        for a, b in RANGES: self.uc.mem_write(a, data[a:b])
        signature = data[0x21422:0x21426]
        self.uc.mem_write(0x21422, signature)
        self.bank_hashes = {}
        self.contexts = {}
        for bank, marker, bad_header, count in ((0x4000, marker1, bad_header1, count1), (0x6000, marker2, bad_header2, count2)):
            image = bytearray(b'\xff'*0x2000)
            image[:2] = signature[:2] if not bad_header else b'\x00\x00'
            image[2:4] = (int.from_bytes(signature[2:], 'big') | 0xFF).to_bytes(2, 'big')
            image[4:6] = count.to_bytes(2, 'big')
            image[0x28:0x2A] = marker.to_bytes(2, 'big')
            context = bytearray((i*29+(bank >> 12)) & 255 for i in range(CONTEXT_SIZE))
            context[-2:] = crc16(context[:-2]).to_bytes(2, 'big')
            if bad_context_crc: context[-1] ^= 1
            image[0x2A:0x2A+CONTEXT_SIZE] = context
            self.contexts[bank] = bytes(context)
            self.bank_hashes[hex(bank)] = sha256(image)
            self.uc.mem_write(bank, bytes(image))
        self.uc.mem_protect(0, 0x100000, UC_PROT_READ | UC_PROT_EXEC)
        self.uc.mem_map(BASE, 0x8000)
        self.uc.mem_map(0x200000, 0x10000)
        self.uc.mem_map(RETURN, 0x1000)
        self.uc.mem_write(BASE+0xE64, cached.to_bytes(4, 'big'))
        self.uc.mem_write(BASE+0x140, b'\xa5'*CONTEXT_SIZE)
        self.uc.hook_add(UC_HOOK_CODE, self.hook)
        self.uc.hook_add(UC_HOOK_MEM_INVALID, self.invalid_memory)

    def invalid_memory(self, machine, access, address, size, value, user_data):
        from unicorn.m68k_const import UC_M68K_REG_PC
        raise RuntimeError(f'invalid synthetic memory access {access} at {address:#x}, size {size}, PC {machine.reg_read(UC_M68K_REG_PC):#x}')

    def hook(self, machine, pc, size, user_data):
        from unicorn.m68k_const import UC_M68K_REG_A7
        if pc in (0x22B18, 0x22C3C, 0x22CF0):
            sp = machine.reg_read(UC_M68K_REG_A7)
            count = 2 if pc == 0x22B18 else 4
            arguments = [hex(int.from_bytes(machine.mem_read(sp+4+i*4, 4), 'big')) for i in range(count)]
            self.observed['storage_trap'] = {'entry': hex(pc), 'arguments': arguments,
                                             'implementation_executed': False}
            machine.emu_stop()  # before any storage primitive instruction
        elif not any(a <= pc < b for a, b in RANGES):
            raise RuntimeError(f'execution escaped selector/caller at {pc:#x}')

    def run(self, operation):
        from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_A5, UC_M68K_REG_SR, UC_M68K_REG_PC, UC_M68K_REG_D0
        entry = {'select': 0x22250, 'restore': 0x2266C, 'update': 0x226F0}[operation]
        self.observed = {'storage_trap': None}
        arguments = b'' if operation == 'select' else (BASE+0x140).to_bytes(4, 'big')
        self.uc.mem_write(STACK, RETURN.to_bytes(4, 'big')+arguments)
        self.uc.reg_write(UC_M68K_REG_SR, 0x2000)
        self.uc.reg_write(UC_M68K_REG_A7, STACK)
        self.uc.reg_write(UC_M68K_REG_A5, BASE)
        self.uc.emu_start(entry, RETURN, timeout=5_000_000, count=100_000)
        returned = self.uc.reg_read(UC_M68K_REG_PC) == RETURN
        if not returned and self.observed['storage_trap'] is None:
            raise RuntimeError('emulator did not return or trap within limits')
        self.observed['returned'] = returned
        self.observed['return_d0'] = hex(self.uc.reg_read(UC_M68K_REG_D0)) if returned else None
        self.observed['cached_pointer'] = hex(int.from_bytes(self.uc.mem_read(BASE+0xE64, 4), 'big'))
        self.observed['selected_record_state'] = hex(int.from_bytes(self.uc.mem_read(BASE+0x1E, 2), 'big'))
        restored = bytes(self.uc.mem_read(BASE+0x140, CONTEXT_SIZE))
        self.observed['restored_context_sha256'] = sha256(restored)
        self.observed['restored_context_crc_matches'] = int.from_bytes(restored[-2:], 'big') == crc16(restored[:-2])
        self.observed['synthetic_banks_unchanged'] = all(sha256(bytes(self.uc.mem_read(int(bank, 0), 0x2000))) == digest for bank, digest in self.bank_hashes.items())
        if not self.observed['synthetic_banks_unchanged']: raise RuntimeError('synthetic storage changed')
        return self.observed


def run_cases(low, high):
    trials = [
        ('bank1_committed', {}, 'select', {'return_d0': '0x4028', 'selected_record_state': '0xffaa'}),
        ('bank2_committed', {'marker1': 0, 'marker2': 0xFFAA}, 'select', {'return_d0': '0x6028', 'selected_record_state': '0xffaa'}),
        ('both_committed_prefers_bank1_despite_count', {'marker2': 0xFFAA, 'count1': 1, 'count2': 200}, 'select', {'return_d0': '0x4028'}),
        ('bank1_pending_precedes_bank2_commit', {'marker1': 0xAA, 'marker2': 0xFFAA}, 'select', {'return_d0': '0x4028', 'selected_record_state': '0xaa'}),
        ('cached_pointer_returns_without_record_validation', {'cached': 0x208000}, 'select', {'return_d0': '0x208000', 'selected_record_state': '0x0'}),
        ('missing_commit_calls_repair', {'marker1': 0, 'marker2': 0}, 'select', {'returned': False}),
        ('bank2_pending_not_selected_as_committed', {'marker1': 0, 'marker2': 0xAA}, 'select', {'returned': False}),
        ('bad_bank2_header_repair_can_erase_committed_bank1', {'bad_header2': True}, 'select', {'returned': False}),
        ('bad_header_checked_before_cached_pointer', {'bad_header1': True, 'cached': 0x6028}, 'select', {'returned': False}),
        ('restore_committed_bank1', {}, 'restore', {'return_d0': '0x0', 'restored_context_crc_matches': True}),
        ('restore_committed_bank2', {'marker1': 0, 'marker2': 0xFFAA}, 'restore', {'return_d0': '0x0', 'restored_context_crc_matches': True}),
        ('pending_record_not_restored', {'marker1': 0xAA}, 'restore', {'return_d0': '0x1'}),
        ('restore_does_not_validate_context_crc', {'bad_context_crc': True}, 'restore', {'return_d0': '0x0', 'restored_context_crc_matches': False}),
        ('update_bank1_active_erases_other_bank', {}, 'update', {'returned': False}),
        ('update_bank2_active_erases_other_bank', {'marker1': 0, 'marker2': 0xFFAA}, 'update', {'returned': False}),
    ]
    records = []
    for label, inputs, operation, expected in trials:
        session = Selection(low, high, **inputs)
        actual = session.run(operation)
        passed = all(actual[key] == value for key, value in expected.items())
        if not actual['returned']:
            destination = '0x6000' if label == 'update_bank1_active_erases_other_bank' else '0x4000'
            passed &= actual['storage_trap']['entry'] == '0x22b18' and actual['storage_trap']['arguments'][1] == destination
        if label.startswith('restore_committed'):
            bank = 0x6000 if label.endswith('bank2') else 0x4000
            passed &= actual['restored_context_sha256'] == sha256(session.contexts[bank])
        records.append({'case': label, 'synthetic_state': inputs, 'operation': operation,
                        'expected': expected, 'observed': actual, 'pass': bool(passed)})
        print(label, 'PASS' if passed else 'FAIL', json.dumps(actual))
    return {'low_sha256': sha256(low), 'high_sha256': sha256(high),
            'code_sha256': {hex(a): sha256((low+high)[a:b]) for a, b in RANGES},
            'scope': 'Synthetic read-only banks; selector/restore/update callers only; every destructive call stopped before implementation execution.',
            'context_bytes': CONTEXT_SIZE, 'flash_implementation_executed': False,
            'live_write_enabled': False, 'all_pass': all(record['pass'] for record in records), 'cases': records}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('low', 'high', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    report = run_cases(args.low.read_bytes(), args.high.read_bytes())
    args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
    raise SystemExit(0 if report['all_pass'] else 1)
