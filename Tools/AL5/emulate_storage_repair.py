"""Offline repair caller and bounded wrapper-error branches; no flash execution."""
import argparse
import json
from pathlib import Path
from al5_segment import sha256
from emulate_storage_selection import Selection, BASE, STACK, RETURN, CONTEXT_SIZE, RANGES
from emulate_storage_recovery import Update, begin, reboot

ERROR_RANGES = [(0x22CAE, 0x22CC4), (0x22DA8, 0x22DBE)]


class Repair(Update):
    def __init__(self, low, high, *, missing_commit=False, erase_status=0, **kwargs):
        super().__init__(low, high, active_bank=0x4000, **kwargs)
        if missing_commit:
            for bank in (0x4000, 0x6000): self.uc.mem_write(bank+0x28, b'\x00\x00')
        self.erase_status = erase_status
        self.low, self.high = low, high

    def hook(self, machine, pc, size, user_data):
        from unicorn.m68k_const import UC_M68K_REG_A7
        if pc == 0x22B18:
            sp = machine.reg_read(UC_M68K_REG_A7)
            status = int.from_bytes(machine.mem_read(sp+4, 4), 'big')
            super().hook(machine, pc, size, user_data)
            # Deliberately vary returned status after an atomic modeled erase.
            # This tests caller status handling, not failed-erase flash effects.
            machine.mem_write(status, self.erase_status.to_bytes(2, 'big'))
            self.operations[-1]['returned_status'] = hex(self.erase_status)
        else:
            super().hook(machine, pc, size, user_data)

    def repair(self):
        from unicorn.m68k_const import UC_M68K_REG_PC, UC_M68K_REG_D0
        if self.cut_after == 0:
            self.interrupted = True
        else:
            begin(self, 0x22250)
            if not self.interrupted and self.uc.reg_read(UC_M68K_REG_PC) != RETURN:
                raise RuntimeError('repair caller did not return within limits')
        banks = {a: bytes(self.uc.mem_read(a, 0x2000)) for a in (0x4000, 0x6000)}
        result = {'operations': self.operations,
                  'returned': not self.interrupted,
                  'selected_record': hex(self.uc.reg_read(UC_M68K_REG_D0)) if not self.interrupted else None,
                  'selected_state': hex(int.from_bytes(self.uc.mem_read(BASE+0x1E, 2), 'big')),
                  'bank_metadata': [{'start': hex(a), 'generation_word': int.from_bytes(b[4:6], 'big'),
                                     'record_marker': b[0x28:0x2A].hex(),
                                     'context_erased': b[0x2A:0x2A+CONTEXT_SIZE] == b'\xff'*CONTEXT_SIZE,
                                     'tail_erased': b[0xA4C:] == b'\xff'*0x15B4,
                                     'header_metadata_matches_original_bank1': b[6:0x28] == self.original_banks[0x4000][6:0x28],
                                     'bank_sha256': sha256(b)} for a, b in banks.items()],
                  'reboot_selection': reboot(self.low, self.high, banks)}
        return result


class WrapperError(Selection):
    def __init__(self, low, high):
        super().__init__(low, high)
        for a, b in ERROR_RANGES: self.uc.mem_write(a, (low+high)[a:b])
        self.stop = None

    def hook(self, machine, pc, size, user_data):
        from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_PC
        if pc in (0x22CC2, 0x22CC4, 0x22DBC, 0x22DBE):
            self.stop = hex(pc)
            machine.emu_stop()
        elif pc == 0x21D08:
            sp = machine.reg_read(UC_M68K_REG_A7)
            machine.reg_write(UC_M68K_REG_PC, int.from_bytes(machine.mem_read(sp, 4), 'big'))
            machine.reg_write(UC_M68K_REG_A7, sp+4)
        elif not any(a <= pc < b for a, b in ERROR_RANGES):
            super().hook(machine, pc, size, user_data)

    def check(self, entry, status):
        from unicorn.m68k_const import UC_M68K_REG_A6
        frame = STACK-0x1000
        self.uc.reg_write(UC_M68K_REG_A6, frame)
        self.uc.mem_write(frame-0x134, bytes([status, 0]))
        begin(self, entry)
        if self.stop is None: raise RuntimeError('error branch escaped bounded endpoints')
        return {'stop_pc': self.stop, 'marker': hex(int.from_bytes(self.uc.mem_read(BASE, 2), 'big'))}


def run_cases(low, high):
    repairs = []
    scenarios = [
        ('bad_bank2_header_with_committed_bank1', {'bad_header2': True}),
        ('bad_bank1_header', {'bad_header1': True}),
        ('both_valid_headers_no_commits', {'missing_commit': True}),
        ('erased_generation_normalized', {'missing_commit': True, 'count1': 0xFFFF, 'count2': 0xFFFF}),
        ('generation_wrap', {'missing_commit': True, 'count1': 0xFFFE, 'count2': 0xFFFE}),
        ('erase_error_status_returned_after_atomic_erase', {'missing_commit': True, 'erase_status': 0x2000}),
    ]
    for label, inputs in scenarios:
        session = Repair(low, high, **inputs)
        observed = session.repair()
        ops = observed['operations']
        expected = [(0x22B18, 0x4000, 8192), (0x22C3C, 0x4000, 42),
                    (0x22B18, 0x6000, 8192), (0x22C3C, 0x6000, 42)]
        passed = [(int(o['entry'], 0), int(o['destination'], 0), o['bytes']) for o in ops] == expected
        passed &= observed['returned'] and observed['selected_record'] == '0x4028' and observed['selected_state'] == '0xaa'
        counts = (1, 2) if label == 'erased_generation_normalized' else ((0xFFFF, 0) if label == 'generation_wrap' else (11, 12))
        passed &= tuple(b['generation_word'] for b in observed['bank_metadata']) == counts
        passed &= [b['record_marker'] for b in observed['bank_metadata']] == ['00aa', '0000']
        passed &= all(b['context_erased'] and b['tail_erased'] and b['header_metadata_matches_original_bank1'] for b in observed['bank_metadata'])
        passed &= observed['reboot_selection']['selected_record'] == '0x4028'
        repairs.append({'case': label, 'inputs': inputs, 'observed': observed, 'pass': bool(passed)})
    interruptions = []
    for cut in range(5):
        session = Repair(low, high, missing_commit=True, cut_after=cut)
        observed = session.repair()
        # After first-header programming the original second header is still
        # valid; erasing bank2 then invalidates it until its header is rewritten.
        rebooted = observed['reboot_selection']
        passed = rebooted['selected_record'] == ('0x4028' if cut in (2, 4) else None)
        if cut not in (2, 4):
            passed &= rebooted['storage_trap']['entry'] == '0x22b18'
        interruptions.append({'interrupt_after_operations': cut, 'observed': observed, 'pass': bool(passed)})
    update_repairs = []
    for active in (0x4000, 0x6000):
        for cut in (1, 2):
            update = Update(low, high, active_bank=active, cut_after=cut)
            banks = update.update()
            session = Repair(low, high)
            for address, bank in banks.items():
                session.uc.mem_write(address, bank)
                session.original_banks[address] = bank
            observed = session.repair()
            passed = observed['returned'] and observed['selected_record'] == '0x4028' and observed['selected_state'] == '0xaa'
            passed &= all(b['context_erased'] and b['tail_erased'] for b in observed['bank_metadata'])
            passed &= len(observed['operations']) == 4
            update_repairs.append({'active_bank_before_update': hex(active), 'update_interrupted_after_operations': cut,
                                   'observed': observed, 'pass': bool(passed)})
    errors = []
    for entry, success, failure in ((0x22CAE, '0x22cc4', '0x22cc2'), (0x22DA8, '0x22dbe', '0x22dbc')):
        for status in (0, 0x20):
            observed = WrapperError(low, high).check(entry, status)
            expected = {'stop_pc': failure if status else success, 'marker': '0x6124' if status else '0x0'}
            errors.append({'entry': hex(entry), 'synthetic_status_byte': hex(status),
                           'observed': observed, 'expected': expected, 'pass': observed == expected})
    return {'low_sha256': sha256(low), 'high_sha256': sha256(high),
            'code_sha256': {hex(a): sha256((low+high)[a:b]) for a, b in RANGES+ERROR_RANGES},
            'scope': 'Real selector repair caller with successful atomic synthetic bank operations; bounded program/copy error branches with synthetic status. No flash implementation execution.',
            'model_limits': 'Bank spans assumed; no failed-erase contents, partial programming, timing or physical reset/recovery simulation. Status-mask helper bypassed in wrapper error slices.',
            'repair_cases': repairs, 'interruption_cases': interruptions,
            'interrupted_update_repair_cases': update_repairs, 'wrapper_error_cases': errors,
            'all_pass': all(c['pass'] for c in repairs+interruptions+update_repairs+errors),
            'flash_implementation_executed': False, 'physical_recovery_verified': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('low', 'high', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    report = run_cases(args.low.read_bytes(), args.high.read_bytes())
    args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
    print(json.dumps({'all_pass': report['all_pass'], 'cases': sum(len(report[k]) for k in ('repair_cases', 'interruption_cases', 'interrupted_update_repair_cases', 'wrapper_error_cases'))}))
    raise SystemExit(0 if report['all_pass'] else 1)
