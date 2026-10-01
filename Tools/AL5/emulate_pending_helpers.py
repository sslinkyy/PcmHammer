"""Remaining pending-path helpers offline; no flash, transport or full startup."""
import argparse
import json
from pathlib import Path
from al5_segment import sha256
from checksum import crc16
from emulate_pending_initialization import Initialization, RANGES as FIRST_RANGES, START, intervals
from emulate_storage_selection import BASE, CONTEXT_SIZE, RANGES as STORAGE_RANGES
from emulate_storage_recovery import begin, Update, reboot
from emulate_receive_preparation import STUBS

HELPERS = [(0x55298, 0x55632), (0xBAED4, 0xBAFA8), (0x67BC8, 0x67C14),
           (0x590A0, 0x590C2), (0x5D894, 0x5D8E4), (0xC4538, 0xC4576),
           (0x60AE8, 0x60AF6), (0x90E48, 0x90E7C), (0xA44D0, 0xA44E0),
           (0xA4228, 0xA425A), (0xC5938, 0xC593A), (0x622F4, 0x62306)]
DEPENDENCIES = [(0x97218, 0x974EA), (0xC3B6C, 0xC3BB8), (0xA9D8C, 0xA9DC8)]
RANGES = HELPERS+DEPENDENCIES+[(0x5BA5E, 0x5BAA6)]
PREPARATION_RANGES = [(0x5BAB8, 0x5BB6E), (0x21D08, 0x21D1E), (0xA95D0, 0xA960A)]


class Remaining(Initialization):
    def __init__(self, low, high, *, fill=0xA5, selector=0):
        super().__init__(low, high, fill=fill)
        for a, b in RANGES: self.uc.mem_write(a, (low+high)[a:b])
        self.uc.mem_write(0x67D46, (low+high)[0x67D46:0x67D52])
        self.uc.mem_write(BASE+0x2DA7, bytes([selector]))
        self.root_helpers = []
        self.context = None
        self.preparing = False
        self.preparation_calls = []
        self.storage_call = None
        self.low, self.high = low, high
        for a, b in PREPARATION_RANGES: self.uc.mem_write(a, (low+high)[a:b])
        self.uc.mem_write(0xAA610, (low+high)[0xAA610:0xAA810])
        self.uc.mem_map(0xFFFFF000, 0x1000)  # synthetic watchdog alias

    def hook(self, machine, pc, size, user_data):
        from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_PC
        if self.preparing and pc in STUBS:
            sp = machine.reg_read(UC_M68K_REG_A7)
            self.preparation_calls.append(hex(pc))
            if pc == 0x226F0:
                self.storage_call = {'entry': hex(pc), 'source': hex(int.from_bytes(machine.mem_read(sp+4, 4), 'big'))}
                machine.emu_stop()  # real storage entry intercepted before execution
            else:
                # Unknown subsystem effects are intentionally omitted.
                machine.reg_write(UC_M68K_REG_PC, int.from_bytes(machine.mem_read(sp, 4), 'big'))
                machine.reg_write(UC_M68K_REG_A7, sp+4)
        elif self.preparing and any(a <= pc < b for a, b in PREPARATION_RANGES):
            pass
        elif pc == 0x5BAA6:
            self.stopped = hex(pc)
            machine.emu_stop()  # before status restoration and partial-caller epilogue
        elif any(a <= pc < b for a, b in RANGES):
            if pc in [a for a, b in HELPERS]: self.root_helpers.append(hex(pc))
        else:
            super().hook(machine, pc, size, user_data)

    def complete_helpers(self):
        restore = self.run('restore')
        if restore['return_d0'] != '0x1': raise RuntimeError('expected pending restore failure')
        begin(self, 0x5BA24)
        if self.stopped != '0x5baa6': raise RuntimeError('pending helper sequence escaped bounded endpoint')
        self.context = bytes(self.uc.mem_read(START, CONTEXT_SIZE))
        self.initialization_written = set(self.written)
        untouched = set(range(CONTEXT_SIZE))-self.written
        return {'stop_pc': self.stopped, 'remaining_helpers_executed': self.root_helpers,
                'context_sha256': sha256(self.context), 'context_bytes_written': len(self.written),
                'written_intervals': intervals(self.written), 'untouched_intervals': intervals(untouched),
                'untouched_bytes_retain_sentinel': all(self.context[i] == self.fill for i in untouched),
                'crc_word_untouched': not ({CONTEXT_SIZE-2, CONTEXT_SIZE-1} & self.written),
                'stored_crc': hex(int.from_bytes(self.context[-2:], 'big')), 'computed_crc': hex(crc16(self.context[:-2])),
                'banks_unchanged': all(sha256(bytes(self.uc.mem_read(int(a, 0), 0x2000))) == h for a, h in self.bank_hashes.items())}

    def preparation_and_modeled_commit(self):
        self.preparing = True
        begin(self, 0x5BAB8)
        if self.storage_call != {'entry': '0x226f0', 'source': '0xff8140'}:
            raise RuntimeError('preparation escaped expected storage interception')
        prepared = bytes(self.uc.mem_read(START, CONTEXT_SIZE))
        self.prepared_context = prepared
        valid_crc = int.from_bytes(prepared[-2:], 'big') == crc16(prepared[:-2])
        update = Update(self.low, self.high, active_bank=0x4000)
        for a in (0x4000, 0x6000): update.uc.mem_write(a, bytes(self.uc.mem_read(a, 0x2000)))
        update.uc.mem_write(START, prepared)
        banks = update.update()
        selected = reboot(self.low, self.high, banks)
        matched = selected['selected_record'] == '0x6028' and selected['selected_context_sha256'] == sha256(prepared)
        return {'preparation_subsystem_calls_bypassed': self.preparation_calls[:-1],
                'intercepted_storage_call': self.storage_call,
                'prepared_context_sha256': sha256(prepared), 'prepared_context_crc_matches': valid_crc,
                'prepared_crc_word': hex(int.from_bytes(prepared[-2:], 'big')),
                'modeled_commit_operations': update.operations, 'modeled_reboot_selection': selected,
                'modeled_committed_context_matches_prepared': matched,
                'real_storage_implementation_executed': False}


def run_cases(low, high):
    records, comparisons = [], []
    for selector in (0, 1):
        sessions = []
        for fill in (0xA5, 0x5A):
            session = Remaining(low, high, fill=fill, selector=selector)
            observed = session.complete_helpers()
            persistence = session.preparation_and_modeled_commit()
            passed = observed['banks_unchanged'] and observed['crc_word_untouched'] and observed['untouched_bytes_retain_sentinel']
            passed &= observed['remaining_helpers_executed'] == [hex(a) for a, b in HELPERS]
            passed &= persistence['prepared_context_crc_matches'] and persistence['modeled_committed_context_matches_prepared']
            records.append({'synthetic_selector_2da7': selector, 'synthetic_ram_fill': hex(fill),
                            'observed': observed, 'preparation_and_modeled_commit': persistence, 'pass': bool(passed)})
            sessions.append(session)
        if sessions[0].initialization_written != sessions[1].initialization_written: raise RuntimeError('helper write coverage depends on sentinel')
        sensitive = {i for i, (a, b) in enumerate(zip(sessions[0].context, sessions[1].context)) if a != b}
        comparisons.append({'synthetic_selector_2da7': selector,
                            'sentinel_sensitive_bytes': len(sensitive),
                            'sentinel_sensitive_intervals': intervals(sensitive),
                            'written_but_sentinel_sensitive_bytes': len(sensitive & sessions[0].initialization_written),
                            'prepared_contexts_differ_despite_matching_crcs': sessions[0].prepared_context != sessions[1].prepared_context,
                            'note': 'Differences include untouched bytes and read-modify-write bits; this is not a complete RAM-initialization proof.'})
    return {'low_sha256': sha256(low), 'high_sha256': sha256(high),
            'code_sha256': {hex(a): sha256((low+high)[a:b]) for a, b in FIRST_RANGES+RANGES+PREPARATION_RANGES+STORAGE_RANGES},
            'scope': 'Pending caller through all twelve remaining helpers; then separate real preparation CRC with subsystem helpers bypassed and storage trapped. Prepared context committed only in atomic host storage model.',
            'model_limits': 'Only selector values 0/1 and two sentinel contexts; external RAM starts zero. No preceding startup/epilogue, unknown subsystem effects, physical persistence, hardware or flash execution.',
            'cases': records, 'sentinel_comparisons': comparisons, 'all_pass': all(c['pass'] for c in records),
            'complete_context_initialization_verified': False, 'context_persistence_verified': False,
            'physical_recovery_verified': False, 'flash_implementation_executed': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('low', 'high', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    report = run_cases(args.low.read_bytes(), args.high.read_bytes())
    args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
    print(json.dumps({'all_pass': report['all_pass'], 'cases': len(report['cases']),
                      'bytes_written': report['cases'][0]['observed']['context_bytes_written'],
                      'comparisons': [{k: c[k] for k in ('synthetic_selector_2da7','sentinel_sensitive_bytes','written_but_sentinel_sensitive_bytes')} for c in report['sentinel_comparisons']]}))
    raise SystemExit(0 if report['all_pass'] else 1)
