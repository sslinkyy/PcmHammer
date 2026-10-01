"""Offline startup copy/clear and linked context caller; hardware omitted."""
import argparse
import json
from pathlib import Path
from al5_segment import sha256
from checksum import crc16
from emulate_pending_helpers import Remaining, HELPERS
from emulate_storage_selection import BASE, CONTEXT_SIZE
from emulate_pending_initialization import START
from emulate_storage_recovery import begin

RANGES = [(0xBE478, 0xBE540), (0x5B8EC, 0x5BAB6)]
PREAMBLE_STUBS = (0x5B5E4, 0x5B6E4, 0x5B7EC, 0x228D8)
CLEAR_BYTES = 0x3670


class Startup(Remaining):
    def __init__(self, low, high, *, fill=0xA5, selector=0):
        super().__init__(low, high, fill=fill, selector=selector)
        for a, b in RANGES: self.uc.mem_write(a, (low+high)[a:b])
        self.uc.mem_write(0xC5E4A, (low+high)[0xC5E4A:0xC5F82])
        self.uc.mem_write(BASE+8, bytes([fill])*0x138)
        self.uc.mem_write(START, bytes([fill])*CLEAR_BYTES)
        self.uc.mem_write(START+CLEAR_BYTES, bytes([fill]))
        self.phase = 'clear'
        self.preamble_bypassed = []
        self.clear_writes = set()
        self.watchdog_values = []

    def write_hook(self, machine, access, address, size, value, user_data):
        if getattr(self, 'phase', None) == 'clear':
            if START <= address < START+CLEAR_BYTES:
                self.clear_writes.update(range(address, address+size))
            if address == 0xFFFA27: self.watchdog_values.append(value)
        super().write_hook(machine, access, address, size, value, user_data)

    def hook(self, machine, pc, size, user_data):
        from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_PC
        if self.phase == 'clear' and pc == 0x994D0:
            machine.emu_stop()  # before unrelated startup/MMIO calls
        elif self.phase == 'caller' and pc in PREAMBLE_STUBS:
            self.preamble_bypassed.append(hex(pc))
            sp = machine.reg_read(UC_M68K_REG_A7)
            machine.reg_write(UC_M68K_REG_PC, int.from_bytes(machine.mem_read(sp, 4), 'big'))
            machine.reg_write(UC_M68K_REG_A7, sp+4)
        elif (any(a <= pc < b for a, b in RANGES) or 0x21D08 <= pc < 0x21D1E) and pc != 0x5BAA6:
            pass
        else:
            super().hook(machine, pc, size, user_data)

    def cold_context(self):
        from unicorn.m68k_const import UC_M68K_REG_PC
        begin(self, 0xBE4F4)
        if self.uc.reg_read(UC_M68K_REG_PC) != 0x994D0: raise RuntimeError('startup clear escaped endpoint')
        clear = {'start': hex(START), 'end_exclusive': hex(START+CLEAR_BYTES),
                 'bytes': CLEAR_BYTES, 'observed_unique_bytes_written': len(self.clear_writes),
                 'region_all_zero': bytes(self.uc.mem_read(START, CLEAR_BYTES)) == b'\x00'*CLEAR_BYTES,
                 'context_all_zero': bytes(self.uc.mem_read(START, CONTEXT_SIZE)) == b'\x00'*CONTEXT_SIZE,
                 'after_region_probe_unchanged': bytes(self.uc.mem_read(START+CLEAR_BYTES, 1)) == bytes([self.fill]),
                 'global_prefix_matches_rom': bytes(self.uc.mem_read(BASE+8, 0x138)) == (self.low+self.high)[0xC5E4A:0xC5F82],
                 'watchdog_write_count': len(self.watchdog_values),
                 'watchdog_values_only_55_aa': all(v in (0x55, 0xAA) for v in self.watchdog_values)}
        self.phase = 'caller'
        self.stopped = None
        begin(self, 0x5B8EC)
        if self.stopped != '0x5baa6': raise RuntimeError('context caller escaped pending endpoint')
        self.context = bytes(self.uc.mem_read(START, CONTEXT_SIZE))
        return {'startup_clear': clear, 'preamble_helpers_bypassed': self.preamble_bypassed,
                'remaining_helpers_executed': self.root_helpers, 'stop_pc': self.stopped,
                'context_sha256': sha256(self.context),
                'stored_crc_before_preparation': hex(int.from_bytes(self.context[-2:], 'big')),
                'computed_crc_before_preparation': hex(crc16(self.context[:-2])),
                'selector_after_clear': int.from_bytes(self.uc.mem_read(BASE+0x2DA7, 1), 'big'),
                'banks_unchanged': all(sha256(bytes(self.uc.mem_read(int(a, 0), 0x2000))) == h for a, h in self.bank_hashes.items())}


def run_cases(low, high):
    records = []
    for fill in (0xA5, 0x5A):
        session = Startup(low, high, fill=fill)
        observed = session.cold_context()
        persistence = session.preparation_and_modeled_commit()
        clear = observed['startup_clear']
        passed = all(clear[k] for k in ('region_all_zero','context_all_zero','after_region_probe_unchanged','global_prefix_matches_rom','watchdog_values_only_55_aa'))
        passed &= clear['observed_unique_bytes_written'] == CLEAR_BYTES
        passed &= observed['banks_unchanged'] and observed['stored_crc_before_preparation'] == '0x0'
        passed &= observed['preamble_helpers_bypassed'] == [hex(a) for a in PREAMBLE_STUBS]
        passed &= observed['remaining_helpers_executed'] == [hex(a) for a, b in HELPERS]
        passed &= persistence['prepared_context_crc_matches'] and persistence['modeled_committed_context_matches_prepared']
        records.append({'synthetic_initial_ram_fill': hex(fill), 'observed': observed,
                        'separate_preparation_and_modeled_commit': persistence, 'pass': bool(passed)})
    same_context = records[0]['observed']['context_sha256'] == records[1]['observed']['context_sha256']
    same_prepared = records[0]['separate_preparation_and_modeled_commit']['prepared_context_sha256'] == records[1]['separate_preparation_and_modeled_commit']['prepared_context_sha256']
    return {'low_sha256': sha256(low), 'high_sha256': sha256(high),
            'code_sha256': {hex(a): sha256((low+high)[a:b]) for a, b in RANGES},
            'scope': 'Real startup copy/clear, linked context caller with four preamble helpers bypassed, real pending defaults; separate preparation and atomic host storage model.',
            'model_limits': 'No physical startup/MMIO execution; intervening startup and context preamble effects omitted. No automatic startup commit or full recovery proof.',
            'cases': records, 'cold_context_independent_of_initial_fill': same_context,
            'prepared_context_independent_of_initial_fill': same_prepared,
            'all_pass': all(c['pass'] for c in records) and same_context and same_prepared,
            'complete_startup_verified': False, 'physical_recovery_verified': False,
            'context_persistence_verified': False, 'flash_implementation_executed': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('low', 'high', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    report = run_cases(args.low.read_bytes(), args.high.read_bytes())
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'all_pass':report['all_pass'],'cases':len(report['cases']),
                      'cold_context_independent_of_initial_fill':report['cold_context_independent_of_initial_fill']}))
    raise SystemExit(0 if report['all_pass'] else 1)
