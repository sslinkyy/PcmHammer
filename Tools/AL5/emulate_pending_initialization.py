"""Bounded pending-context initialization offline; no storage writes or hardware."""
import argparse
import json
from pathlib import Path
from al5_segment import sha256
from checksum import crc16
from emulate_storage_selection import Selection, BASE, RETURN, CONTEXT_SIZE
from emulate_storage_recovery import begin

RANGES = [(0x56734, 0x56A5A), (0xC0234, 0xC028A), (0xC02B0, 0xC02D6),
          (0xA9D0C, 0xA9D4C), (0x5BA24, 0x5BA5E)]
START = BASE+0x140


def intervals(offsets):
    groups = []
    for offset in sorted(offsets):
        if groups and offset == groups[-1][1]: groups[-1][1] += 1
        else: groups.append([offset, offset+1])
    return [{'start': hex(START+a), 'end_exclusive': hex(START+b), 'bytes': b-a} for a, b in groups]


class Initialization(Selection):
    def __init__(self, low, high, *, fill=0xA5):
        super().__init__(low, high, marker1=0xAA)
        from unicorn import UC_HOOK_MEM_WRITE
        data = low+high
        for a, b in RANGES: self.uc.mem_write(a, data[a:b])
        self.uc.mem_write(0x8000, low[0x8000:0x15FD8])
        self.uc.mem_write(START, bytes([fill])*CONTEXT_SIZE)
        self.fill = fill
        self.low = low
        self.written = set()
        self.helper_entries = []
        self.stopped = None
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self.write_hook)

    def write_hook(self, machine, access, address, size, value, user_data):
        for location in range(address, address+size):
            if START <= location < START+CONTEXT_SIZE: self.written.add(location-START)

    def hook(self, machine, pc, size, user_data):
        if pc == 0x5BA5E:
            self.stopped = hex(pc)  # before the next unresolved initializer
            machine.emu_stop()
        elif any(a <= pc < b for a, b in RANGES):
            if pc in (0x56734, 0xC02B0, 0xC0234, 0xA9D0C): self.helper_entries.append(hex(pc))
        else:
            super().hook(machine, pc, size, user_data)

    def initialize(self, operation):
        from unicorn.m68k_const import UC_M68K_REG_PC
        restore = None
        if operation == 'pending_caller':
            restore = self.run('restore')
            if restore['return_d0'] != '0x1': raise RuntimeError('expected pending restore failure')
        entry = {'defaults': 0x56734, 'secondary': 0xC02B0, 'pending_caller': 0x5BA24}[operation]
        begin(self, entry)
        returned = self.uc.reg_read(UC_M68K_REG_PC) == RETURN
        if not returned and self.stopped != '0x5ba5e': raise RuntimeError('initializer escaped bounded endpoints')
        context = bytes(self.uc.mem_read(START, CONTEXT_SIZE))
        untouched = set(range(CONTEXT_SIZE))-self.written
        return {'returned': returned, 'stop_pc': self.stopped, 'helper_entries': self.helper_entries,
                'pending_restore_return_d0': restore['return_d0'] if restore else None,
                'context_sha256': sha256(context), 'context_bytes_written': len(self.written),
                'written_intervals': intervals(self.written), 'untouched_intervals': intervals(untouched),
                'untouched_bytes_retain_sentinel': all(context[i] == self.fill for i in untouched),
                'crc_word_untouched': not ({CONTEXT_SIZE-2, CONTEXT_SIZE-1} & self.written),
                'stored_crc': hex(int.from_bytes(context[-2:], 'big')), 'computed_crc': hex(crc16(context[:-2])),
                'banks_unchanged': all(sha256(bytes(self.uc.mem_read(int(a, 0), 0x2000))) == h for a, h in self.bank_hashes.items()),
                'calibration_prefix_matches': context[:0x658] == self.low[0x8000:0x8658] if operation == 'defaults' else None,
                'copy_8_bits_writes_one_byte': bytes(self.uc.mem_read(BASE+0x8A0, 8)) == self.low[0xC0AE:0xC0AF]+b'\x00'*7 if operation != 'secondary' else None,
                'secondary_9_bit_copy_matches_two_bytes': bytes(self.uc.mem_read(0xFF82EE, 2)) == self.low[0x81AE:0x81B0] if operation != 'defaults' else None,
                'secondary_strings_terminated': bytes(self.uc.mem_read(0xFF82FB, 1))+bytes(self.uc.mem_read(0xFF8305, 1)) == b'\x00\x00' if operation != 'defaults' else None}


def run_cases(low, high):
    records = []
    for operation in ('defaults', 'secondary', 'pending_caller'):
        for fill in (0xA5, 0x5A):
            observed = Initialization(low, high, fill=fill).initialize(operation)
            passed = observed['banks_unchanged'] and observed['untouched_bytes_retain_sentinel'] and observed['crc_word_untouched']
            if operation == 'defaults': passed &= observed['returned'] and observed['calibration_prefix_matches'] and observed['copy_8_bits_writes_one_byte']
            if operation != 'defaults': passed &= observed['secondary_9_bit_copy_matches_two_bytes'] and observed['secondary_strings_terminated']
            if operation == 'pending_caller': passed &= observed['stop_pc'] == '0x5ba5e' and observed['pending_restore_return_d0'] == '0x1'
            records.append({'operation': operation, 'synthetic_ram_fill': hex(fill), 'observed': observed, 'pass': bool(passed)})
    for operation in ('defaults', 'secondary', 'pending_caller'):
        pair = [r for r in records if r['operation'] == operation]
        if pair[0]['observed']['written_intervals'] != pair[1]['observed']['written_intervals']:
            raise RuntimeError('write coverage depends on sentinel fill')
    return {'low_sha256': sha256(low), 'high_sha256': sha256(high),
            'code_sha256': {hex(a): sha256((low+high)[a:b]) for a, b in RANGES},
            'scope': 'Real bounded default helpers and pending caller through 0x5BA5E; synthetic RAM and protected banks. No flash implementation execution.',
            'model_limits': 'Stops before 0x55298 and subsequent initializers; no full startup, context persistence, reset, physical memory or live transport proof.',
            'cases': records, 'all_pass': all(r['pass'] for r in records),
            'complete_context_initialization_verified': False, 'physical_recovery_verified': False,
            'flash_implementation_executed': False, 'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('low', 'high', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    report = run_cases(args.low.read_bytes(), args.high.read_bytes())
    args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
    print(json.dumps({'all_pass': report['all_pass'], 'cases': len(report['cases']),
                      'coverage': [{'operation': c['operation'], 'bytes_written': c['observed']['context_bytes_written']} for c in report['cases'][::2]]}))
    raise SystemExit(0 if report['all_pass'] else 1)
