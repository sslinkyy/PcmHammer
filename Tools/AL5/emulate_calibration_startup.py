"""Trace calibration-check flag/seed from the real bounded startup ROM copy.

The linked marker check omits intervening startup initializers. No hardware
startup, flash primitive, vehicle I/O or physical recovery is executed.
"""
import argparse
import json
from pathlib import Path
from al5_segment import START, LENGTH, sha256
from emulate_calibration_marker import validate_source, marker_case, reset_marker_branch

COPY_ENTRY, COPY_STOP = 0xBE4F4, 0x994D0
COPY_RANGE = (0xBE478, 0xBE540)
ROM_START, PREFIX_START, PREFIX_END = 0xC5E4A, 0xFF8008, 0xFF8140
BASE, CLEAR_END = 0xFF8000, 0xFFB7B0
FLAG, SEED = BASE + 0x104, BASE + 0x106
FLAG_SOURCE = ROM_START + FLAG - PREFIX_START
SEED_SOURCE = ROM_START + SEED - PREFIX_START


def executable_span(pc, size):
    return size > 0 and (pc == COPY_STOP or COPY_RANGE[0] <= pc and pc + size <= COPY_RANGE[1])


def writable_span(address, size):
    return size > 0 and (address == 0xFFFA27 and size == 1 or any(
        a <= address and address + size <= b for a, b in (
            (0x200000, 0x210000), (PREFIX_START, CLEAR_END))))


def copied_initial_state(low, high, *, fill=0xA5):
    validate_source(low, high)
    if type(fill) is not int or not 0 <= fill <= 0xFF:
        raise ValueError('synthetic RAM fill must be a byte, not Boolean')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('requires the pinned Unicorn 2.1.4 runtime')
    # Reuse the existing startup mapping/copy implementation and entry helper.
    # Narrow its execution/write ownership before any native instruction runs.
    from emulate_startup_context import Startup
    from emulate_storage_recovery import begin
    from unicorn.m68k_const import UC_M68K_REG_PC

    class CopyOnly(Startup):
        def __init__(self):
            self.copy_flag_writes = []
            self.copied_offsets = set()
            self.cleared_offsets = set()
            self.observed_watchdog_writes = []
            self.copy_stop_seen = False
            super().__init__(low, high, fill=fill)

        def hook(self, machine, pc, size, user_data):
            if not executable_span(pc, size):
                raise RuntimeError(f'execution escaped bounded startup copy at {pc:#x}')
            if pc == COPY_STOP:
                self.copy_stop_seen = True
                machine.emu_stop()  # BEFORE the first intervening initializer.

        def write_hook(self, machine, access, address, size, value, user_data):
            if not writable_span(address, size):
                raise RuntimeError(f'unexpected startup native write at {address:#x}, size {size}')
            if address == 0xFFFA27:
                self.observed_watchdog_writes.append(value)
            for location in range(address, address + size):
                if PREFIX_START <= location < PREFIX_END:
                    self.copied_offsets.add(location - PREFIX_START)
                elif PREFIX_END <= location < CLEAR_END:
                    self.cleared_offsets.add(location - PREFIX_END)
            if address <= FLAG < address + size:
                self.copy_flag_writes.append({'address': hex(address), 'size': size,
                    'value': hex(value), 'written_flag_byte': (value >> (8 * (address + size - FLAG - 1))) & 0xFF})

    session = CopyOnly()
    begin(session, COPY_ENTRY)
    if not session.copy_stop_seen or session.uc.reg_read(UC_M68K_REG_PC) != COPY_STOP:
        raise RuntimeError('startup copy did not reach its owned boundary')
    data = low + high
    rom_prefix = data[ROM_START:ROM_START + PREFIX_END - PREFIX_START]
    ram_prefix = bytes(session.uc.mem_read(PREFIX_START, PREFIX_END - PREFIX_START))
    cleared = bytes(session.uc.mem_read(PREFIX_END, CLEAR_END - PREFIX_END))
    flag = session.uc.mem_read(FLAG, 1)[0]
    seed = int.from_bytes(session.uc.mem_read(SEED, 2), 'big')
    if ram_prefix != rom_prefix or flag != data[FLAG_SOURCE] or seed != int.from_bytes(data[SEED_SOURCE:SEED_SOURCE + 2], 'big'):
        raise RuntimeError('copied state does not match the pinned ROM source')
    if len(session.copied_offsets) != len(rom_prefix) or len(session.cleared_offsets) != len(cleared) or any(cleared):
        raise RuntimeError('startup native copy/clear coverage mismatch')
    if bytes(session.uc.mem_read(CLEAR_END, 1)) != bytes([fill]):
        raise RuntimeError('startup copy changed its after-boundary sentinel')
    if any(v not in (0x55, 0xAA) for v in session.observed_watchdog_writes):
        raise RuntimeError('unexpected synthetic watchdog value')
    return {'synthetic_initial_ram_fill': hex(fill), 'stop_pc': hex(COPY_STOP),
        'flag_address': hex(FLAG), 'flag_source_address': hex(FLAG_SOURCE), 'initial_check_flag': flag,
        'seed_address': hex(SEED), 'seed_source_address': hex(SEED_SOURCE), 'crc_seed': seed,
        'prefix_start': hex(PREFIX_START), 'prefix_end_exclusive': hex(PREFIX_END),
        'prefix_bytes': len(ram_prefix), 'copied_unique_bytes': len(session.copied_offsets),
        'prefix_sha256': sha256(ram_prefix), 'prefix_matches_pinned_rom': True,
        'clear_start': hex(PREFIX_END), 'clear_end_exclusive': hex(CLEAR_END),
        'cleared_unique_bytes': len(session.cleared_offsets), 'clear_all_zero': True,
        'after_clear_sentinel_preserved': True, 'flag_native_writes': session.copy_flag_writes,
        'synthetic_watchdog_write_count': len(session.observed_watchdog_writes),
        'intervening_initializers_executed': False, 'complete_startup_verified': False,
        'physical_recovery_verified': False, 'live_write_enabled': False, 'ready_to_flash': False}


def audit(low, high):
    validate_source(low, high)
    data = low + high
    stock = low[START:START + LENGTH]
    bad = bytearray(stock)
    bad[0x200] ^= 1
    initializations, linked = [], []
    for fill in (0xA5, 0x5A):
        initial = copied_initial_state(low, high, fill=fill)
        if initial['initial_check_flag'] != 1 or initial['crc_seed'] != 0:
            raise RuntimeError('pinned cold-copy flag/seed changed')
        initializations.append(initial)
        for name, marker, calibration, expected in (
                ('saved_calibration', 0x4AFC, stock, 'returned'),
                ('erased_marker', 0xFFFF, stock, 'completion_marker_rejected'),
                ('payload_fault', 0x4AFC, bytes(bad), 'calibration_crc_rejected')):
            observed = marker_case(low, high, marker=marker, calibration=calibration,
                initial_check=initial['initial_check_flag'] != 0, crc_seed=initial['crc_seed'])
            if observed['stop'] != expected or observed['marker_reads'] != 1:
                raise RuntimeError('unexpected selected startup-copy/marker-check handoff')
            branch = None
            if observed['reset_marker'] != '0x0':
                branch = reset_marker_branch(low, int(observed['reset_marker'], 0))
            linked.append({'name': name, 'synthetic_initial_ram_fill': hex(fill),
                'modeled_completion_marker': hex(marker), 'modeled_calibration_sha256': sha256(calibration),
                'flag_and_seed_from_actual_startup_copy': True,
                'intervening_initializers_executed': False, 'observed_marker_check': observed,
                'separate_selected_reset_branch': branch})
    source_ranges = [COPY_RANGE, (ROM_START, ROM_START + PREFIX_END - PREFIX_START),
                     (0xC5D30, 0xC5D38), (0x994D0, 0x99500), (0xC5A40, 0xC5A44)]
    dependencies = ('emulate_startup_context.py', 'emulate_storage_recovery.py',
        'emulate_storage_selection.py', 'emulate_pending_initialization.py',
        'emulate_pending_helpers.py', 'emulate_calibration_marker.py')
    return {'mode': 'offline_startup_copy_flag_seed_and_selected_marker_handoff',
        'low_sha256': sha256(low), 'high_sha256': sha256(high), 'unicorn_version': '2.1.4',
        'generator_sha256': sha256(Path(__file__).read_bytes()),
        'dependency_sha256': {name: sha256(Path(__file__).with_name(name).read_bytes()) for name in dependencies},
        'source_ranges': [{'start': hex(a), 'exclusive_end': hex(b), 'sha256': sha256(data[a:b])} for a, b in source_ranges],
        'initialization_cases': initializations, 'linked_cases': linked, 'all_pass': True,
        'limitations': ['Real ROM copy produces flag1/CRC seed0 at the boundary before initializer 0x994D0.',
            'Intervening initializers, VBR/interrupt setup and hardware effects are omitted from the selected marker-check handoff.',
            'Saved editor bytes are not current physical backups. Hardware reset, power-loss state and VPW recovery are unverified.'],
        'intervening_initializers_executed': False, 'complete_startup_verified': False,
        'physical_recovery_verified': False, 'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('low', 'high', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error('output must be a new report path')
    report = audit(args.low.read_bytes(), args.high.read_bytes())
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'initialization_cases': len(report['initialization_cases']),
        'linked_cases': len(report['linked_cases']), 'all_pass': True, 'ready_to_flash': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
