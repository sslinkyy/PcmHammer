"""Pinned AL5 calibration marker/CRC checks in isolated memory; no live I/O.

The entry flag, retained RAM and changed calibration bytes are synthetic.
Reset-marker routing starts at a selected branch, not a hardware reset.
"""
import argparse
import json
from pathlib import Path
from al5_segment import LENGTH, START, sha256

LOW_HASH = 'cf5dd139e52ba5925fc95f166627a9a7abcac1374ded8cb738df8297b961a3f6'
HIGH_HASH = '492040d9460d53b77dda606b9a89f4254e0680f239093001663f6ed5cf51ba75'
BASE, STACK, RETURN = 0xFF8000, 0x208000, 0x300000
ENTRY = 0xA96F8
RANGES = ((0xA96F8, 0xA97E0), (0xA960C, 0xA9694),
          (0xA95D0, 0xA960A), (0x21D08, 0x21D18))
TRAPS = {0xA971A: 'completion_marker_rejected',
         0xA9668: 'calibration_crc_rejected',
         0xA979C: 'calibration_identifier_rejected',
         0xA965A: 'application_crc_rejected'}


def validate_source(low, high):
    if not isinstance(low, (bytes, bytearray)) or len(low) != 0x20000 or sha256(low) != LOW_HASH:
        raise ValueError('unexpected saved LOW size/hash')
    if not isinstance(high, (bytes, bytearray)) or len(high) != 0xE0000 or sha256(high) != HIGH_HASH:
        raise ValueError('unexpected saved HIGH size/hash')


def executable_address(address):
    return executable_span(address, 1)


def executable_span(address, size):
    return size > 0 and (address == RETURN or any(a <= address and address + size <= b for a, b in RANGES))


def writable_span(address, size):
    return size > 0 and any(a <= address and address + size <= b for a, b in (
        (0x200000, 0x210000), (BASE, BASE + 2),
        (BASE + 0x104, BASE + 0x108), (BASE + 0x1F78, BASE + 0x1F84)))


def marker_case(low, high, *, marker=0x4AFC, initial_check=True,
                calibration=None, crc_seed=0, current_start=START, current_end=0x15FD4,
                stride=955, initial_ram_marker=0):
    validate_source(low, high)
    if type(marker) is not int or not 0 <= marker <= 0xFFFF:
        raise ValueError('marker must be a word')
    if type(initial_ram_marker) is not int or not 0 <= initial_ram_marker <= 0xFFFF:
        raise ValueError('initial RAM marker must be a word, not Boolean')
    if type(initial_check) is not bool:
        raise ValueError('initial check flag must be Boolean')
    calibration = low[START:START + LENGTH] if calibration is None else calibration
    if not isinstance(calibration, (bytes, bytearray)) or len(calibration) != LENGTH:
        raise ValueError('exact raw calibration segment required')
    calibration = bytes(calibration)
    if type(crc_seed) is not int or type(stride) is not int or not 0 <= crc_seed <= 0xFFFF or not 1 <= stride <= LENGTH:
        raise ValueError('invalid synthetic CRC state')
    if type(current_start) is not int or type(current_end) is not int or not START <= current_start <= current_end <= 0x15FD4:
        raise ValueError('synthetic CRC pointers outside calibration body')
    from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ, UC_PROT_READ, UC_PROT_EXEC, __version__
    if __version__ != '2.1.4':
        raise ValueError('requires the pinned Unicorn 2.1.4 runtime')
    from unicorn.m68k_const import UC_CPU_M68K_M68020, UC_M68K_REG_A5, UC_M68K_REG_A7, UC_M68K_REG_PC, UC_M68K_REG_SR
    data = low + high
    uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
    uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    uc.mem_map(0, 0x100000)
    for a, b in RANGES:
        uc.mem_write(a, data[a:b])
    uc.mem_write(0xAA610, data[0xAA610:0xAA810])
    uc.mem_write(START, calibration)
    uc.mem_write(0x1FFFE, marker.to_bytes(2, 'big'))
    uc.mem_write(0x2141E, data[0x2141E:0x21421])
    uc.mem_protect(0, 0x100000, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_map(BASE, 0x8000)
    uc.mem_map(0x200000, 0x10000)
    uc.mem_map(RETURN, 0x1000)
    uc.mem_write(BASE, initial_ram_marker.to_bytes(2, 'big'))
    uc.mem_write(BASE + 0x104, bytes([int(initial_check)]))
    uc.mem_write(BASE + 0x106, crc_seed.to_bytes(2, 'big'))
    uc.mem_write(BASE + 0x1F78, stride.to_bytes(2, 'big'))
    uc.mem_write(BASE + 0x1F7C, current_start.to_bytes(4, 'big'))
    uc.mem_write(BASE + 0x1F80, current_end.to_bytes(4, 'big'))
    uc.mem_write(STACK, RETURN.to_bytes(4, 'big'))
    uc.reg_write(UC_M68K_REG_SR, 0x2000)
    uc.reg_write(UC_M68K_REG_A5, BASE)
    uc.reg_write(UC_M68K_REG_A7, STACK)
    observed = {'stop': None, 'stop_pc': None, 'marker_reads': 0,
                'crc_helper_calls': 0, 'interrupt_mask_helper_calls': 0, 'instructions': 0}

    def code(machine, pc, size, _):
        if not executable_span(pc, size):
            raise RuntimeError(f'execution escaped marker/CRC ranges at {pc:#x}')
        observed['instructions'] += 1
        if pc == 0xA960C:
            observed['crc_helper_calls'] += 1
        if pc == 0x21D08:
            observed['interrupt_mask_helper_calls'] += 1
        if pc in TRAPS or pc == RETURN:
            observed['stop'] = TRAPS.get(pc, 'returned')
            observed['stop_pc'] = hex(pc)
            machine.emu_stop()

    def write(machine, access, address, size, value, _):
        if not writable_span(address, size):
            raise RuntimeError(f'unexpected native write at {address:#x} size {size}')

    def read(machine, access, address, size, value, _):
        if address <= 0x1FFFE < address + size:
            observed['marker_reads'] += 1

    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.hook_add(UC_HOOK_MEM_READ, read)
    uc.emu_start(ENTRY, 0, timeout=20_000_000, count=1_500_000)
    if observed['stop'] is None:
        raise RuntimeError('marker model exhausted its budget without an owned stop')
    if observed['stop'] == 'returned' and uc.reg_read(UC_M68K_REG_A7) != STACK + 4:
        raise RuntimeError('unexpected marker routine return stack')
    observed.update({
        'initial_ram_marker': hex(initial_ram_marker),
        'reset_marker': hex(int.from_bytes(uc.mem_read(BASE, 2), 'big')),
        'initial_check_flag_after': uc.mem_read(BASE + 0x104, 1)[0],
        'crc_accumulator_after': hex(int.from_bytes(uc.mem_read(BASE + 0x106, 2), 'big')),
        'current_start_after': hex(int.from_bytes(uc.mem_read(BASE + 0x1F7C, 4), 'big')),
        'current_end_after': hex(int.from_bytes(uc.mem_read(BASE + 0x1F80, 4), 'big')),
        'stride_after': int.from_bytes(uc.mem_read(BASE + 0x1F78, 2), 'big'),
        'interrupt_mask_after': (uc.reg_read(UC_M68K_REG_SR) >> 8) & 7,
        'pc': hex(uc.reg_read(UC_M68K_REG_PC)),
        'live_write_enabled': False, 'ready_to_flash': False, 'physical_recovery_verified': False})
    return observed


def reset_marker_branch(low, marker):
    """Selected retained-RAM branch only; full reset/startup/hardware is omitted."""
    if not isinstance(low, (bytes, bytearray)) or len(low) != 0x20000 or sha256(low) != LOW_HASH:
        raise ValueError('unexpected saved LOW')
    if type(marker) is not int or not 0 <= marker <= 0xFFFF:
        raise ValueError('reset marker must be a word')
    from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_EXEC, __version__
    if __version__ != '2.1.4':
        raise ValueError('requires the pinned Unicorn 2.1.4 runtime')
    from unicorn.m68k_const import UC_CPU_M68K_M68020
    uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
    uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    uc.mem_map(0, 0x1000)
    uc.mem_write(0x8B2, low[0x8B2:0x96E])
    uc.mem_protect(0, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_map(BASE, 0x1000)
    uc.mem_write(BASE, marker.to_bytes(2, 'big'))
    observed = {'stop_pc': None, 'selected_reset_branch_only': True}

    def code(machine, pc, size, _):
        if pc in (0x97C, 0x96E, 0x87C):
            observed['stop_pc'] = hex(pc)
            machine.emu_stop()
        elif not (size > 0 and 0x8B2 <= pc and pc + size <= 0x96E):
            raise RuntimeError(f'escaped selected reset-marker branch at {pc:#x}')

    def write(machine, access, address, size, value, _):
        if address != BASE or size != 2:
            raise RuntimeError('unexpected reset-marker write')

    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(0x8B2, 0, timeout=1_000_000, count=200)
    if observed['stop_pc'] is None:
        raise RuntimeError('reset-marker branch did not reach an owned stop')
    observed['marker_after'] = hex(int.from_bytes(uc.mem_read(BASE, 2), 'big'))
    observed['physical_reset_verified'] = False
    return observed


def audit(low, high):
    validate_source(low, high)
    stock = low[START:START + LENGTH]
    body_bad = bytearray(stock)
    body_bad[0x200] ^= 1
    crc_bad = bytearray(stock)
    crc_bad[-4] ^= 1
    compensation_bad = bytearray(stock)
    compensation_bad[-1] ^= 1
    identifier_bad = bytearray(stock)
    identifier_bad[0] ^= 1
    # A CRC-correct but identifier-mismatching synthetic input isolates the next gate.
    from checksum import native_field
    identifier_bad[-4:] = native_field(identifier_bad)
    cases = [
        ('saved_marker_and_calibration', {}, 'returned', None),
        ('erased_marker', {'marker': 0xFFFF}, 'completion_marker_rejected', 0xC7D8),
        ('zero_marker', {'marker': 0}, 'completion_marker_rejected', 0xC7D8),
        ('partial_marker', {'marker': 0x4AFF}, 'completion_marker_rejected', 0xC7D8),
        ('payload_bit_fault', {'calibration': body_bad}, 'calibration_crc_rejected', 0x3E91),
        ('stored_crc_fault', {'calibration': crc_bad}, 'calibration_crc_rejected', 0x3E91),
        ('compensation_only_fault', {'calibration': compensation_bad}, 'returned', None),
        ('crc_correct_identifier_fault', {'calibration': identifier_bad}, 'calibration_identifier_rejected', 0xC12A),
        ('clear_initial_flag_erased_marker', {'marker': 0xFFFF, 'initial_check': False}, 'returned', None),
    ]
    records = []
    for name, context, expected_stop, expected_reset in cases:
        observed = marker_case(low, high, **context)
        if observed['stop'] != expected_stop:
            raise RuntimeError(f'{name}: expected {expected_stop}, got {observed["stop"]}')
        branch = None
        if expected_reset is not None:
            branch = reset_marker_branch(low, int(observed['reset_marker'], 0))
            if branch['stop_pc'] != '0x97c' or int(branch['marker_after'], 0) != expected_reset:
                raise RuntimeError('unexpected reset-marker routing')
        if context.get('initial_check') is False and observed['marker_reads'] != 0:
            raise RuntimeError('clear-flag path unexpectedly checked completion marker')
        records.append({'name': name, 'synthetic_context': {
            'marker': hex(context.get('marker', 0x4AFC)), 'initial_check_flag': context.get('initial_check', True),
            'initial_ram_marker': hex(context.get('initial_ram_marker', 0)),
            'crc_seed': 0, 'calibration_sha256': sha256(context.get('calibration', stock))},
            'observed': observed, 'selected_reset_branch': branch})
    data = low + high
    source_ranges = list(RANGES) + [(0xAA610, 0xAA810), (0x8B2, 0x96E), (0x2141E, 0x21421)]
    return {'mode': 'offline_calibration_marker_crc_and_selected_reset_branch',
            'low_sha256': LOW_HASH, 'high_sha256': HIGH_HASH,
            'generator_sha256': sha256(Path(__file__).read_bytes()), 'unicorn_version': '2.1.4',
            'source_ranges': [{'start': hex(a), 'exclusive_end': hex(b), 'sha256': sha256(data[a:b])} for a, b in source_ranges],
            'cases': records, 'all_pass': True,
            'limitations': ['Entry flag +0x104 and initial CRC state are supplied to this slice; startup provenance is tested separately by the startup/initializer models.',
                'Only selected reset-marker branches run; power loss, RAM retention, boot integrity gates, peripheral startup and VPW reentry are unverified.',
                'The CRC check excludes the final BE16 compensation word; this model does not certify the complete native checksum.',
                'Flash primitives and transport do not execute.'],
            'ready_to_flash': False, 'live_write_enabled': False, 'physical_recovery_verified': False, 'would_send': []}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--low', required=True, type=Path)
    parser.add_argument('--high', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error('output must be a new report path')
    report = audit(args.low.read_bytes(), args.high.read_bytes())
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'cases': len(report['cases']), 'all_pass': True, 'ready_to_flash': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
