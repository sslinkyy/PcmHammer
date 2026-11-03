"""Replay the saved AL5 TCC throttle-release consumer, entirely offline.

Source firmware is never modified. Optional table changes exist only in isolated
emulator RAM. No adapter, peripheral, serial, network or target-process API is used.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

LOW_SHA = 'cf5dd139e52ba5925fc95f166627a9a7abcac1374ded8cb738df8297b961a3f6'
HIGH_SHA = '492040d9460d53b77dda606b9a89f4254e0680f239093001663f6ed5cf51ba75'
STOCK_SHA = '140b70ea90cb57c20aaab2d9641d2b7caaa6bf312c89bd9369b27b8bce5fcbe6'
CONTEXT, STACK, RETURN = 0x200000, 0x218000, 0x300000
WINDOWS = ((0x3A7C0, 0x3A9BA), (0x3DC40, 0x3DCC4),
           (0x3DD40, 0x3DDB8), (0x3DF08, 0x3E06E),
           (0x29A60, 0x29A68), (0x8BA60, 0x8BA66))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def word(data, address):
    return struct.unpack_from('>H', data, address)[0]


def axis(data, address, value):
    count = word(data, address)
    points = struct.unpack_from('>' + str(count) + 'H', data, address + 2)
    if value <= points[0]:
        return 0
    if value >= points[-1]:
        return 65535
    shift = data[0x3E95E + count]
    index = next(i for i in range(count - 1) if value < points[i + 1])
    return (index << shift) | (((value - points[index]) << shift) //
                               (points[index + 1] - points[index]))


def interpolate(left, right, fraction, shift):
    delta = (abs(right - left) * fraction) >> shift
    return left + delta if right >= left else left - delta


def surface(data, address, row_coord, col_coord):
    rows, columns = struct.unpack_from('>2H', data, address)
    rs, cs = data[0x3E95E + rows], data[0x3E95E + columns]
    row, column = row_coord >> rs, col_coord >> cs
    rf, cf = row_coord & ((1 << rs) - 1), col_coord & ((1 << cs) - 1)
    def at(r, c):
        return word(data, address + 4 + 2 * (c * rows + r))
    lo = interpolate(at(row, column), at(row + 1, column), rf, rs)
    hi = interpolate(at(row, column + 1), at(row + 1, column + 1), rf, rs)
    return interpolate(lo, hi, cf, cs)


def replay(image, *, mode=0, alternate=1, gear=4, speed_raw=12800,
           rpm_raw=16000, comparison_raw=0, compensation=4096,
           enable=1, acceleration=0, previous_accel_gate=0,
           primary_gate=1, table_raw=None, initial_reason=0):
    from unicorn import (Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE,
                         UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_EXEC)
    from unicorn.m68k_const import (UC_CPU_M68K_M68020, UC_M68K_REG_A5,
        UC_M68K_REG_A7, UC_M68K_REG_SR, UC_M68K_REG_PC)
    uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
    uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    uc.mem_map(0, 0x100000)
    uc.mem_map(CONTEXT, 0x20000)
    uc.mem_map(RETURN, 0x1000)
    uc.mem_write(0, image)
    uc.mem_write(0x11ACC, bytes([enable, enable]))
    base = (0x13A08 if alternate and enable else 0x13950) if mode == 1 else (
        0x13AC0 if mode == 2 else (0x13C30 if alternate and enable else 0x13B78))
    if table_raw is not None:
        # Synthetic experiment: alter only the selected vector in emulator RAM.
        uc.mem_write(base + gear * 36 + 2, struct.pack('>17H', *([table_raw] * 17)))
    uc.mem_protect(0, 0x100000, UC_PROT_READ | UC_PROT_EXEC)
    def w(offset, value):
        uc.mem_write(CONTEXT + offset, struct.pack('>H', value & 65535))
    for offset, value in ((0x1C7B, mode), (0x1226, alternate), (0x2286, gear),
                          (0x23FA, primary_gate << 1),
                          (0x23FE, previous_accel_gate << 6),
                          (0x2410, initial_reason << 1)):
        uc.mem_write(CONTEXT + offset, bytes([value]))
    for offset, value in ((0x120C, speed_raw), (0x1CE4, rpm_raw),
                          (0x1544, comparison_raw), (0x155E, compensation),
                          (0x1212, acceleration)):
        w(offset, value)
    uc.mem_write(STACK, struct.pack('>I', RETURN))
    uc.reg_write(UC_M68K_REG_SR, 0x2700)
    uc.reg_write(UC_M68K_REG_A5, CONTEXT)
    uc.reg_write(UC_M68K_REG_A7, STACK)
    calls, written, steps = [], set(), [0]
    def guard(machine, address, size, _):
        if not any(start <= address < end for start, end in WINDOWS):
            raise RuntimeError(f'execution outside declared routines: {address:#x}')
        steps[0] += 1
        if address in (0x3DC40, 0x3DD40, 0x3DF08):
            sp = machine.reg_read(UC_M68K_REG_A7)
            args = struct.unpack('>3I', machine.mem_read(sp + 4, 12))
            calls.append({'entry': hex(address), 'arguments': list(args[:3 if address == 0x3DF08 else 2])})
    def writes(machine, access, address, size, value, _):
        if not CONTEXT <= address < CONTEXT + 0x20000:
            raise RuntimeError(f'write outside synthetic context/stack: {address:#x}')
        if address < CONTEXT + 0x4000:
            written.update(range(address - CONTEXT, address - CONTEXT + size))
    uc.hook_add(UC_HOOK_CODE, guard)
    uc.hook_add(UC_HOOK_MEM_WRITE, writes)
    uc.emu_start(0x3A7C0, RETURN, timeout=1_000_000, count=10000)
    if uc.reg_read(UC_M68K_REG_PC) != RETURN or uc.reg_read(UC_M68K_REG_A7) != STACK + 4:
        raise RuntimeError('routine did not return with balanced stack')
    def readw(offset):
        return struct.unpack('>H', uc.mem_read(CONTEXT + offset, 2))[0]
    return {'selected_header': next((hex(c['arguments'][0]) for c in calls if c['entry'] == '0x3dd40'), None),
            'table_result_raw': readw(0x23C4), 'surface_result_raw': readw(0x23B6),
            'comparison_threshold_raw': readw(0x23B4),
            'reason_bit_2410_1': bool(uc.mem_read(CONTEXT + 0x2410, 1)[0] & 2),
            'acceleration_gate': bool(uc.mem_read(CONTEXT + 0x23FE, 1)[0] & 64),
            'calls': calls, 'instruction_count': steps[0],
            'context_written_offsets': [hex(o) for o in sorted(written)]}


def run(low, high, stock):
    for label, data, expected in (('low', low, LOW_SHA), ('high', high, HIGH_SHA), ('stock', stock, STOCK_SHA)):
        if digest(data) != expected:
            raise ValueError(f'{label}: input identity does not match this investigated firmware')
    image = bytearray(low + high)
    image[0x8000:0x15FD8] = stock
    image = bytes(image)
    cases = []
    for mode in (0, 1, 2):
        for alternate in (0, 1):
            for gear in range(5):
                args = dict(mode=mode, alternate=alternate, gear=gear)
                actual = replay(image, **args)
                table_raw = 0 if mode == 2 else 65535
                modeled = surface(image, 0x14E48, axis(image, 0x150EA, 16000), table_raw)
                threshold = (modeled * word(image, 0x14E3C + 2 * gear)) >> 19
                expected_header = (0x13A08 if alternate else 0x13950) if mode == 1 else (
                    0x13AC0 if mode == 2 else (0x13C30 if alternate else 0x13B78))
                cases.append({'kind': 'stock_all_modes_and_gears', 'inputs': args, 'result': actual,
                    'match': actual['selected_header'] == hex(expected_header + gear * 36)
                        and actual['surface_result_raw'] == modeled
                        and actual['comparison_threshold_raw'] == threshold
                        and actual['reason_bit_2410_1'] == (threshold > 0)})
    for table_raw in (0, 16384, 32768, 49152, 65535):
        for rpm_raw in (1600, 8000, 16000, 24000, 28800):
            args = dict(table_raw=table_raw, rpm_raw=rpm_raw)
            modeled = surface(image, 0x14E48, axis(image, 0x150EA, rpm_raw), table_raw)
            threshold = (modeled * word(image, 0x14E44)) >> 19
            for comparison in sorted(set((max(0, threshold - 1), threshold, min(65535, threshold + 1)))):
                actual = replay(image, comparison_raw=comparison, **args)
                cases.append({'kind': 'synthetic_table_and_comparator_boundary',
                    'inputs': dict(args, comparison_raw=comparison), 'result': actual,
                    'match': actual['table_result_raw'] == table_raw
                        and actual['surface_result_raw'] == modeled
                        and actual['comparison_threshold_raw'] == threshold
                        and actual['reason_bit_2410_1'] == (threshold > comparison)})
    for gear in (0, 4):
        for compensation in (0, 2048, 4096, 8192, 65535):
            actual = replay(image, gear=gear, compensation=compensation)
            modeled = surface(image, 0x14E48, axis(image, 0x150EA, 16000), 65535)
            intermediate = (modeled * word(image, 0x14E3C + 2 * gear)) >> 19
            threshold = min(65535, ((intermediate & 65535) * compensation) >> 12)
            cases.append({'kind': 'runtime_compensation',
                'inputs': {'gear': gear, 'compensation': compensation}, 'result': actual,
                'match': actual['comparison_threshold_raw'] == threshold})
    for previous, limit in ((0, word(image, 0x14E38)), (1, word(image, 0x14E3A))):
        for accel in (-1, limit - 1, limit, limit + 1):
            args = dict(acceleration=accel, previous_accel_gate=previous)
            actual = replay(image, **args)
            expected = accel < limit
            cases.append({'kind': 'signed_acceleration_hysteresis', 'inputs': args, 'result': actual,
                          'match': actual['acceleration_gate'] == expected
                              and (actual['selected_header'] is not None) == expected})
    for mode in (0, 1):
        actual = replay(image, mode=mode, enable=0)
        expected = (0x13950 if mode == 1 else 0x13B78) + 4 * 36
        cases.append({'kind': 'alternate_enable_clear', 'inputs': {'mode': mode, 'enable': 0},
                      'result': actual, 'match': actual['selected_header'] == hex(expected)})
    actual = replay(image, primary_gate=0)
    cases.append({'kind': 'primary_gate_clear', 'inputs': {'primary_gate': 0}, 'result': actual,
                  'match': not actual['calls'] and not actual['reason_bit_2410_1']})
    for args in ({'primary_gate': 0}, {'comparison_raw': 65535}, {'acceleration': 32767}):
        actual = replay(image, initial_reason=1, **args)
        cases.append({'kind': 'existing_reason_not_cleared_here',
                      'inputs': dict(args, initial_reason=1), 'result': actual,
                      'match': actual['reason_bit_2410_1']})
    return {'source_hashes': {'low': digest(low), 'high': digest(high), 'stock': digest(stock)},
        'composition': 'saved low+high firmware; calibration replaced in emulator with exact stock segment',
        'scope': 'actual extracted 0x3A7C0 routine plus real mode getter, axis helper, vector and bilinear interpolators; no call stubs',
        'emulator': 'Unicorn M68020; synthetic RAM and inputs; no peripheral or vehicle I/O',
        'limitations': ['Input producers and scheduler are not executed here.',
            'No physical converter behavior or edited-calibration acceptance is established.',
            'Synthetic table vectors exist only in emulator memory.',
            'The output is the software reason bit; downstream arbitration is separate evidence.'],
        'code_windows': [{'start': hex(a), 'end_exclusive': hex(b), 'sha256': digest(image[a:b])} for a, b in WINDOWS],
        'cases': cases, 'case_count': len(cases), 'all_match': all(c['match'] for c in cases)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('low', 'high', 'stock', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('output already exists; select a new report path')
    report = run(args.low.read_bytes(), args.high.read_bytes(), args.stock.read_bytes())
    report['inputs'] = {name: str(getattr(args, name)) for name in ('low', 'high', 'stock')}
    with args.output.open('x', encoding='utf-8', newline='\n') as output:
        output.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'case_count': report['case_count'], 'all_match': report['all_match'],
        'failed_inputs': [{'kind': c['kind'], 'inputs': c['inputs']}
                          for c in report['cases'] if not c['match']]}, indent=2))
    raise SystemExit(0 if report['all_match'] else 1)
