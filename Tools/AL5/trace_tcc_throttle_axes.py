"""Offline, byte-bound AL5 TCC axis and interpolation extraction/replay.

No transport access; source files are read only. Synthetic ramps exist solely
inside emulator memory to make the otherwise constant stock tables observable.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

HIGH_SHA = '492040d9460d53b77dda606b9a89f4254e0680f239093001663f6ed5cf51ba75'
STOCK_SHA = '140b70ea90cb57c20aaab2d9641d2b7caaa6bf312c89bd9369b27b8bce5fcbe6'
CONTEXT, STACK, RETURN = 0x200000, 0x218000, 0x210000


def digest(data):
    return hashlib.sha256(data).hexdigest()


def lerp(a, b, fraction, shift):
    delta = (abs(b-a)*fraction) >> shift
    return a+delta if b >= a else a-delta


def expected_vector(values, raw_input):
    coordinate = min(raw_input*2, 65535)
    row, fraction = divmod(coordinate, 4096)
    return coordinate, lerp(values[row], values[row+1], fraction, 12)


def investigate(high, stock, native_bytes):
    from capstone import Cs, CS_ARCH_M68K, CS_MODE_BIG_ENDIAN, CS_MODE_M68K_020
    from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE
    from unicorn.m68k_const import (
        UC_CPU_M68K_M68020, UC_M68K_REG_SR, UC_M68K_REG_A5,
        UC_M68K_REG_A7, UC_M68K_REG_D0, UC_M68K_REG_D7, UC_M68K_REG_PC,
    )
    if len(high) != 0xE0000 or digest(high) != HIGH_SHA:
        raise ValueError('high image identity is not the investigated AL5 image')
    if len(stock) != 57304 or digest(stock) != STOCK_SHA:
        raise ValueError('stock image identity is not the investigated AL5 segment')
    native = json.loads(native_bytes.decode('cp1252'))
    reference = next(c for c in native['calibrations'] if c['id'] == 'D5073')
    if reference['rows'] != list(range(0, 257, 16)) or reference['column_count'] != 5:
        raise ValueError('native D5073 reference does not have the investigated axes')
    md = Cs(CS_ARCH_M68K, CS_MODE_BIG_ENDIAN | CS_MODE_M68K_020)
    windows = []
    for title, start, end in (
        ('row coordinate producer and family selector', 0x3A822, 0x3A936),
        ('unsigned axis normalization', 0x3DC40, 0x3DCC4),
        ('unsigned one dimensional interpolation', 0x3DD40, 0x3DDB8),
        ('unsigned two dimensional interpolation', 0x3DF08, 0x3E06E),
        ('filtered speed source calculation', 0x4A7BC, 0x4A852),
        ('speed filter invocation', 0x4AF84, 0x4AFAE),
        ('network speed normalization and fallback', 0x4A940, 0x4AA72),
        ('selected gear index commit and initialization', 0xC0698, 0xC0716),
    ):
        code = high[start-0x20000:end-0x20000]
        instructions = [dict(address=f'0x{i.address:X}', bytes=i.bytes.hex(),
                             mnemonic=i.mnemonic, operands=i.op_str)
                        for i in md.disasm(code, start)]
        if sum(len(bytes.fromhex(i['bytes'])) for i in instructions) != len(code):
            raise ValueError(f'incomplete disassembly at {start:#x}')
        windows.append(dict(title=title, start=f'0x{start:X}',
                            end_exclusive=f'0x{end:X}', sha256=digest(code),
                            instructions=instructions))
    uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
    uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    uc.mem_map(0, 0x100000)
    uc.mem_write(0x20000, high)
    uc.mem_write(0x8000, stock)
    uc.mem_map(CONTEXT, 0x20000)
    uc.reg_write(UC_M68K_REG_SR, 0x2700)
    uc.reg_write(UC_M68K_REG_A5, CONTEXT)
    current_allowed = []
    calls = []

    def guard(machine, address, size, _):
        if not any(lo <= address < hi for lo, hi in current_allowed):
            raise RuntimeError(f'execution left extracted routines at {address:#x}')
        if address in (0x3DC40, 0x3DD40):
            sp = machine.reg_read(UC_M68K_REG_A7)
            table, argument = struct.unpack('>II', machine.mem_read(sp+4, 8))
            calls.append(dict(routine=f'0x{address:X}', table=f'0x{table:X}', argument=argument))

    uc.hook_add(UC_HOOK_CODE, guard)

    def call(entry, args, end=RETURN, allowed=()):
        current_allowed[:] = allowed
        calls.clear()
        uc.reg_write(UC_M68K_REG_A7, STACK)
        uc.mem_write(STACK, struct.pack('>'+('I'*(len(args)+1)), RETURN, *args))
        uc.emu_start(entry, end, timeout=1_000_000, count=5000)
        expected_sp = STACK+4 if end == RETURN else STACK
        if uc.reg_read(UC_M68K_REG_PC) != end or uc.reg_read(UC_M68K_REG_A7) != expected_sp:
            raise RuntimeError('extracted routine did not reach its declared end with the expected stack')
        return uc.reg_read(UC_M68K_REG_D0) & 65535

    axis_inputs = sorted({0, 1, 65535, 32768, 32769} | {
        max(0, min(65535, k*2048+d)) for k in range(17) for d in (-1, 0, 1)})
    axis_cases = []
    for value in axis_inputs:
        actual = call(0x3DC40, [0xBF2E4, value], allowed=[(0x3DC40, 0x3DCC4)])
        wanted = min(value*2, 65535)
        axis_cases.append(dict(raw_input=value, coordinate=actual, expected=wanted, match=actual == wanted))

    vector_cases = []
    original = bytes(uc.mem_read(0x13A0A, 34))
    vectors = {'stock_constant': [65535]*17,
               'synthetic_rising': [i*4000 for i in range(17)],
               'synthetic_falling': [64000-i*4000 for i in range(17)]}
    for name, values in vectors.items():
        uc.mem_write(0x13A0A, struct.pack('>17H', *values))
        for value in axis_inputs:
            coordinate, wanted = expected_vector(values, value)
            actual = call(0x3DD40, [0x13A08, coordinate], allowed=[(0x3DD40, 0x3DDB8)])
            vector_cases.append(dict(vector=name, raw_input=value, coordinate=coordinate,
                                     output=actual, expected=wanted, match=actual == wanted))
    uc.mem_write(0x13A0A, original)

    integrated_cases = []
    allowed = [(0x3A822, 0x3A936), (0x29A60, 0x29A68), (0x8BA60, 0x8BA66),
               (0x3DC40, 0x3DCC4), (0x3DD40, 0x3DDB8)]
    # Actual getter, normalizer and interpolator execute. Only RAM state is injected.
    for mode in (0, 1, 2, 3):
        for flag in (0, 1):
            for column in range(5):
                for value in (0, 1024, 12800, 32768, 65535):
                    uc.mem_write(CONTEXT+0x1C7B, bytes([mode]))
                    uc.mem_write(CONTEXT+0x1226, bytes([flag]))
                    uc.mem_write(CONTEXT+0x2286, bytes([column]))
                    uc.mem_write(CONTEXT+0x120C, struct.pack('>H', value))
                    call(0x3A822, [], end=0x3A936, allowed=allowed)
                    actual = struct.unpack('>H', uc.mem_read(CONTEXT+0x23C4, 2))[0]
                    base = ((0x13A08 if flag else 0x13950) if mode == 1 else
                            0x13AC0 if mode == 2 else (0x13C30 if flag else 0x13B78))
                    wanted = 0 if mode == 2 else 65535
                    match = (actual == wanted and len(calls) == 2 and
                             calls[1]['table'] == f'0x{base+column*36:X}' and
                             calls[1]['argument'] == min(value*2, 65535))
                    integrated_cases.append(dict(mode=mode, flag_1226=flag, column=column,
                                                 raw_input=value, output=actual, calls=list(calls), match=match))

    # Probe the actual bilinear helper on a synthetic 3x3 grid in emulator-only RAM.
    # Deliberately mixed slopes exercise both unsigned interpolation branches.
    grid = [[1000, 9000, 2000], [50000, 20000, 60000], [4000, 45000, 3000]]
    table = 0x211000
    uc.mem_write(table, struct.pack('>11H', 3, 3, *(v for column in grid for v in column)))
    bilinear_cases = []
    for row in (0, 1, 16384, 32767, 32768, 49152, 65535):
        for col in (0, 1, 16384, 32767, 32768, 49152, 65535):
            ri, rf = divmod(row, 32768)
            ci, cf = divmod(col, 32768)
            first = lerp(grid[ci][ri], grid[ci][ri+1], rf, 15)
            second = lerp(grid[ci+1][ri], grid[ci+1][ri+1], rf, 15)
            wanted = lerp(first, second, cf, 15)
            actual = call(0x3DF08, [table, row, col], allowed=[(0x3DF08, 0x3E06E)])
            bilinear_cases.append(dict(row_coordinate=row, column_coordinate=col,
                                       output=actual, expected=wanted, match=actual == wanted))

    gear_cases = []
    for previous in range(5):
        for candidate in range(5):
            uc.mem_write(CONTEXT+0x2286, bytes([previous]))
            uc.mem_write(CONTEXT+0x2250, bytes([candidate]))
            uc.mem_write(CONTEXT+0x2288, bytes([0xFF]))
            call(0xC0698, [], end=0xC06EA, allowed=[(0xC0698, 0xC06EA)])
            committed = uc.mem_read(CONTEXT+0x2286, 1)[0]
            direction = uc.mem_read(CONTEXT+0x2288, 1)[0] & 0x30
            wanted = 0x10 if candidate < previous else 0x20 if candidate > previous else 0
            gear_cases.append(dict(previous=previous, candidate=candidate, committed=committed,
                                   direction_bits=direction, match=committed == candidate and direction == wanted))

    return dict(
        source_high_sha256=digest(high), stock_sha256=digest(stock), native_export_sha256=digest(native_bytes),
        scope='offline extracted firmware; real getter, normalizer, interpolation; synthetic RAM state',
        axis=dict(runtime_input='A5+0x120C', source_axis='0xBF2E4',
                  raw_axis_words=[2, 0, 32768], coordinate='min(2*raw_input,65535)',
                  seventeen_cell_raw_breakpoints=list(range(0, 32769, 2048)),
                  native_reference_labels=reference['rows'],
                  physical_units='vehicle speed km/h and raw/128 are corroborated inferences from native D5073 row labels plus speed-ratio producer; the export has no explicit row unit'),
        interpolation=dict(one_dimensional='unsigned, interpolate adjacent words with 12-bit fractional coordinate; truncate magnitude toward first endpoint',
                           high_endpoint='coordinate clamps at65535; a changing final segment approaches but need not exactly reach cell16',
                           two_dimensional='unsigned column-major; interpolate row within each adjacent column then interpolate columns; argument2=row, argument3=column'),
        gear=dict(source='A5+0x2250 committed into A5+0x2286 at0xC06E6; initial byte from0x14E21 at0xC0704',
                  interpretation='selected gear-state index, not proof of physically achieved gear',
                  column_reference='marker-confirmed native D5073-D5075 label index0..4 as1st..5th; alternate banks use same index without conversion',
                  native_columns=reference['columns']),
        speed_fields=dict(filtered='120C is B94E8-filtered1202 with coefficient14B3C',
                          raw='1202 derives from runtime122A and constants14B12,14B18(H0137),14B16(H0103), then factor60/16',
                          network='120A normally multiplies network word2122 by learned factor0B2E >>15, with fallback copy from120C; this report does not independently identify the network word'),
        axis_cases=axis_cases, vector_cases=vector_cases,
        integrated_cases=integrated_cases, bilinear_cases=bilinear_cases, gear_cases=gear_cases,
        all_match=all(c['match'] for group in (axis_cases, vector_cases, integrated_cases, bilinear_cases, gear_cases) for c in group),
        windows=windows,
        limitations=['No vehicle execution or physical input measurements.',
                     'Physical units use existing named-definition evidence; raw axis/interpolation are independently executed.',
                     'Gear producer commit is traced; all upstream candidate-gear selection paths were not traced.',
                     'Stock alternate vectors are constant65535, so synthetic emulator-only ramps expose interpolation behavior.',
                     'Bilinear replay uses a synthetic3x3 grid, not a claim about calibration14E48 meaning.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('high', 'stock', 'export', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--deps', type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('output already exists; select a new report path')
    if args.deps:
        sys.path.insert(0, str(args.deps))
    report = investigate(args.high.read_bytes(), args.stock.read_bytes(), args.export.read_bytes())
    report['inputs'] = {'high': str(args.high), 'stock': str(args.stock), 'export': str(args.export)}
    with args.output.open('x', encoding='utf-8', newline='\n') as output:
        output.write(json.dumps(report, indent=2)+'\n')
    print(json.dumps({key: len(report[key]) for key in
                      ('axis_cases', 'vector_cases', 'integrated_cases', 'bilinear_cases', 'gear_cases')} |
                     {'all_match': report['all_match']}))
    raise SystemExit(0 if report['all_match'] else 1)
