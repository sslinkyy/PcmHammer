"""Validate extracted throttle-family selection with lookup/getter stubs, offline."""
import argparse
import json
import struct
from pathlib import Path
from al5_segment import START, sha256, validate

ENTRY, END, GET_MODE, LOOKUP = 0x3A83C, 0x3A936, 0x29A60, 0x3DD40
CONTEXT, STACK = 0x200000, 0x218000


def selected(code, mode, column, flag_1226, enable_primary, enable_alternate):
    from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE
    from unicorn.m68k_const import UC_CPU_M68K_M68020, UC_M68K_REG_SR, UC_M68K_REG_A5, UC_M68K_REG_A7, UC_M68K_REG_D0, UC_M68K_REG_D7, UC_M68K_REG_PC
    uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
    uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    uc.mem_map(0x29000, 0x2000)
    uc.mem_map(0x3A000, 0x1000)
    uc.mem_map(0x3D000, 0x1000)
    uc.mem_map(CONTEXT, 0x4000)
    uc.mem_map(0x210000, 0x10000)
    uc.mem_map(0x11000, 0x1000)
    uc.mem_write(ENTRY, code)
    uc.mem_write(CONTEXT+0x1226, bytes([flag_1226]))
    uc.mem_write(CONTEXT+0x2286, bytes([column]))
    uc.mem_write(0x11ACC, bytes([enable_primary, enable_alternate]))
    uc.reg_write(UC_M68K_REG_SR, 0x2700)
    uc.reg_write(UC_M68K_REG_A5, CONTEXT)
    uc.reg_write(UC_M68K_REG_A7, STACK)
    uc.reg_write(UC_M68K_REG_D7, 0x1234)
    calls = []
    def stub_return(machine, result):
        sp = machine.reg_read(UC_M68K_REG_A7)
        target = struct.unpack('>I', machine.mem_read(sp, 4))[0]
        machine.reg_write(UC_M68K_REG_D0, result)
        machine.reg_write(UC_M68K_REG_A7, sp+4)
        machine.reg_write(UC_M68K_REG_PC, target)
    def guard(machine, address, size, user_data):
        if address == GET_MODE:
            stub_return(machine, mode)
        elif address == LOOKUP:
            sp = machine.reg_read(UC_M68K_REG_A7)
            table, index = struct.unpack('>2I', machine.mem_read(sp+4, 8))
            calls.append((table, index))
            stub_return(machine, 0x5A5A)
        elif not ENTRY <= address < END:
            raise RuntimeError(f'selection escaped bounded code at {address:#x}')
    uc.hook_add(UC_HOOK_CODE, guard)
    uc.emu_start(ENTRY, END, timeout=1_000_000, count=10000)
    if len(calls) != 1 or uc.reg_read(UC_M68K_REG_A7) != STACK:
        raise RuntimeError('selection did not complete one balanced lookup')
    if bytes(uc.mem_read(CONTEXT+0x23C4, 2)) != b'\x5A\x5A':
        raise RuntimeError('lookup result was not stored in the observed runtime field')
    return calls[0]


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('high', 'stock', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    args = p.parse_args()
    high, stock = args.high.read_bytes(), args.stock.read_bytes()
    if len(high) != 0xE0000 or validate(stock):
        raise ValueError('unexpected saved inputs')
    code = high[ENTRY-0x20000:END-0x20000]
    records = []
    for mode in (0, 1, 2, 3):
        for column in range(5):
            for flag in (0, 1):
                base = ((0x13A08 if flag else 0x13950) if mode == 1 else
                        0x13AC0 if mode == 2 else (0x13C30 if flag else 0x13B78))
                address, index = selected(code, mode, column, flag, 1, 1)
                offset = address-START
                header = int.from_bytes(stock[offset:offset+2], 'big')
                raw = struct.unpack_from('>17H', stock, offset+2)
                match = address == base+column*36 and index == 0x1234 and header == 17
                records.append({'mode_injected': mode, 'column_index': column, 'flag_1226': flag,
                    'enable_11ACC': 1, 'enable_11ACD': 1, 'table_header': f'0x{address:05X}',
                    'raw_values_unique': sorted(set(raw)), 'match': match})
    for column in range(5):
        address, index = selected(code, 1, column, 1, 0, 1)
        records.append({'mode_injected': 1, 'column_index': column, 'flag_1226': 1,
            'enable_11ACC': 0, 'enable_11ACD': 1, 'table_header': f'0x{address:05X}',
            'match': address == 0x13950+column*36 and index == 0x1234})
    report = {'source_sha256': sha256(high), 'stock_sha256': sha256(stock),
        'routine_sha256': sha256(code), 'start': f'0x{ENTRY:05X}', 'end_exclusive': f'0x{END:05X}',
        'scope': 'bounded selection code, synthetic context, mode getter and interpolator stubbed',
        'semantic_limit': 'mode/flag and column numbers injected; physical mode names and actual gear-index producer not proven',
        'cases': records, 'all_match': all(r['match'] for r in records)}
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(len(records), 'selection cases', 'PASS' if report['all_match'] else 'FAIL')
    raise SystemExit(0 if report['all_match'] else 1)
