"""Execute the extracted AL5 CRC routine in an isolated M68020 emulator.

Only code/table, synthetic payload and stack RAM are mapped. No peripherals,
adapter APIs, serial ports or vehicle transport exist in this process.
"""
import argparse
import json
import random
import struct
from pathlib import Path
from al5_segment import LENGTH, sha256
from checksum import crc16

ROUTINE = 0xA95D0
ROUTINE_END = 0xA960A
TABLE = 0xAA610
DATA = 0x8000
STACK = 0x208000
RETURN = 0x300000


def emulate(code, table, payload, seed):
    from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE
    from unicorn.m68k_const import UC_CPU_M68K_M68020, UC_M68K_REG_SR, UC_M68K_REG_A7, UC_M68K_REG_D0
    uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
    uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    uc.mem_map(0xA9000, 0x2000)
    uc.mem_map(DATA, 0xE000)
    uc.mem_map(0x200000, 0x10000)
    uc.mem_map(RETURN, 0x1000)
    uc.mem_write(ROUTINE, code)
    uc.mem_write(TABLE, table)
    if payload:
        uc.mem_write(DATA, payload)
    uc.mem_write(STACK, struct.pack('>4I', RETURN, DATA, DATA+len(payload), seed))
    uc.reg_write(UC_M68K_REG_SR, 0x2700)
    uc.reg_write(UC_M68K_REG_A7, STACK)
    counts = [0]
    def guard(machine, address, size, user_data):
        if not ROUTINE <= address < ROUTINE_END:
            raise RuntimeError(f'Execution escaped CRC routine at {address:#x}')
        counts[0] += 1
    uc.hook_add(UC_HOOK_CODE, guard)
    uc.emu_start(ROUTINE, RETURN, timeout=15_000_000, count=1_500_000)
    if uc.reg_read(UC_M68K_REG_A7) != STACK+4:
        raise RuntimeError('routine did not return normally')
    return uc.reg_read(UC_M68K_REG_D0) & 0xFFFF, counts[0]


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('firmware-high', 'stock', 'ppei', 'output'):
        p.add_argument('--'+name, required=True, type=Path)
    args = p.parse_args()
    high = args.firmware_high.read_bytes()
    if len(high) != 0xE0000:
        raise ValueError('expected existing 20000-FFFFF editor dump')
    code = high[ROUTINE-0x20000:ROUTINE_END-0x20000]
    table = high[TABLE-0x20000:TABLE+512-0x20000]
    rng = random.Random(15184109)
    cases = [('empty', b''), ('standard_crc_vector', b'123456789'),
             ('all_byte_values', bytes(range(256))),
             ('random_4096', bytes(rng.randrange(256) for _ in range(4096)))]
    for label, path in [('stock', args.stock), ('ppei', args.ppei)]:
        data = path.read_bytes()
        if len(data) != LENGTH:
            raise ValueError('wrong reference segment length')
        cases.append((label, data[:-4]))
    records = []
    for label, payload in cases:
        for seed in (0, 0xFFFF):
            actual, instructions = emulate(code, table, payload, seed)
            expected = crc16(payload, seed)
            records.append({'case': label, 'payload_length': len(payload),
                'payload_sha256': sha256(payload), 'seed': seed, 'instructions': instructions,
                'firmware_result': f'{actual:04X}', 'python_result': f'{expected:04X}',
                'match': actual == expected})
    result = {'routine_address': f'0x{ROUTINE:05X}', 'routine_sha256': sha256(code),
              'table_sha256': sha256(table), 'firmware_high_sha256': sha256(high),
              'emulator': 'Unicorn M68020; isolated memory; no peripheral/vehicle I/O',
              'cases': records, 'all_match': all(r['match'] for r in records)}
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['all_match'] else 1)
