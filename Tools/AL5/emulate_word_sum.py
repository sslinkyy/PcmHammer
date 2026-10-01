"""Exercise the saved boot BE16 sum routine in isolated memory, without hardware I/O."""
import argparse
import json
import random
import struct
from pathlib import Path
from al5_segment import LENGTH, sha256, word_sum

ENTRY, END, DATA, RETURN = 0xA08, 0xA74, 0x8000, 0x300000


def emulate(code, data):
    from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE
    from unicorn.m68k_const import UC_CPU_M68K_M68020, UC_M68K_REG_A0, UC_M68K_REG_A1, UC_M68K_REG_A2, UC_M68K_REG_SR, UC_M68K_REG_D4
    if len(data) < 2 or len(data) & 1 or len(data) > LENGTH:
        raise ValueError('sum routine requires a nonempty bounded even-length range')
    uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
    uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    uc.mem_map(0, 0x1000)
    uc.mem_map(DATA, 0xE000)
    uc.mem_map(0xFF8000, 0x1000)
    uc.mem_map(0xFFFFF000, 0x1000)
    uc.mem_map(RETURN, 0x1000)
    uc.mem_write(ENTRY, code)
    uc.mem_write(DATA, data)
    uc.reg_write(UC_M68K_REG_SR, 0x2700)
    uc.reg_write(UC_M68K_REG_A0, DATA)
    uc.reg_write(UC_M68K_REG_A1, DATA+len(data)-2)
    uc.reg_write(UC_M68K_REG_A2, RETURN)
    instructions = [0]
    def guard(machine, address, size, user_data):
        if not ENTRY <= address < END:
            raise RuntimeError(f'execution escaped sum routine at {address:#x}')
        instructions[0] += 1
    uc.hook_add(UC_HOOK_CODE, guard)
    uc.emu_start(ENTRY, RETURN, timeout=2_000_000, count=200_000)
    if uc.reg_read(UC_M68K_REG_A0) != DATA+len(data):
        raise RuntimeError('sum routine did not process the exact requested range')
    actual = uc.reg_read(UC_M68K_REG_D4) & 0xFFFF
    stored = struct.unpack('>H', uc.mem_read(0xFF8006, 2))[0]
    if stored != actual:
        raise RuntimeError('synthetic stored sum disagrees with register result')
    return actual, instructions[0]


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('low', 'stock', 'ppei', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    args = p.parse_args()
    low = args.low.read_bytes()
    if len(low) != 0x20000:
        raise ValueError('unexpected saved low editor dump size')
    code = low[ENTRY:END]
    rng = random.Random(15184109)
    cases = [(f'random_{n}', bytes(rng.randrange(256) for _ in range(n)))
             for n in (2, 4, 6, 30, 32, 34, 60, 62, 64, 66, 126, 128, 130, 4096)]
    cases.append(('overflow_words', b'\xFF\xFF'*65))
    for label, path in [('stock', args.stock), ('ppei', args.ppei)]:
        data = path.read_bytes()
        if len(data) != LENGTH:
            raise ValueError('reference segment has wrong length')
        cases.append((label, data))
        changed = bytearray(data)
        changed[0x200] ^= 1
        cases.append((label+'_payload_bit_changed', bytes(changed)))
    records = []
    for label, data in cases:
        actual, count = emulate(code, data)
        expected = word_sum(data)
        records.append({'case': label, 'length': len(data), 'sha256': sha256(data),
            'firmware_result': f'{actual:04X}', 'python_result': f'{expected:04X}',
            'instructions': count, 'match': actual == expected})
        print(label, f'{actual:04X}', 'PASS' if actual == expected else 'FAIL')
    result = {'source_sha256': sha256(low), 'routine_sha256': sha256(code),
        'routine_address': f'0x{ENTRY:05X}', 'end_argument': 'inclusive address of final BE16 word',
        'scope': 'isolated sum code; watchdog/status addresses are synthetic memory, not peripherals',
        'limit': 'Known callers check boot and application ranges; calibration caller/generator not proven',
        'cases': records, 'all_match': all(r['match'] for r in records)}
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    raise SystemExit(0 if result['all_match'] else 1)
