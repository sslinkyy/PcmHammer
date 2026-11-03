"""Offline AL5 TCC reason arbitration and state-zero replay; no vehicle I/O.

Source firmware and calibration files are read-only. Extracted machine code runs
in isolated Unicorn memory; all ROM writes are rejected. State/input fields are
synthetic, so results establish bounded software behavior, not physical release.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

EXPECTED_LOW = 'cf5dd139e52ba5925fc95f166627a9a7abcac1374ded8cb738df8297b961a3f6'
EXPECTED_HIGH = '492040d9460d53b77dda606b9a89f4254e0680f239093001663f6ed5cf51ba75'
EXPECTED_STOCK = '140b70ea90cb57c20aaab2d9641d2b7caaa6bf312c89bd9369b27b8bce5fcbe6'
CONTEXT, STACK, RETURN = 0x200000, 0x218000, 0x300000
WINDOWS = [
    (0x299F0, 0x299F8), (0x97868, 0x9786E),
    (0x4AB1C, 0x4ABCA), (0x67FFC, 0x68048),
    (0x68100, 0x6817E), (0x683DC, 0x6844E),
    (0xA9BF0, 0xA9C5A), (0xADAA8, 0xADC80),
    (0x3F7BC, 0x3F7EC), (0x3F7FE, 0x3F850),
    (0x3FACC, 0x3FB3A),
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def replay(rom, entry, allowed, fields=(), arguments=()):
    from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_EXEC
    from unicorn.m68k_const import UC_CPU_M68K_M68020, UC_M68K_REG_A5, UC_M68K_REG_A7, UC_M68K_REG_SR, UC_M68K_REG_PC, UC_M68K_REG_D0
    uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
    uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    uc.mem_map(0, 0x100000)
    uc.mem_write(0, rom)
    uc.mem_protect(0, 0x100000, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_map(CONTEXT, 0x4000)
    uc.mem_map(0x210000, 0x10000)
    uc.mem_map(RETURN, 0x1000)
    for offset, data in fields:
        uc.mem_write(CONTEXT + offset, data)
    uc.mem_write(STACK, struct.pack('>' + 'I' * (1 + len(arguments)), RETURN, *arguments))
    uc.reg_write(UC_M68K_REG_SR, 0x2700)
    uc.reg_write(UC_M68K_REG_A5, CONTEXT)
    uc.reg_write(UC_M68K_REG_A7, STACK)
    count = 0

    def guard(machine, address, size, user):
        nonlocal count
        if not any(start <= address < end for start, end in allowed):
            raise RuntimeError(f'execution escaped declared code windows at {address:#x}')
        count += 1

    uc.hook_add(UC_HOOK_CODE, guard)
    uc.emu_start(entry, RETURN, timeout=1_000_000, count=10000)
    if uc.reg_read(UC_M68K_REG_PC) != RETURN or uc.reg_read(UC_M68K_REG_A7) != STACK + 4:
        raise RuntimeError('bounded replay did not return with balanced stack')
    return uc, uc.reg_read(UC_M68K_REG_D0) & 0xFFFFFFFF, count


def investigate(low, high, stock):
    from capstone import Cs, CS_ARCH_M68K, CS_MODE_M68K_020, CS_MODE_BIG_ENDIAN
    if (sha(low), sha(high), sha(stock)) != (EXPECTED_LOW, EXPECTED_HIGH, EXPECTED_STOCK):
        raise ValueError('input identity differs from the investigated AL5 OS/calibration')
    original = low + high
    rom = bytearray(original)
    rom[0x8000:0x15FD8] = stock
    # Explicitly synthetic diagnostic override controls, not patched source files.
    rom[0x23414:0x23416] = b'\0\0'
    rom = bytes(rom)
    cs = Cs(CS_ARCH_M68K, CS_MODE_M68K_020 | CS_MODE_BIG_ENDIAN)
    windows = []
    for start, end in WINDOWS:
        instructions = list(cs.disasm(original[start:end], start))
        if not instructions or instructions[-1].address + instructions[-1].size != end:
            raise ValueError(f'incomplete bounded decode at {start:#x}')
        windows.append({'start': hex(start), 'end_exclusive': hex(end),
                        'sha256': sha(original[start:end]), 'instructions': [
                            {'address': hex(i.address), 'bytes': i.bytes.hex(),
                             'mnemonic': i.mnemonic, 'operands': i.op_str} for i in instructions]})
    cases = []
    for name, bits, start, end, expected in (
        ('empty', b'\0\0\0\0', 0, 28, 0xFFFFFFFF),
        ('reason22', b'\0\0\x02\0', 0, 28, 22),
        ('first_has_priority', b'\x80\0\x02\0', 0, 28, 0),
        ('end_excluded', b'\0\0\x02\0', 0, 22, 0xFFFFFFFF),
        ('start_included', b'\0\0\x02\0', 22, 28, 22),
    ):
        _, actual, count = replay(rom, 0xA9BF0, [(0xA9BF0, 0xA9C5A)],
                                  [(0x240E, bits)], [CONTEXT + 0x240E, start, end])
        cases.append({'case': 'scanner_' + name, 'expected': expected,
                      'actual': actual, 'instructions': count, 'pass': actual == expected})
    for name, reason, override, expected in (
        ('reason22_sets_zero', True, False, 0),
        ('no_reason_retains_state', False, False, 7),
        ('override_bypasses_reason', True, True, 7),
    ):
        fields = [(0x2407, b'\x07'), (0x240E, b'\0\0' + bytes([2 if reason else 0]) + b'\0'),
                  (0x2419, bytes([int(override)]))]
        uc, _, count = replay(rom, 0xADAA8, [(0xADAA8, 0xADC80), (0xA9BF0, 0xA9C5A)], fields)
        actual = uc.mem_read(CONTEXT + 0x2407, 1)[0]
        cases.append({'case': 'arbitration_' + name, 'expected_state': expected,
                      'actual_state': actual, 'instructions': count, 'pass': actual == expected})
    for speed, previous_flag, expected in (
        (12800, 0, 0), (32511, 0, 0), (32512, 0, 12345),
        (32512, 1, 0), (32639, 1, 0), (32640, 1, 12345),
    ):
        fields = [(0x120C, struct.pack('>H', speed)), (0x23FF, bytes([8 * previous_flag])),
                  (0x23CE, struct.pack('>H', 12345)), (0x23CA, b'\x55\x55')]
        uc, _, count = replay(rom, 0x3FACC, [(0x3FACC, 0x3FB3A)], fields)
        actual = int.from_bytes(uc.mem_read(CONTEXT + 0x23CA, 2), 'big')
        cases.append({'case': 'state_zero_speed_hysteresis', 'speed_raw': speed,
                      'previous_hysteresis_flag': previous_flag, 'expected_23CA': expected,
                      'actual_23CA': actual, 'instructions': count, 'pass': actual == expected})
    return {
        'scope': 'source-byte bounded disassembly plus isolated extracted-machine-code replay',
        'source_sha256': {'low': sha(low), 'high': sha(high), 'stock': sha(stock)},
        'emulator': 'Unicorn M68020; ROM protected read/execute; synthetic RAM; no peripherals',
        'synthetic_controls': {'0x23414': 0, '0x23415': 0},
        'findings': {
            'scanner': '0xA9BF0 returns first set bit in [start,end), MSB-first per byte, or -1',
            'reason': 'A5+0x2410 bit1 is index22 in 28-bit reason set at A5+0x240E',
            'arbitration': 'Absent bypass conditions, any reason sets A5+0x2407 to state0',
            'bypass': 'Earlier state/diagnostic overrides can bypass the 28-bit reason scan',
            'state0_dispatch': '0x3F7D6 switch table0x3F7EC offset0x12 ->0x3F7FE ->0x3FACC',
            'state0_result': '0x3FACC resets23DA/DC/DE; speed hysteresis selects23CA=0 or23CE',
            'stock_speed_thresholds_raw': {'0x13768': 32512, '0x1376A': 32640},
            'stock_155E': 'cal14E18=0 makes producer0x683DC set155E=4096, unity Q12',
            'real_throttle_getter': '0x299F0 ->0x97868 returns A5+0x1DB2',
            'comparison_source': '1544 ordinarily copies154A;154A uses14E48 with RPM1214 and actual1DB2, gear and runtime compensation; alternate154C/E branches exist',
            'guard_source': '1212 is filtered saturated derivative of1202 relative to previous1232; exact physical units not established here',
            'root_consumer_shift_correction': '0x3A97E moveq #0x13 loads decimal19, so gear multiply is shifted by19, not13',
        },
        'limitations': [
            'Synthetic RAM and software-only replay do not establish physical clutch release or hydraulic response.',
            'State0 is not unconditionally zero23CA: stock speed hysteresis and later diagnostic override exist.',
            '23CA is an internal command quantity; final PWM/current/output polarity is not established here.',
            'This does not replay the full controller scheduler or every competing reason/override.',
        ],
        'static_windows': windows, 'state_dispatch_words': original[0x3F7EC:0x3F7FE].hex(),
        'cases': cases, 'all_match': all(c['pass'] for c in cases),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('low', 'high', 'stock', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('output already exists; select a new report path')
    report = investigate(args.low.read_bytes(), args.high.read_bytes(), args.stock.read_bytes())
    report['sources'] = {name: str(getattr(args, name).resolve()) for name in ('low', 'high', 'stock')}
    with args.output.open('x', encoding='utf-8', newline='\n') as output:
        output.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'cases': len(report['cases']), 'all_match': report['all_match']}))
    raise SystemExit(0 if report['all_match'] else 1)


if __name__ == '__main__':
    main()
