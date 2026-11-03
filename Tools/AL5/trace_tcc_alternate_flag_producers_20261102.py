"""Read-only AL5 alternate TCC flag/mode producer evidence and bounded replay.

The source files are never modified. Runtime contexts are synthetic; this does
not establish whole-firmware execution, vehicle behavior, or programming safety.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--low', type=Path, required=True)
    p.add_argument('--high', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--deps', type=Path)
    args = p.parse_args()
    if args.output.exists():
        raise ValueError('output already exists; preserve existing evidence')
    if args.deps:
        sys.path.insert(0, str(args.deps))
    import capstone
    import unicorn
    from capstone import Cs, CS_ARCH_M68K, CS_MODE_M68K_020, CS_MODE_BIG_ENDIAN
    from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE
    from unicorn.m68k_const import (UC_CPU_M68K_M68020, UC_M68K_REG_A5,
        UC_M68K_REG_A6, UC_M68K_REG_A7, UC_M68K_REG_SR, UC_M68K_REG_PC)

    low, high = args.low.read_bytes(), args.high.read_bytes()
    if len(low) != 0x20000 or len(high) != 0xE0000:
        raise ValueError('unexpected firmware dump size')
    data = low + high
    digest = lambda b: hashlib.sha256(b).hexdigest()
    cs = Cs(CS_ARCH_M68K, CS_MODE_M68K_020 | CS_MODE_BIG_ENDIAN)

    def instruction(i):
        return {'address': f'0x{i.address:05X}', 'bytes': bytes(i.bytes).hex(),
                'mnemonic': i.mnemonic, 'operands': i.op_str}

    references = {}
    for field in (0x1226, 0x1C7B, 0x2120, 0x2125, 0x120A, 0x120C):
        found = {}
        pattern = field.to_bytes(2, 'big')
        for offset in range(0, len(data) - 2, 2):
            if data[offset:offset+2] != pattern:
                continue
            for start in range(max(0, offset - 10), offset, 2):
                i = next(cs.disasm(data[start:offset+12], start, count=1), None)
                if (i and i.address + len(i.bytes) > offset
                        and f'${field:x}(a5)' in i.op_str):
                    found[i.address] = instruction(i)
        references[f'A5+0x{field:04X}'] = list(found.values())

    ranges = [
        ('flag_producer', 0x4ABCC, 0x4AC7E),
        ('active_state_producer', 0xB6BE4, 0xB6C8C),
        ('ccvs_decoder', 0xBAB80, 0xBAC2E),
        ('set_speed_conversion', 0xB6D14, 0xB6D42),
        ('network_payload_copy', 0x63804, 0x63878),
        ('message_kind_lookup', 0x6F828, 0x6F8FE),
        ('network_dispatch', 0xBC994, 0xBCA50),
        ('mode_producer', 0x8B658, 0x8B84C),
        ('speed_reference_producer', 0x4A940, 0x4AA72),
        ('speed_filter', 0x4AF84, 0x4AFAE),
        ('vehicle_speed_derivation', 0x4A7BC, 0x4A852),
        ('throttle_proxy_producer', 0x9754C, 0x9760A),
    ]
    windows = []
    for name, start, end in ranges:
        raw = data[start:end]
        instructions = list(cs.disasm(raw, start))
        consumed = sum(len(i.bytes) for i in instructions)
        windows.append({'name': name, 'start': hex(start), 'end_exclusive': hex(end),
            'sha256': digest(raw), 'fully_linear_decoded': consumed == len(raw),
            'instructions': [instruction(i) for i in instructions]})

    CONTEXT, STACK = 0x200000, 0x218000

    def replay(start, end, fields, patches=()):
        uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
        uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
        uc.mem_map(0, 0x100000)
        uc.mem_write(0, data)
        uc.mem_map(CONTEXT, 0x20000)
        uc.reg_write(UC_M68K_REG_SR, 0x2700)
        uc.reg_write(UC_M68K_REG_A5, CONTEXT)
        uc.reg_write(UC_M68K_REG_A6, STACK - 0x100)
        uc.reg_write(UC_M68K_REG_A7, STACK)
        for offset, raw in fields.items():
            uc.mem_write(CONTEXT + offset, raw)
        for address, raw in patches:
            uc.mem_write(address, raw)
        count = [0]
        def guard(machine, address, size, opaque):
            if not start <= address < end:
                raise ValueError(f'bounded slice escaped at {address:#x}')
            count[0] += 1
        uc.hook_add(UC_HOOK_CODE, guard)
        uc.emu_start(start, end, timeout=1_000_000, count=5000)
        if uc.reg_read(UC_M68K_REG_PC) != end:
            raise ValueError('bounded slice did not reach declared stop')
        return uc, count[0]

    word = lambda value: struct.pack('>H', value)
    flag_cases = []
    cases = [
        ('center_active', 1, 10000, 10000, 0, 0xFFFF, 1),
        ('center_inactive', 0, 10000, 10000, 0, 0xFFFF, 0),
        ('upper_equal', 1, 10000, 11280, 0, 0xFFFF, 1),
        ('upper_above', 1, 10000, 11281, 0, 0xFFFF, 0),
        ('lower_equal', 1, 10000, 8720, 0, 0xFFFF, 1),
        ('lower_below', 1, 10000, 8719, 0, 0xFFFF, 0),
        ('cap_equal', 1, 10000, 10000, 100, 100, 1),
        ('cap_above', 1, 10000, 10000, 101, 100, 0),
        ('upper_saturates', 1, 65000, 65535, 0, 0xFFFF, 1),
        ('lower_saturates', 1, 500, 0, 0, 0xFFFF, 1),
    ]
    for name, active, reference, measured, throttle, cap, expected in cases:
        uc, count = replay(0x4ABCC, 0x4AC7C,
            {0x2120: bytes([active]), 0x120A: word(reference),
             0x120C: word(measured), 0x1DB2: word(throttle)},
            [(0x14B4C, word(cap))])
        observed = int.from_bytes(uc.mem_read(CONTEXT+0x1226, 1), 'big')
        flag_cases.append({'name': name, 'active_2120': active,
            'reference_120A': reference, 'measured_120C': measured,
            'input_1DB2': throttle, 'cap_14B4C': cap,
            'expected': expected, 'observed': observed,
            'pass': observed == expected, 'instructions': count})

    state_cases = []
    for state in range(8):
        for invalid in (False, True):
            uc, count = replay(0xB6BE4, 0xB6C74,
                {0x2125: bytes([state]), 0x2348: bytes([0x10 if invalid else 0])})
            observed = int.from_bytes(uc.mem_read(CONTEXT+0x2120, 1), 'big')
            expected = int(not invalid and state in range(1, 6))
            state_cases.append({'state': state, 'invalid_bit': invalid,
                'expected': expected, 'observed': observed,
                'pass': expected == observed, 'instructions': count})

    parser_cases = []
    for state in range(8):
        # BAB9C reads payload index 6 at A6-2; supplied payload only, no bus call.
        uc, count = replay(0xBAB9C, 0xBABC4,
            {0x2125: b'\x03', 0x2348: b'\x00'},
            [(STACK - 0x102, bytes([state << 5]))])
        observed = int.from_bytes(uc.mem_read(CONTEXT+0x2125, 1), 'big')
        invalid = bool(uc.mem_read(CONTEXT+0x2348, 1)[0] & 0x10)
        expected = 3 if state == 7 else state
        parser_cases.append({'payload_byte7_high3': state, 'previous_state': 3,
            'observed_state': observed, 'observed_invalid': invalid,
            'pass': observed == expected and invalid == (state == 7),
            'instructions': count})

    mode_cases = []
    for name, fields, expected in (
        ('base_normal', {}, 0),
        ('base_tow_correlated', {0x1C7C: b'\x01'}, 1),
        ('override_10A4_stock_cal2', {0x10A4: b'\x01'}, 2),
        ('cruise_stock_cal3_falls_through', {0x2120: b'\x01'}, 0),
        ('cruise_stock_cal3_keeps_tow', {0x2120: b'\x01', 0x1C7C: b'\x01'}, 1),
        ('runtime_override_mode0', {0x2E01: b'\x01', 0x2CF4: b'\x00'}, 0),
        ('runtime_override_mode1', {0x2E01: b'\x01', 0x2CF4: b'\x01'}, 1),
        ('runtime_override_mode2', {0x2E01: b'\x01', 0x2CF4: b'\x02'}, 2),
    ):
        uc, count = replay(0x8B73A, 0x8B848, fields)
        observed = int.from_bytes(uc.mem_read(CONTEXT+0x1C7B, 1), 'big')
        mode_cases.append({'name': name, 'synthetic_fields': {hex(k): v.hex() for k,v in fields.items()},
            'expected': expected, 'observed': observed, 'pass': observed == expected,
            'instructions': count})

    report = {
        'scope': 'offline static evidence and bounded synthetic-context execution; no vehicle I/O',
        'sources': [{'path': str(path.resolve()), 'size': len(raw), 'sha256': digest(raw)}
                    for path, raw in ((args.low, low), (args.high, high))],
        'versions': {'capstone': capstone.__version__, 'unicorn': unicorn.__version__},
        'references': references,
        'reference_coverage': 'even-aligned displacement-literal candidates decoded at preceding instruction starts; excludes pointer aliases, indirect and computed references; candidates are not an exhaustive CFG',
        'windows': windows,
        'descriptor': {'address': '0x6FDD0', 'bytes': data[0x6FDD0:0x6FDD8].hex(),
                       'handler_index': data[0x6FDD1], 'pgn': '0xFEF1',
                       'dispatch_pointer_address': '0xBCA58',
                       'dispatch_pointer_bytes': data[0xBCA58:0xBCA5C].hex()},
        'stock_calibrations': {hex(a): data[a:a+n].hex() for a,n in
             ((0x14B46,2),(0x14B48,2),(0x14B4C,2),(0x11ACC,1),(0x11ACD,1),
              (0x15132,1),(0x15133,1),(0x1513A,2),(0x1513C,2),(0x15307,1),
              (0x1531D,1),(0x1531E,1))},
        'derived_flag_rule': 'A5+1226 copies A5+2120 when u16(A5+1DB2)<=u16(cal14B4C) and max(0,u16(A5+120A)-u16(cal14B48))<=u16(A5+120C)<=min(65535,u16(A5+120A)+u16(cal14B46)); otherwise zero',
        'physical_interpretation': 'Cruise-state-qualified speed-window flag: network PGN FEF1 byte7 high3 states feed2125 and then2120; byte6 feeds corrected cruise set-speed2122; 120A derives from2122 with learned scaling, and120C is filtered locally derived vehicle speed. Thus the alternate tables are cruise-conditioned throttle-release candidates, not arbitrary hot/brake modes.',
        'external_semantic_sources': [
            {'url': 'https://powertraincontrolsolutions.com/download/Released/Public/Developer_Files/PCS%20J1939%20Messages%20v2_1.pdf',
             'page': 6, 'support': 'PGN FEF1 CCVS; byte6 SPN86 cruise set speed; byte7 bits8-6 SPN527 cruise states; byte2-3 SPN84 vehicle speed'},
            {'url': 'https://assets.danfoss.com/documents/latest/67498/AQ310885477127en-000101.pdf',
             'page': 26, 'support': 'SPN527 state labels 0 off,1 hold,2 accelerate,3 decelerate,4 resume,5 set,6 accelerator override; SPN86 set speed km/h'},
        ],
        'replay': {'flag_boundary_cases': flag_cases, 'active_state_cases': state_cases,
                   'network_state_parser_cases': parser_cases, 'mode_policy_cases': mode_cases,
                   'stubs': [], 'context': 'synthetic runtime fields; source code unchanged; cap patched in emulator only for two cap boundary cases'},
        'limitations': [
            'Bounded M68020 emulation of saved AL5 byte windows does not prove the exact physical CPU or whole-controller behavior.',
            'The network payload decoder was entered after its transport-copy helper; no frame was sent or observed.',
            'Mode0/1/2 labels correlate with independently marker-mapped base tables, not all physical mode-input producers.',
            'Learned speed-scale dynamics, scheduler timing, input freshness and all alternate fault paths are not qualified here.',
            'The throttle-like 1DB2 input derives from getter1122 and optional filters; physical identity is not established in this report.',
            'No XDF or calibration bytes were changed; no live programming claim.',
        ],
    }
    all_cases = flag_cases + state_cases + parser_cases + mode_cases
    report['all_replay_cases_pass'] = all(c['pass'] for c in all_cases)
    report['replay_case_count'] = len(all_cases)
    with args.output.open('x', encoding='utf-8', newline='\n') as output:
        output.write(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'output': str(args.output), 'case_count': len(all_cases),
                      'pass': report['all_replay_cases_pass']}))
    if not report['all_replay_cases_pass']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
