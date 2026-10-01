"""Exercise the resident command dispatcher offline with every flash call trapped.

Only dispatcher code, synthetic RAM and explicit helper stubs are mapped.
No flash routine, peripheral, adapter, serial API or bus transport is available.
"""
import argparse
import json
import struct
from pathlib import Path
from al5_segment import sha256

ENTRY, END = 0x19C8, 0x2A24
FLASH, SEND, STACK, RETURN = 0xFF8500, 0x1820, 0x208000, 0x300000


def emulate(code, payload, length, *, message_type=4, identifier=0x3F8, ram_mode=0, flash_status=0):
    from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE
    from unicorn.m68k_const import UC_CPU_M68K_M68020, UC_M68K_REG_SR, UC_M68K_REG_A7, UC_M68K_REG_PC, UC_M68K_REG_D0
    if len(payload) > 8 or not 0 <= length <= 8:
        raise ValueError('synthetic input exceeds eight-byte buffer')
    uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
    uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    uc.mem_map(0x1000, 0x2000)
    uc.mem_map(0xFF8000, 0x4000)
    uc.mem_map(0x200000, 0x10000)
    uc.mem_map(RETURN, 0x1000)
    uc.mem_write(ENTRY, code)
    uc.mem_write(STACK, struct.pack('>I', RETURN))
    uc.mem_write(0xFF814C, struct.pack('>I', FLASH))
    uc.mem_write(0xFF8088, bytes([(message_type << 4) | length]))
    uc.mem_write(0xFF808A, struct.pack('>I', identifier << 3))
    uc.mem_write(0xFF808E, payload.ljust(8, b'\0'))
    uc.mem_write(0xFF815C, bytes([ram_mode]))
    uc.reg_write(UC_M68K_REG_SR, 0x2700)
    uc.reg_write(UC_M68K_REG_A7, STACK)
    calls, responses, executed = [], [], [0]

    def stub_return(machine, value):
        sp = machine.reg_read(UC_M68K_REG_A7)
        target = struct.unpack('>I', machine.mem_read(sp, 4))[0]
        machine.reg_write(UC_M68K_REG_D0, value)
        machine.reg_write(UC_M68K_REG_A7, sp+4)
        machine.reg_write(UC_M68K_REG_PC, target)

    def guard(machine, address, size, user_data):
        executed[0] += 1
        if address == FLASH:
            sp = machine.reg_read(UC_M68K_REG_A7)
            args = bytes(machine.mem_read(sp+4, 14))
            operation = struct.unpack_from('>I', args)[0]
            source, destination = struct.unpack_from('>2I', args, 6)
            count = args[5]
            data = bytes(machine.mem_read(source, count)) if operation == 1 and count else b''
            calls.append({'operation': operation, 'selector': args[4], 'count': count,
                'destination': f'0x{destination:06X}', 'data_hex': data.hex(),
                'primitive_executed': False})
            stub_return(machine, flash_status)
        elif address == SEND:
            sp = machine.reg_read(UC_M68K_REG_A7)
            frame = bytes(machine.mem_read(sp+4, 18))
            responses.append({'internal_frame_hex': frame.hex(), 'data_hex': frame[10:10+(frame[0] & 15)].hex()})
            stub_return(machine, 0)
        elif not ENTRY <= address < END:
            raise RuntimeError(f'dispatcher escaped at {address:#x}')

    uc.hook_add(UC_HOOK_CODE, guard)
    uc.emu_start(ENTRY, RETURN, timeout=2_000_000, count=100_000)
    if uc.reg_read(UC_M68K_REG_A7) != STACK+4:
        raise RuntimeError('dispatcher did not return normally')
    return {'flash_calls': calls, 'responses': responses, 'instructions': executed[0],
            'memory_mode': ram_mode, 'stored_address': bytes(uc.mem_read(0xFF8158, 4)).hex(),
            'ram_probe_hex': bytes(uc.mem_read(0xFF9000, 4)).hex(),
            'ready_to_flash': False, 'live_write_enabled': False}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--low', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    low = args.low.read_bytes()
    if len(low) != 0x20000:
        raise ValueError('unexpected low editor dump size')
    code = low[ENTRY:END]
    cases = [
        ('erase_selector_3_trapped', bytes.fromhex('1203'), 2, {}, 1),
        ('program_2_bytes_trapped', bytes.fromhex('220080001234'), 6, {}, 1),
        ('program_4_bytes_trapped', bytes.fromhex('2301000012345678'), 8, {}, 1),
        ('program_odd_count_rejected', bytes.fromhex('2200800012'), 5, {}, 0),
        ('program_below_4000_rejected', bytes.fromhex('220020001234'), 6, {}, 0),
        ('program_odd_address_rejected', bytes.fromhex('220080011234'), 6, {}, 0),
        ('program_crosses_flash_limit_rejected', bytes.fromhex('230FFFFE12345678'), 8, {}, 0),
        ('wrong_message_type_ignored', bytes.fromhex('1203'), 2, {'message_type': 3}, 0),
        ('wrong_identifier_ignored', bytes.fromhex('1203'), 2, {'identifier': 0x2F8}, 0),
        ('zero_data_program_no_flash', bytes.fromhex('23008000'), 4, {}, 0),
        ('program_failure_status_stub', bytes.fromhex('220080001234'), 6, {'flash_status': 1}, 1),
        ('erase_short_length_uses_staged_selector', bytes.fromhex('1203'), 1, {}, 1),
        ('program_length_underflow_trapped', bytes.fromhex('220080001234'), 0, {}, 1),
        ('ram_copy_no_flash', bytes.fromhex('22FF900012345678'), 8, {'ram_mode': 1}, 0),
        ('ram_below_loader_range_rejected', bytes.fromhex('22FF80001234'), 6, {'ram_mode': 1}, 0),
        ('alternate_identifier_accepted', bytes.fromhex('220080001234'), 6, {'identifier': 0x3F9}, 1),
    ]
    expected_calls_by_case = {
        'erase_selector_3_trapped': (0, 3, 0, '0x000000', ''),
        'erase_short_length_uses_staged_selector': (0, 3, 0, '0x000000', ''),
        'program_2_bytes_trapped': (1, 0, 2, '0x008000', '1234'),
        'program_4_bytes_trapped': (1, 0, 4, '0x010000', '12345678'),
        'program_failure_status_stub': (1, 0, 2, '0x008000', '1234'),
        'alternate_identifier_accepted': (1, 0, 2, '0x008000', '1234'),
    }
    expected_responses = {
        'erase_selector_3_trapped': ['1200'],
        'erase_short_length_uses_staged_selector': ['1200'],
        'program_2_bytes_trapped': ['2200800000'],
        'program_4_bytes_trapped': [],
        'program_odd_count_rejected': ['2200800002'],
        'program_below_4000_rejected': ['2200200002'],
        'program_odd_address_rejected': ['2200800102'],
        'program_crosses_flash_limit_rejected': [],
        'wrong_message_type_ignored': [], 'wrong_identifier_ignored': [],
        'zero_data_program_no_flash': [],
        'program_failure_status_stub': ['2200800001'],
        'ram_copy_no_flash': ['22ff900000'],
        'ram_below_loader_range_rejected': ['22ff800002'],
        'alternate_identifier_accepted': ['2200800000'],
        'program_length_underflow_trapped': ['2200800000'],
    }
    records = []
    for label, payload, length, options, expected_calls in cases:
        result = emulate(code, payload, length, **options)
        checks = [len(result['flash_calls']) == expected_calls,
                  [r['data_hex'] for r in result['responses']] == expected_responses[label],
                  all(not c['primitive_executed'] for c in result['flash_calls'])]
        if label in expected_calls_by_case:
            c = result['flash_calls'][0] if result['flash_calls'] else {}
            checks.append(tuple(c.get(k) for k in ('operation', 'selector', 'count', 'destination', 'data_hex'))
                          == expected_calls_by_case[label])
        if label == 'program_length_underflow_trapped':
            c = result['flash_calls'][0] if result['flash_calls'] else {}
            checks.extend([c.get('operation') == 1, c.get('count') == 252,
                           c.get('destination') == '0x008000'])
        checks.append(result['ram_probe_hex'] == ('12345678' if label == 'ram_copy_no_flash' else '00000000'))
        result.update(case=label, input_hex=payload.hex(), injected_length=length,
                      expected_flash_calls=expected_calls,
                      checks=checks, pass_case=all(checks))
        records.append(result)
        print(label, 'PASS' if result['pass_case'] else 'FAIL',
              'trapped calls', len(result['flash_calls']),
              'response data', [r['data_hex'] for r in result['responses']])
    report = {'source_sha256': sha256(low), 'dispatcher_sha256': sha256(code),
        'dispatcher_address': f'0x{ENTRY:05X}',
        'scope': 'isolated dispatcher; synthetic memory-buffer inputs; flash and send stubs',
        'transport_warning': 'Internal identifier/control representation; not a live CAN or VPW packet builder',
        'all_pass': all(r['pass_case'] for r in records), 'cases': records}
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    raise SystemExit(0 if report['all_pass'] else 1)
