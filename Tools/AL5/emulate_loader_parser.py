"""Bounded captured-loader parsing only; trap before every flash/MMIO routine."""
import argparse
import json
from pathlib import Path
from al5_segment import sha256

BASE = 0xFF9000
RX = 0xFFFF9AA0
STACK = 0xFFA700
EXPECTED_SHA = 'b545d9b2d078662466ab32d9cdeb5b3c38c840135e8aeca09f33760ec66780fa'


def experiment(code, *, count=2, payload=b'\x12\x34', address=0x8000,
               subtype=0, corrupt_sum=False, header=b'\x6d\x18\xf0\x36'):
    if sha256(code) != EXPECTED_SHA:
        raise ValueError('captured loader hash mismatch')
    from unicorn import (Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE,
                         UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE)
    from unicorn.m68k_const import (UC_CPU_M68K_M68020, UC_M68K_REG_SR,
        UC_M68K_REG_A7, UC_M68K_REG_A1,
        UC_M68K_REG_D0, UC_M68K_REG_D3, UC_M68K_REG_D7)
    tail = bytes([subtype]) + count.to_bytes(2, 'big') + address.to_bytes(3, 'big') + payload
    frame = header + tail + ((sum(tail) + int(corrupt_sum)) & 65535).to_bytes(2, 'big')
    uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
    uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    uc.mem_map(0xFF8000, 0x8000)
    uc.mem_map(0xFFFF0000, 0x10000)
    uc.mem_write(BASE, code)
    for stub in (0xFF960C, 0xFF9518, 0xFF961E, 0xFF9550):
        uc.mem_write(stub, b'\x4e\x75')
    uc.mem_write(RX, frame)
    uc.reg_write(UC_M68K_REG_SR, 0x2700)
    uc.reg_write(UC_M68K_REG_A7, STACK)
    result = {'stop': None, 'status_arguments': [], 'watchdog_calls_trapped': 0,
              'flash_commands_executed': 0, 'frame_overread_attempted': False,
              'program_source_overlaps_checksum': False, 'word_program_entry': None}

    from unicorn.m68k_const import UC_M68K_REG_PC

    def hook(machine, pc, size, _):
        if pc == 0xFF903A:
            result['stop'] = 'receive_loop_boundary'; machine.emu_stop()
        elif pc == 0xFF960C:
            result['watchdog_calls_trapped'] += 1
        elif pc == 0xFF9518:
            result['status_arguments'].append(machine.reg_read(UC_M68K_REG_D0) & 255)
        elif pc in (0xFF961E, 0xFF9550):
            pass  # isolated RTS stub; hardware code never executes
        elif pc == 0xFF93EA:
            result['word_program_entry'] = {
                'destination': hex(machine.reg_read(UC_M68K_REG_A1)),
                'remaining_bytes': machine.reg_read(UC_M68K_REG_D3) & 65535}
        elif pc == 0xFF940E:
            result['stop'] = 'flash_command_trap'; machine.emu_stop()
        elif pc == 0xFF9452:
            result['stop'] = 'flash_reset_trap'
            result['program_error_bits'] = machine.reg_read(UC_M68K_REG_D7) & 255
            machine.emu_stop()
        elif pc in (0xFF91D6, 0xFF9252, 0xFF925A):
            result['stop'] = 'other_service_trap'; machine.emu_stop()
        elif not (0xFF90BE <= pc < 0xFF91D6 or 0xFF93EA <= pc < 0xFF9462):
            raise RuntimeError(f'escaped permitted code at {pc:#x}')

    def read_hook(machine, access, address_read, size, value, _):
        if RX <= address_read < RX + 0x10000:
            if address_read + size > RX + len(frame):
                result['frame_overread_attempted'] = True
                result['stop'] = 'frame_read_trap'; machine.emu_stop()
            if machine.reg_read(UC_M68K_REG_PC) == 0xFF93FC:
                result['program_source_overlaps_checksum'] = address_read + size > RX + 10 + len(payload)

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.hook_add(UC_HOOK_MEM_READ, read_hook)
    def write_hook(machine, access, address_write, size, value, _):
        if not (STACK - 16 <= address_write < STACK or
                (size == 1 and address_write in (0xFFFF9A72, 0xFFFF9A78, 0xFFFF9A79))):
            raise RuntimeError(f'unexpected store before trap at {address_write:#x}')
    uc.hook_add(UC_HOOK_MEM_WRITE, write_hook)
    uc.emu_start(0xFF90BE, 0xFF962C, timeout=2_000_000, count=200_000)
    if result['stop'] is None:
        raise RuntimeError('execution limit reached without a classified stop')
    return result


def run(code):
    cases = [
        ('valid_even', {}, 'flash_command_trap'),
        ('zero_count', {'count': 0, 'payload': b''}, 'frame_read_trap'),
        ('odd_count_one', {'count': 1, 'payload': b'\x42'}, 'flash_command_trap'),
        ('odd_destination', {'address': 0x8001}, 'flash_command_trap'),
        ('below_calibration', {'address': 0x4000}, 'flash_command_trap'),
        ('zero_destination', {'address': 0}, 'flash_command_trap'),
        ('upper_bound', {'address': 0xFFFFE}, 'flash_reset_trap'),
        ('below_upper_bound', {'address': 0xFFFFD}, 'flash_command_trap'),
        ('short_payload', {'count': 4}, 'frame_read_trap'),
        ('bad_sum', {'corrupt_sum': True}, 'receive_loop_boundary'),
        ('delay_subtype', {'subtype': 0xDB}, 'receive_loop_boundary'),
        ('wrong_destination', {'header': bytes.fromhex('6d19f036')}, 'receive_loop_boundary'),
        ('erase_subtype', {'subtype': 0xEE}, 'other_service_trap'),
        ('finalize_subtype', {'subtype': 0xFF}, 'other_service_trap'),
    ]
    records = []
    for label, kwargs, expected in cases:
        observed = experiment(code, **kwargs)
        checks = {'stop': expected}
        if label == 'odd_count_one':
            checks['program_source_overlaps_checksum'] = True
        if label in ('zero_count', 'short_payload'):
            checks['frame_overread_attempted'] = True
        if label == 'upper_bound':
            checks['program_error_bits'] = 128
        if label in ('bad_sum', 'delay_subtype'):
            checks['status_arguments'] = [0x77 if label == 'bad_sum' else 0x73]
        records.append({'case': label, 'expected': checks, 'observed': observed,
                        'pass': all(observed[k] == v for k, v in checks.items())})
    return {'payload_sha256': sha256(code), 'generator_sha256': sha256(Path(__file__).read_bytes()),
            'scope': 'Captured parser in isolated M68020 emulator with synthetic RAM frames; flash and hardware calls trapped.',
            'limits': 'No physical transport, flash semantics or complete receive-loop emulation. Trapped overreads establish attempted reads, not physical outcomes. Word loop after first command remains unexecuted.',
            'cases': records, 'all_pass': all(c['pass'] for c in records),
            'ready_to_flash': False, 'live_write_enabled': False, 'erase_scope': None, 'would_send': []}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--loader', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    report = run(args.loader.read_bytes())
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'cases': len(report['cases']), 'all_pass': report['all_pass']}))
    raise SystemExit(0 if report['all_pass'] else 1)
