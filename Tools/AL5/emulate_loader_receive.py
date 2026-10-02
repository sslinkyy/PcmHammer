"""Saved receive loop with synthetic register events and bounded buffer stores."""
import argparse
import json
from pathlib import Path
from al5_segment import sha256
from emulate_loader_parser import EXPECTED_SHA, BASE, RX, STACK


def frame_events(body=b'\x6d\x18\xf0\x3c\x05', flags=0):
    if len(body) < 2:
        raise ValueError('synthetic complete frame requires at least two bytes')
    return [(1, b) for b in body[:-1]] + [(5, body[-1]), (0, flags)]


def experiment(code, events, *, buffer_limit=16, frame_budget=255,
               counter_seed=None, repeat_dispatch=False):
    if sha256(code) != EXPECTED_SHA:
        raise ValueError('captured loader hash mismatch')
    from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ
    from unicorn.m68k_const import (UC_CPU_M68K_M68020, UC_M68K_REG_SR,
        UC_M68K_REG_PC, UC_M68K_REG_A7, UC_M68K_REG_A0,
        UC_M68K_REG_D0, UC_M68K_REG_D3, UC_M68K_REG_D4)
    uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
    uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    uc.mem_map(0xFF8000, 0x8000)
    uc.mem_map(0xFFFF0000, 0x10000)
    uc.mem_write(BASE, code)
    for stub in (0xFF960C, 0xFF95EE):
        uc.mem_write(stub, b'\x4e\x75')
    uc.mem_write(0xFFFF9A72, bytes([frame_budget]))
    uc.reg_write(UC_M68K_REG_SR, 0x2700)
    uc.reg_write(UC_M68K_REG_A7, STACK)
    result = {'stop': None, 'events_consumed': 0, 'buffer_bytes_written': 0,
              'maximum_frame_bytes': 0, 'dispatch_boundaries': 0,
              'discard_reads': 0, 'completion_flags': [], 'counter_seeds_applied': [],
              'buffer_overrun_attempted': False, 'watchdog_calls_trapped': 0,
              'mmio_instructions_executed': 0, 'reset_instruction_executed': False}
    position = 0
    frame_bytes = 0
    seeded = set()

    def pop():
        nonlocal position
        if position >= len(events):
            raise RuntimeError('data read exhausted synthetic events')
        value = events[position][1]
        position += 1
        result['events_consumed'] = position
        return value

    def hook(machine, pc, size, _):
        nonlocal frame_bytes
        if pc == 0xFF903A and position == len(events) and counter_seed is None:
            result['stop'] = 'receive_boundary'; machine.emu_stop()
        elif pc in (0xFF903C, 0xFF906C) and counter_seed is not None and pc not in seeded:
            machine.reg_write(UC_M68K_REG_D3, counter_seed)
            seeded.add(pc)
            result['counter_seeds_applied'].append(hex(pc))
        elif pc == 0xFF9236:
            result['stop'] = 'shared_exit_trap'; machine.emu_stop()
        elif pc == 0xFF90BE:
            if not repeat_dispatch:
                result['dispatch_boundaries'] += 1
                result['stop'] = 'dispatcher_trap'; machine.emu_stop()
        elif pc == 0xFF90D8 and repeat_dispatch:
            result['dispatch_boundaries'] += 1
            machine.reg_write(UC_M68K_REG_PC, 0xFF903A)
        elif pc == 0xFF9048:
            frame_bytes = 0
        elif pc in (0xFF9056, 0xFF907C, 0xFF9092):
            status = events[position][0] if position < len(events) else 0
            machine.reg_write(UC_M68K_REG_D4, status << 5)
            machine.reg_write(UC_M68K_REG_PC, pc + 4)
        elif pc in (0xFF9066, 0xFF9086):
            dest = machine.reg_read(UC_M68K_REG_A0)
            if not RX <= dest < RX + buffer_limit:
                result['buffer_overrun_attempted'] = True
                result['stop'] = 'buffer_write_trap'; machine.emu_stop(); return
            machine.mem_write(dest, bytes([pop()]))
            machine.reg_write(UC_M68K_REG_A0, dest + 1)
            frame_bytes += 1
            result['buffer_bytes_written'] += 1
            result['maximum_frame_bytes'] = max(result['maximum_frame_bytes'], frame_bytes)
            machine.reg_write(UC_M68K_REG_PC, pc + 4)
        elif pc == 0xFF9096:
            flags = pop()
            result['completion_flags'].append(flags)
            machine.reg_write(UC_M68K_REG_D3, flags)
            machine.reg_write(UC_M68K_REG_PC, pc + 4)
        elif pc == 0xFF9032:
            machine.reg_write(UC_M68K_REG_D0, pop())
            result['discard_reads'] += 1
            machine.reg_write(UC_M68K_REG_PC, pc + 4)
        elif pc == 0xFF960C:
            result['watchdog_calls_trapped'] += 1
            if result['watchdog_calls_trapped'] > 10000:
                raise RuntimeError('bounded synthetic receive budget exhausted')
        elif pc == 0xFF95EE:
            pass
        elif not 0xFF9032 <= pc < 0xFF90D8:
            raise RuntimeError(f'escaped receive loop at {pc:#x}')

    def store_hook(machine, access, addr, size, value, _):
        if not (STACK - 16 <= addr and addr + size <= STACK or addr == 0xFFFF9A72 and size == 1):
            raise RuntimeError(f'unexpected instruction store at {addr:#x}')

    def read_hook(machine, access, addr, size, value, _):
        if 0xFFFFE800 <= addr < 0xFFFFE802:
            raise RuntimeError('hardware read escaped interception')

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.hook_add(UC_HOOK_MEM_WRITE, store_hook)
    uc.hook_add(UC_HOOK_MEM_READ, read_hook)
    uc.emu_start(0xFF903A, 0xFF962C, timeout=5_000_000, count=100000)
    if result['stop'] is None:
        raise RuntimeError('execution limit without classified stop')
    result['remaining_frame_budget'] = bytes(uc.mem_read(0xFFFF9A72, 1))[0]
    result['saved_frame_prefix_sha256'] = sha256(bytes(uc.mem_read(RX, result['maximum_frame_bytes'])))
    return result


def run(code):
    normal = frame_events()
    cases = [
        ('complete_frame', normal, {}, 'dispatcher_trap'),
        ('two_byte_frame', frame_events(b'\x6d\x18'), {}, 'dispatcher_trap'),
        ('discard_then_frame', [(7, 0)] + normal, {}, 'dispatcher_trap'),
        ('top_completion_error', frame_events(flags=0x40), {}, 'receive_boundary'),
        ('middle_completion_error', frame_events(flags=0x10), {}, 'receive_boundary'),
        ('idle_timeout_boundary', [], {'counter_seed': 0x4FFFF}, 'shared_exit_trap'),
        ('partial_frame_timeout_boundary', [(1, 0x6D)], {'counter_seed': 0x4FFFE}, 'shared_exit_trap'),
        ('model_buffer_limit_crossing', frame_events(b'\x42' * 17), {}, 'buffer_write_trap'),
        ('one_frame_budget', normal, {'frame_budget': 1}, 'shared_exit_trap'),
        ('priority_6c_frame_budget', frame_events(b'\x6c\x18\xf0\x3c\x05') * 255, {'repeat_dispatch': True}, 'shared_exit_trap'),
        ('priority_6d_refreshes_budget', normal * 256, {'repeat_dispatch': True}, 'receive_boundary'),
    ]
    records = []
    for label, events, kwargs, expected in cases:
        observed = experiment(code, events, **kwargs)
        checks = {'stop': expected}
        if label == 'priority_6c_frame_budget':
            checks.update(dispatch_boundaries=254, remaining_frame_budget=0)
        if label == 'priority_6d_refreshes_budget':
            checks.update(dispatch_boundaries=256, remaining_frame_budget=255)
        if label == 'two_byte_frame':
            checks['maximum_frame_bytes'] = 2
        if label == 'model_buffer_limit_crossing':
            checks.update(buffer_overrun_attempted=True, maximum_frame_bytes=16)
        if label == 'discard_then_frame':
            checks['discard_reads'] = 1
        records.append({'case': label, 'expected': checks, 'observed': observed,
                        'pass': all(observed[k] == value for k, value in checks.items())})
    return {'payload_sha256': sha256(code), 'generator_sha256': sha256(Path(__file__).read_bytes()),
            'scope': 'Actual receive-loop branches with synthetic register events, explicit buffer limit and dispatch/exit traps. Timeout cases seed counters near their compare boundary.',
            'limits': 'No physical FIFO/CRC semantics or elapsed timeout. Repeated-frame tests execute only the dispatcher priority prefix, then substitute return to the receive loop. The 16-byte trap is a model boundary, not a measured hardware buffer size.',
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
