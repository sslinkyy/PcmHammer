"""File-only sender/exit emulation with synthetic FIFO readiness; all MMIO trapped."""
import argparse
import json
from pathlib import Path
from al5_segment import sha256
from emulate_loader_parser import EXPECTED_SHA, BASE, RX, STACK

RETURN = 0xFFA000


def experiment(code, *, mode='status', priority=0x6D, source=0xF0,
               status=0x73, length=3, busy_reads=0):
    if sha256(code) != EXPECTED_SHA:
        raise ValueError('captured loader hash mismatch')
    from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ
    from unicorn.m68k_const import (UC_CPU_M68K_M68020, UC_M68K_REG_SR,
        UC_M68K_REG_PC, UC_M68K_REG_A7, UC_M68K_REG_D0, UC_M68K_REG_D1)
    uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
    uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    uc.mem_map(0xFF8000, 0x8000)
    uc.mem_map(0xFFFF0000, 0x10000)
    uc.mem_write(BASE, code)
    for stub in (0xFF960C, 0xFF961A):
        uc.mem_write(stub, b'\x4e\x75')
    uc.mem_write(STACK, RETURN.to_bytes(4, 'big'))
    uc.mem_write(0xFFFF9A78, bytes([source, priority]))
    uc.mem_write(0xFFFF9A80, bytes([0x76, 0, status]))
    uc.mem_write(RX, bytes([priority, 0x18, source, 0x3C, 0x55]))
    uc.reg_write(UC_M68K_REG_SR, 0x2700)
    uc.reg_write(UC_M68K_REG_A7, STACK)
    uc.reg_write(UC_M68K_REG_D0, status)
    uc.reg_write(UC_M68K_REG_D1, length)
    entries = {'status': 0xFF9518, 'raw_sender': 0xFF952E,
               'cleanup': 0xFF9550, 'exit_dispatch': 0xFF90BE,
               'finalize_success_tail': 0xFF9224, 'finalize_failure_tail': 0xFF922E}
    if mode not in entries:
        raise ValueError('unsupported experiment mode')
    observed = {'stop': None, 'ready_reads': 0, 'watchdog_calls_trapped': 0,
                'delay_calls_trapped': 0, 'reset_instruction_executed': False,
                'mmio_instructions_executed': 0, 'source_overread_attempted': False,
                'control_writes_modeled': [], 'exit_control_data_values': [], 'fifo_groups': []}
    events = []
    control = 0

    def hook(machine, pc, size, _):
        nonlocal control
        if pc in (RETURN, 0xFF9000, 0xFF903A):
            observed['stop'] = {RETURN: 'return', 0xFF9000: 'loader_restart_trap', 0xFF903A: 'receive_boundary'}[pc]
            machine.emu_stop()
        elif pc == 0xFF924A:
            observed['stop'] = 'hardware_reset_trap'; machine.emu_stop()
        elif pc == 0xFF960C:
            observed['watchdog_calls_trapped'] += 1
        elif pc == 0xFF961A:
            observed['delay_calls_trapped'] += 1
        elif pc in (0xFF952E, 0xFF9550, 0xFF9578, 0xFF9568, 0xFF9590, 0xFF95B2, 0xFF95BE, 0xFF923A):
            control = {0xFF9568: 12, 0xFF9590: 12, 0xFF95B2: 12,
                       0xFF95BE: 4, 0xFF923A: 64}.get(pc, 20)
            observed['control_writes_modeled'].append(control)
            machine.reg_write(UC_M68K_REG_PC, pc + 6)
        elif pc == 0xFF9240:
            observed['exit_control_data_values'].append(0)
            machine.reg_write(UC_M68K_REG_PC, pc + 6)
        elif pc == 0xFF95C4:
            events.append((control, machine.reg_read(UC_M68K_REG_D0) & 255))
            machine.reg_write(UC_M68K_REG_PC, pc + 4)
        elif pc == 0xFF95D8:
            observed['ready_reads'] += 1
            busy = busy_reads is None or observed['ready_reads'] <= busy_reads
            machine.reg_write(UC_M68K_REG_D0, 3 if busy else 0)
            machine.reg_write(UC_M68K_REG_PC, pc + 4)
        elif not (0xFF9518 <= pc < 0xFF95FC or 0xFF90BE <= pc < 0xFF9130 or
                  0xFF9224 <= pc < 0xFF9250 or 0xFF925A <= pc <= 0xFF9282):
            raise RuntimeError(f'execution escaped allowed sender/exit code at {pc:#x}')

    def write_hook(machine, access, addr, size, value, _):
        if not (STACK - 32 <= addr and addr + size <= STACK or
                size == 1 and addr in (0xFFFF9A72, 0xFFFF9A78, 0xFFFF9A79, 0xFFFF9A80, 0xFFFF9A81, 0xFFFF9A82)):
            raise RuntimeError(f'unexpected instruction store at {addr:#x}')

    def read_hook(machine, access, addr, size, value, _):
        if 0xFFFFE800 <= addr < 0xFFFFE802:
            raise RuntimeError('MMIO read escaped trap')
        if machine.reg_read(UC_M68K_REG_PC) in (0xFF95A4, 0xFF95B8) and addr + size > 0xFFFF9A83:
            observed['source_overread_attempted'] = True
            observed['stop'] = 'body_read_trap'; machine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.hook_add(UC_HOOK_MEM_WRITE, write_hook)
    uc.hook_add(UC_HOOK_MEM_READ, read_hook)
    uc.emu_start(entries[mode], 0xFF962C, timeout=5_000_000, count=500_000)
    if observed['stop'] is None:
        raise RuntimeError('execution limit without classified stop')
    groups = []
    for ctrl, byte in events:
        if ctrl == 20 or not groups:
            groups.append([])
        groups[-1].append((ctrl, byte))
    for group in groups:
        data = bytes(byte for _, byte in group)
        fields = {'bytes': len(data), 'sha256': sha256(data), 'final_control': group[-1][0]}
        if len(data) >= 3 and group[0][0] == 20:
            fields['header'] = {'priority': data[0], 'destination': data[1], 'source': data[2]}
            fields['body_bytes'] = len(data) - 3
            if len(data) == 6:
                fields['status_body'] = {'service': data[3], 'subtype': data[4], 'status': data[5]}
        observed['fifo_groups'].append(fields)
    return observed


def run(code):
    cases = [
        ('status_ready', {}, 'return'),
        ('priority_6c_source_f1', {'priority': 0x6C, 'source': 0xF1}, 'return'),
        ('delayed_ready', {'busy_reads': 5}, 'return'),
        ('always_busy', {'busy_reads': None}, 'loader_restart_trap'),
        ('cleanup_broadcasts', {'mode': 'cleanup'}, 'return'),
        ('length_zero', {'mode': 'raw_sender', 'length': 0}, 'body_read_trap'),
        ('length_one', {'mode': 'raw_sender', 'length': 1}, 'body_read_trap'),
        ('exit_request', {'mode': 'exit_dispatch'}, 'hardware_reset_trap'),
        ('finalize_success_tail', {'mode': 'finalize_success_tail'}, 'hardware_reset_trap'),
        ('finalize_failure_tail', {'mode': 'finalize_failure_tail'}, 'hardware_reset_trap'),
    ]
    records = []
    for label, kwargs, stop in cases:
        observed = experiment(code, **kwargs)
        checks = {'stop': stop}
        if label == 'always_busy':
            checks.update(ready_reads=4095, watchdog_calls_trapped=4096)
        if label in ('length_zero', 'length_one'):
            checks['source_overread_attempted'] = True
        if label in ('exit_request', 'finalize_success_tail', 'finalize_failure_tail'):
            checks.update(delay_calls_trapped=2, exit_control_data_values=[0])
        records.append({'case': label, 'expected_stop': stop, 'observed': observed,
                        'expected': checks, 'pass': all(observed[k] == v for k, v in checks.items())})
    return {'payload_sha256': sha256(code), 'generator_sha256': sha256(Path(__file__).read_bytes()),
            'scope': 'Captured sender and bounded exit tails with synthetic FIFO readiness. Every MMIO instruction skipped; watchdog/delay stubbed and reset/restart trapped.',
            'limits': 'FIFO bytes are software observations, not complete physical frames. Controller CRC/checksum, arbitration, timing and successful reset/recovery remain unverified. Finalize tail cases bypass all verification and marker programming.',
            'reset_mmio_address': '0xffff8000', 'physical_reset_verified': False,
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
