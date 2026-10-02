"""Captured word loop with host-modeled flash only; no device or adapter access."""
import argparse
import json
from pathlib import Path
from al5_segment import sha256
from emulate_loader_parser import EXPECTED_SHA, RX, STACK, BASE


def experiment(code, *, count=4, payload=b'\x12\x34\x56\x78', address=0x8000,
               fail_word=None, direct_word_entry=False):
    if sha256(code) != EXPECTED_SHA:
        raise ValueError('captured loader hash mismatch')
    from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
    from unicorn.m68k_const import (UC_CPU_M68K_M68020, UC_M68K_REG_SR,
        UC_M68K_REG_PC, UC_M68K_REG_A7, UC_M68K_REG_A0, UC_M68K_REG_A1,
        UC_M68K_REG_D0, UC_M68K_REG_D1, UC_M68K_REG_D3)
    tail = b'\x00' + count.to_bytes(2, 'big') + address.to_bytes(3, 'big') + payload
    frame = bytes.fromhex('6d18f036') + tail
    if not direct_word_entry:
        frame += (sum(tail) & 65535).to_bytes(2, 'big')
    uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
    uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    uc.mem_map(0, 0x100000)  # synthetic flash backing, never hardware
    uc.mem_map(0xFF8000, 0x8000)
    uc.mem_map(0xFFFF0000, 0x10000)
    uc.mem_write(BASE, code)
    for stub in (0xFF960C, 0xFF961E, 0xFF9550, 0xFF952E):
        uc.mem_write(stub, b'\x4e\x75')
    uc.mem_write(RX, frame)
    uc.reg_write(UC_M68K_REG_SR, 0x2700)
    uc.reg_write(UC_M68K_REG_A7, STACK)
    if direct_word_entry:
        uc.reg_write(UC_M68K_REG_A0, RX + 10)
        uc.reg_write(UC_M68K_REG_A1, address)
        uc.reg_write(UC_M68K_REG_D1, 0)
        uc.reg_write(UC_M68K_REG_D3, count)
        uc.mem_write(STACK, (0xFF903A).to_bytes(4, 'big'))
    observed = {'stop': None, 'modeled_words': [], 'responses': [], 'loop_counts': [],
                'poll_reads': 0, 'reset_sequences_trapped': 0,
                'source_overread_attempted': False, 'checksum_source_words': 0,
                'flash_command_instructions_executed': 0}

    def hook(machine, pc, size, _):
        if pc == 0xFF903A:
            observed['stop'] = 'receive_boundary'; machine.emu_stop()
        elif pc == 0xFF93EA:
            observed['loop_counts'].append(machine.reg_read(UC_M68K_REG_D3) & 65535)
        elif pc == 0xFF940E:
            # Skip all four command stores. Model readback, then execute real polling.
            dest = machine.reg_read(UC_M68K_REG_A1)
            word = machine.reg_read(UC_M68K_REG_D0) & 65535
            index = len(observed['modeled_words'])
            if index >= 16:
                observed['stop'] = 'word_budget'; machine.emu_stop(); return
            success = index != fail_word
            observed['modeled_words'].append({'address': hex(dest),
                'remaining_bytes': machine.reg_read(UC_M68K_REG_D3) & 65535,
                'readback_matches': success})
            machine.mem_write(dest, (word if success else word ^ 1).to_bytes(2, 'big'))
            machine.reg_write(UC_M68K_REG_PC, 0xFF941C)
        elif pc == 0xFF9452:
            observed['reset_sequences_trapped'] += 1
            machine.reg_write(UC_M68K_REG_PC, 0xFF945A)
        elif pc in (0xFF960C, 0xFF961E, 0xFF9550):
            pass  # return stubs, no hardware behavior
        elif pc == 0xFF952E:
            length = machine.reg_read(UC_M68K_REG_D1) & 255
            if length != 3:
                raise RuntimeError('unexpected response length')
            body = bytes(machine.mem_read(0xFFFF9A80, 3))
            observed['responses'].append({'service': body[0], 'subtype': body[1], 'status': body[2]})
        elif pc in (0xFF91D6, 0xFF9252, 0xFF925A):
            raise RuntimeError('unexpected destructive/other service')
        elif not (0xFF90BE <= pc < 0xFF91D6 or 0xFF93EA <= pc < 0xFF9462 or 0xFF94A8 <= pc < 0xFF952E):
            raise RuntimeError(f'execution escaped at {pc:#x}')

    def read_hook(machine, access, addr, size, value, _):
        pc = machine.reg_read(UC_M68K_REG_PC)
        if pc in (0xFF9420, 0xFF942A):
            observed['poll_reads'] += 1
        if RX <= addr < RX + 0x10000:
            if addr + size > RX + len(frame):
                observed['source_overread_attempted'] = True
                observed['stop'] = 'source_read_trap'; machine.emu_stop()
            elif pc == 0xFF93FC and addr + size > RX + 10 + len(payload):
                observed['checksum_source_words'] += 1

    def write_hook(machine, access, addr, size, value, _):
        allowed = STACK - 16 <= addr < STACK or (
            size == 1 and addr in (0xFFFF9A72, 0xFFFF9A78, 0xFFFF9A79, 0xFFFF9A80, 0xFFFF9A81, 0xFFFF9A82))
        if not allowed:
            raise RuntimeError(f'unexpected emulated instruction store at {addr:#x}')
    uc.hook_add(UC_HOOK_CODE, hook)
    uc.hook_add(UC_HOOK_MEM_READ, read_hook)
    uc.hook_add(UC_HOOK_MEM_WRITE, write_hook)
    uc.emu_start(0xFF93EA if direct_word_entry else 0xFF90BE, 0xFF962C,
                 timeout=5_000_000, count=500_000)
    if observed['stop'] is None:
        raise RuntimeError('execution limit reached without classified stop')
    return observed


def run(code):
    cases = [
        ('two_words_success', {}, 'receive_boundary', [0x73], 2),
        ('first_word_failure', {'fail_word': 0}, 'receive_boundary', [0xF8], 1),
        ('second_word_failure', {'fail_word': 1}, 'receive_boundary', [0xF8], 2),
        ('upper_bound_rejected', {'address': 0xFFFFE}, 'receive_boundary', [0x74], 0),
        ('later_upper_bound', {'address': 0xFFFFC}, 'receive_boundary', [0x74], 1),
        ('odd_count', {'count': 1, 'payload': b'\x42'}, 'source_read_trap', [], 1),
        ('zero_word_count_direct', {'count': 0, 'direct_word_entry': True}, 'source_read_trap', [], 2),
        ('below_calibration', {'address': 0x4000}, 'receive_boundary', [0x73], 2),
    ]
    records = []
    for label, kwargs, stop, statuses, words in cases:
        actual = experiment(code, **kwargs)
        passed = (actual['stop'] == stop and len(actual['modeled_words']) == words and
                  [r['status'] for r in actual['responses']] == statuses)
        if label == 'odd_count':
            passed = passed and actual['loop_counts'] == [1, 65535] and actual['checksum_source_words'] == 1
        if label == 'zero_word_count_direct':
            passed = passed and actual['loop_counts'] == [0, 65534, 65532]
        records.append({'case': label, 'expected': {'stop': stop, 'statuses': statuses, 'word_count': words},
                        'observed': actual, 'pass': passed})
    return {'payload_sha256': sha256(code), 'generator_sha256': sha256(Path(__file__).read_bytes()),
            'scope': 'Real captured loop/poll/error/status instructions, synthetic immediate-match or permanent-mismatch flash backing. All command/reset stores skipped and hardware sender stubbed.',
            'limits': 'No physical flash, timing, transport, recovery or erase model. Zero word count enters the routine directly and bypasses parser. Response body construction is exercised, not wire transmission.',
            'cases': records, 'all_pass': all(r['pass'] for r in records),
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
