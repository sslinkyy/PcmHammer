"""Captured loader entry through receive/parser and bounded modeled word writes.

All setup/flash/MMIO stores are skipped or trapped before execution. FIFO,
sender and readback are synthetic. No adapter API or executable byte patches.
"""
import argparse
import json
from pathlib import Path

from al5_segment import sha256
from emulate_loader_parser import BASE, RX, EXPECTED_SHA

ENTRY_STACK = 0xFFA7FE
RANGES = ((BASE, BASE+0x26), (BASE+0x32, BASE+0x1D6),
          (BASE+0x3EA, BASE+0x462), (BASE+0x4A8, BASE+0x52E))


def executable_span(pc, size):
    return size > 0 and any(a <= pc and pc+size <= b for a, b in RANGES)


def writable_span(address, size):
    return size > 0 and (ENTRY_STACK-256 <= address and address+size <= ENTRY_STACK or
        size == 1 and address in (0xFFFF9A72, 0xFFFF9A78, 0xFFFF9A79,
                                   0xFFFF9A80, 0xFFFF9A81, 0xFFFF9A82))


class LoaderSession:
    def __init__(self, code):
        if sha256(code) != EXPECTED_SHA:
            raise ValueError('captured loader hash mismatch')
        import unicorn
        if unicorn.__version__ != '2.1.4':
            raise ValueError('requires Unicorn 2.1.4')
        from unicorn.m68k_const import UC_CPU_M68K_M68020, UC_M68K_REG_SR, UC_M68K_REG_A7, UC_M68K_REG_D7
        self.code = code
        self.uc = unicorn.Uc(unicorn.UC_ARCH_M68K, unicorn.UC_MODE_BIG_ENDIAN)
        self.uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
        self.uc.mem_map(0, 0x100000, unicorn.UC_PROT_READ)
        self.uc.mem_map(0xFF8000, 0x8000)
        self.uc.mem_map(0xFFFF0000, 0x10000)
        self.uc.mem_write(BASE, code)
        self.uc.mem_protect(BASE, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
        self.uc.reg_write(UC_M68K_REG_SR, 0x2000)
        self.uc.reg_write(UC_M68K_REG_A7, 0xFFA600)
        self.uc.reg_write(UC_M68K_REG_D7, 0xA5)
        self.uc.mem_write(RX, b'\xA5'*16)
        self.uc.mem_write(0xFFFF9A72, b'\x12')
        self.started = False
        self.closed = False
        self.events = []
        self.frame_length = 0
        self.readback = 'trap'
        self.fail_word = None
        self.observed = {}
        self.uc.hook_add(unicorn.UC_HOOK_CODE, self.hook)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_READ, self.read_hook)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, self.write_hook)

    def callback_return(self, target):
        from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_PC
        sp = self.uc.reg_read(UC_M68K_REG_A7)
        if not ENTRY_STACK-256 <= sp <= ENTRY_STACK-4:
            raise RuntimeError('helper stack escaped ownership')
        ret = int.from_bytes(self.uc.mem_read(sp, 4), 'big')
        offset = ret-BASE
        word = self.code[offset-4:offset-2] == b'\x61\x00' and (
            ret-2 + int.from_bytes(self.code[offset-2:offset], 'big', signed=True) == target)
        short = self.code[offset-2:offset-1] == b'\x61' and self.code[offset-1:offset] != b'\x00' and (
            ret + int.from_bytes(self.code[offset-1:offset], 'big', signed=True) == target)
        if not executable_span(ret, 2) or not (word or short):
            raise RuntimeError('unexpected synthetic helper caller')
        self.uc.reg_write(UC_M68K_REG_A7, sp+4)
        self.uc.reg_write(UC_M68K_REG_PC, ret)

    def pop(self):
        if not self.events:
            raise RuntimeError('synthetic receive events exhausted')
        self.observed['events_consumed'] += 1
        return self.events.pop(0)[1]

    def hook(self, machine, pc, size, _):
        from unicorn.m68k_const import (UC_M68K_REG_PC, UC_M68K_REG_A0, UC_M68K_REG_A1,
                                        UC_M68K_REG_D0, UC_M68K_REG_D1, UC_M68K_REG_D3, UC_M68K_REG_D4)
        if pc == BASE+0x3A and (self.mode == 'entry' or not self.events):
            self.observed['stop'] = 'receive_boundary'
            machine.emu_stop()
        elif pc in (BASE+0x1D6, BASE+0x236, BASE+0x252, BASE+0x25A):
            self.observed['stop'] = {BASE+0x1D6: 'finalize_entry', BASE+0x236: 'reset_exit',
                                     BASE+0x252: 'erase_entry', BASE+0x25A: 'other_service'}[pc]
            machine.emu_stop()
        elif pc == BASE+0xA:
            self.observed['suppressed_setup_stores'] += 1
            machine.reg_write(UC_M68K_REG_PC, BASE+0x10)
        elif pc in (BASE+0x60C, BASE+0x61A, BASE+0x61E, BASE+0x5EE, BASE+0x550):
            name = hex(pc)
            calls = self.observed['synthetic_helper_calls']
            calls[name] = calls.get(name, 0)+1
            self.callback_return(pc)
        elif pc == BASE+0x52E:
            if machine.reg_read(UC_M68K_REG_D1) & 255 != 3:
                raise RuntimeError('unexpected status length')
            self.observed['responses'].append(bytes(machine.mem_read(0xFFFF9A80, 3)).hex())
            self.callback_return(pc)
        elif pc in (BASE+0x56, BASE+0x7C, BASE+0x92):
            if not self.events:
                raise RuntimeError('synthetic status unavailable')
            machine.reg_write(UC_M68K_REG_D4, self.events[0][0] << 5)
            machine.reg_write(UC_M68K_REG_PC, pc+4)
        elif pc in (BASE+0x66, BASE+0x86):
            address = machine.reg_read(UC_M68K_REG_A0)
            if not RX <= address < RX+16:
                raise RuntimeError('receive buffer model boundary exceeded')
            machine.mem_write(address, bytes([self.pop()]))
            machine.reg_write(UC_M68K_REG_A0, address+1)
            machine.reg_write(UC_M68K_REG_PC, pc+4)
        elif pc == BASE+0x96:
            machine.reg_write(UC_M68K_REG_D3, self.pop())
            machine.reg_write(UC_M68K_REG_PC, pc+4)
        elif pc == BASE+0x32:
            machine.reg_write(UC_M68K_REG_D0, self.pop())
            machine.reg_write(UC_M68K_REG_PC, pc+4)
        elif pc == BASE+0x40E:
            if self.readback == 'trap':
                self.observed['stop'] = 'before_flash_command'
                machine.emu_stop()
                return
            index = len(self.observed['modeled_words'])
            if index >= 2:
                raise RuntimeError('two-word model budget exceeded')
            address = machine.reg_read(UC_M68K_REG_A1)
            if address not in (0x8000, 0x8002):
                raise RuntimeError('synthetic readback address escaped test region')
            word = machine.reg_read(UC_M68K_REG_D0) & 65535
            matches = index != self.fail_word
            machine.mem_write(address, (word if matches else word ^ 1).to_bytes(2, 'big'))
            self.observed['modeled_words'].append(dict(address=hex(address), readback_matches=matches))
            self.observed['suppressed_flash_stores'] += 4
            machine.reg_write(UC_M68K_REG_PC, BASE+0x41C)
        elif pc == BASE+0x452:
            self.observed['suppressed_flash_stores'] += 2
            machine.reg_write(UC_M68K_REG_PC, BASE+0x45A)
        elif not executable_span(pc, size):
            raise RuntimeError(f'execution escaped loader entry model at {pc:#x}+{size}')

    def read_hook(self, machine, access, address, size, value, _):
        from unicorn.m68k_const import UC_M68K_REG_PC
        if address >= 0xFFFFE000:
            raise RuntimeError('MMIO read escaped interception')
        if RX <= address < RX+16 and self.mode == 'frame' and address+size > RX+self.frame_length:
            self.observed['stop'] = 'frame_read_boundary'
            machine.emu_stop()
        if machine.reg_read(UC_M68K_REG_PC) in (BASE+0x420, BASE+0x42A):
            self.observed['native_poll_reads'] += 1

    def write_hook(self, machine, access, address, size, value, _):
        if not writable_span(address, size):
            raise RuntimeError(f'native write escaped loader model at {address:#x}+{size}')

    def execute(self, entry, mode):
        from unicorn.m68k_const import UC_M68K_REG_PC, UC_M68K_REG_A7, UC_M68K_REG_A0, UC_M68K_REG_D7, UC_M68K_REG_SR
        self.mode = mode
        self.observed = dict(stop=None, events_consumed=0, responses=[], modeled_words=[],
            suppressed_setup_stores=0, suppressed_flash_stores=0, synthetic_helper_calls={}, native_poll_reads=0)
        self.closed = True
        self.uc.emu_start(entry, 0, count=500000, timeout=5_000_000)
        if self.observed['stop'] is None:
            raise RuntimeError('loader execution budget exhausted')
        self.closed = self.observed['stop'] != 'receive_boundary'
        return dict(self.observed, stop_pc=hex(self.uc.reg_read(UC_M68K_REG_PC)),
            stack_delta=self.uc.reg_read(UC_M68K_REG_A7)-ENTRY_STACK,
            a0=hex(self.uc.reg_read(UC_M68K_REG_A0)), d7=hex(self.uc.reg_read(UC_M68K_REG_D7)),
            interrupt_mask=(self.uc.reg_read(UC_M68K_REG_SR)>>8)&7,
            receive_budget=self.uc.mem_read(0xFFFF9A72, 1)[0],
            receive_prefix_hex=bytes(self.uc.mem_read(RX, 16)).hex(),
            synthetic_flash_hex=bytes(self.uc.mem_read(0x8000, 4)).hex(),
            pending_events=len(self.events), same_native_session=True,
            physical_loader_execution_verified=False, flash_commands_executed=False,
            transport_used=False, physical_recovery_verified=False,
            automatic_retry_allowed=False, live_write_enabled=False, ready_to_flash=False, would_send=[])

    def start(self):
        if self.started or self.closed:
            raise RuntimeError('loader already started or terminal')
        self.started = True
        return self.execute(BASE, 'entry')

    def restart(self):
        if not self.started or self.closed:
            raise RuntimeError('restart requires a prior receive boundary')
        return self.execute(BASE, 'entry')

    def frame(self, *, subtype=0, corrupt_sum=False, readback='trap', fail_word=None):
        if not self.started or self.closed:
            raise RuntimeError('frame requires initialized receive boundary')
        if (type(subtype) is not int or subtype not in (0, 0xDB, 0xEE, 0xFF) or
                type(corrupt_sum) is not bool or readback not in ('trap', 'synthetic') or
                fail_word is not None and (type(fail_word) is not int or fail_word not in (0, 1))):
            raise ValueError('invalid bounded frame context')
        self.readback, self.fail_word = readback, fail_word
        tail = bytes([subtype])+bytes.fromhex('000400800012345678')
        data = bytes.fromhex('6d18f036')+tail+((sum(tail)+int(corrupt_sum))&65535).to_bytes(2, 'big')
        self.frame_length = len(data)
        self.events = [(1, v) for v in data[:-1]] + [(5, data[-1]), (0, 0)]
        return self.execute(BASE+0x3A, 'frame')


def audit(code):
    cases = []
    for name, steps in (
        ('entry_to_program_command', [('frame', {})]),
        ('modeled_program_success', [('frame', {'readback': 'synthetic'})]),
        ('bad_sum_before_program', [('frame', {'corrupt_sum': True})]),
        ('delay_subtype_without_program', [('frame', {'subtype': 0xDB})]),
        ('erase_dispatch_trapped', [('frame', {'subtype': 0xEE})]),
        ('finalize_dispatch_trapped', [('frame', {'subtype': 0xFF})]),
        ('failure_then_success_keeps_pending_frame', [('frame', {'readback': 'synthetic', 'fail_word': 1}), ('frame', {'readback': 'synthetic'})]),
        ('repeated_failure_then_software_reentry', [('frame', {'readback': 'synthetic', 'fail_word': 0}), ('frame', {'readback': 'synthetic', 'fail_word': 0}), ('restart', {})]),
    ):
        session = LoaderSession(code)
        observed = [session.start()]
        observed.extend(getattr(session, method)(**args) for method, args in steps)
        cases.append(dict(name=name, steps=observed))
    return dict(mode='offline_loader_entry_receive_parser_modeled_word_path', payload_sha256=EXPECTED_SHA,
        generator_sha256=sha256(Path(__file__).read_bytes()),
        dependency_sha256={'emulate_loader_parser.py': sha256(Path(__file__).with_name('emulate_loader_parser.py').read_bytes())},
        source_ranges=[dict(start=hex(a), exclusive_end=hex(b), sha256=sha256(code[a-BASE:b-BASE])) for a, b in RANGES],
        cases=cases, limitations=['Loader entry is selected explicitly; boot-to-loader execution is not joined.',
            'Initial D7=0xA5, receive RAM=0xA5 and incoming stack/budget are synthetic retention probes, not observed hardware startup values.',
            'Receive events, sender and delay/watchdog/cleanup helpers are synthetic. Setup and flash stores never execute.',
            'Only two words at synthetic 0x8000/0x8002 are modeled; no physical programming, erase, FIFO, reset or recovery is established.',
            'Software reentry is selected at a receive boundary, not triggered by an emulated sender timeout.'],
        physical_recovery_verified=False, automatic_retry_allowed=False,
        live_write_enabled=False, ready_to_flash=False, would_send=[])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('loader', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error('output must be a new report path')
    report = audit(args.loader.read_bytes())
    with args.output.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(cases=len(report['cases']), ready_to_flash=False)))


if __name__ == '__main__':
    main()
