"""Offline native boot upload -> pinned loader entry -> modeled programming.

One CPU and RAM session; all physical FIFO, sender, flash and MMIO effects stay
synthetic or suppressed. Only the pinned private loader may enter uploaded RAM.
"""
import argparse
import json
from pathlib import Path

from al5_segment import sha256
from emulate_boot_receive_session import executable_span as boot_span, frame_events, WATCHDOG_STORES
from emulate_boot_receive_isr import START, RTE, STACK as BOOT_STACK
from emulate_boot_session import EXPECTED_LOW
from emulate_loader_error_sender import ErrorSenderSession
from emulate_loader_parser import BASE, EXPECTED_SHA


def captured_upload_events(code, *, execute=True, corrupt_checksum=False):
    if sha256(code) != EXPECTED_SHA or type(execute) is not bool or type(corrupt_checksum) is not bool:
        raise ValueError('requires pinned loader and Boolean synthetic options')
    tail = bytes([0x80 if execute else 0])+len(code).to_bytes(2, 'big')+BASE.to_bytes(3, 'big')+code
    checksum = (sum(tail)+int(corrupt_checksum)) & 65535
    data = bytes.fromhex('6d18f036')+tail+checksum.to_bytes(2, 'big')
    return tuple((0x20, v) for v in data)+((0xA0, 0), (0, 0))


class BootLoaderSession(ErrorSenderSession):
    def __init__(self, low, code):
        if len(low) != 0x20000 or sha256(low) != EXPECTED_LOW:
            raise ValueError('unexpected pinned LOW source')
        super().__init__(code)
        from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
        from unicorn.m68k_const import UC_M68K_REG_SR, UC_M68K_REG_A7
        self.low = low
        self.phase = 'boot'
        self.boot_queue = []
        self.uploaded_offsets = set()
        self.handoff = None
        self.uc.mem_write(0, low[:0x5000])
        self.uc.mem_protect(0, 0x5000, UC_PROT_READ | UC_PROT_EXEC)
        self.uc.mem_map(0x200000, 0x10000)
        # Remove the parent's preloaded code. Only actual native boot transfer
        # instructions will populate uploaded RAM before its first instruction.
        self.uc.mem_protect(BASE, 0x1000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        self.uc.mem_write(BASE, bytes(len(code)))
        self.uc.mem_write(0xFF8010, b'\x01')
        self.uc.reg_write(UC_M68K_REG_SR, 0x2700)
        self.uc.reg_write(UC_M68K_REG_A7, BOOT_STACK)

    def new_observation(self):
        return dict(super().new_observation(), boot_responses=[], boot_fifo_reads=0,
                    boot_flush_calls=0, suppressed_boot_watchdog_stores=0)

    def boot_callback_return(self, target):
        from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_PC
        sp = self.uc.reg_read(UC_M68K_REG_A7)
        if not BOOT_STACK-512 <= sp <= BOOT_STACK-4:
            raise RuntimeError('boot callback stack escaped ownership')
        ret = int.from_bytes(self.uc.mem_read(sp, 4), 'big')
        bsr = self.low[ret-4:ret-2] == b'\x61\x00' and (
            ret-2+int.from_bytes(self.low[ret-2:ret], 'big', signed=True) == target)
        jsr = self.low[ret-6:ret-4] == b'\x4e\xb9' and (
            int.from_bytes(self.low[ret-4:ret], 'big') == target)
        if not boot_span(ret, 2) or not (bsr or jsr):
            raise RuntimeError('unexpected boot callback caller')
        self.uc.reg_write(UC_M68K_REG_A7, sp+4)
        self.uc.reg_write(UC_M68K_REG_PC, ret)

    def hook(self, machine, pc, size, user):
        if self.phase == 'loader':
            return super().hook(machine, pc, size, user)
        from unicorn.m68k_const import UC_M68K_REG_PC, UC_M68K_REG_A7, UC_M68K_REG_D0, UC_M68K_REG_D7
        if pc == BASE:
            actual = bytes(machine.mem_read(BASE, len(self.code)))
            sp = machine.reg_read(UC_M68K_REG_A7)
            if (sha256(actual) != EXPECTED_SHA or len(self.uploaded_offsets) != len(self.code) or
                    sp != BOOT_STACK-72 or int.from_bytes(machine.mem_read(sp, 4), 'big') != 0x33B8):
                raise RuntimeError('uploaded loader or native handoff context mismatch')
            if self.boot_queue not in ([], [(0, 0)]):
                raise RuntimeError('non-idle boot data remains at handoff')
            self.handoff = dict(uploaded_sha256=sha256(actual), native_uploaded_bytes=len(self.uploaded_offsets),
                boot_stack_delta=sp-BOOT_STACK, pending_boot_return='0x33b8',
                d7_at_loader_entry=hex(machine.reg_read(UC_M68K_REG_D7)),
                native_jsr_reached=True, loader_bytes_preloaded=False)
            from unicorn import UC_PROT_READ, UC_PROT_EXEC
            machine.mem_protect(BASE, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
            self.phase = 'loader'
            self.started = True
            return super().hook(machine, pc, size, user)
        if pc == RTE:
            self.observed['stop'] = 'before_boot_rte'
            machine.emu_stop()
        elif pc in WATCHDOG_STORES:
            self.observed['suppressed_boot_watchdog_stores'] += 1
            machine.reg_write(UC_M68K_REG_PC, WATCHDOG_STORES[pc])
        elif pc == 0x2E8C:
            if not self.boot_queue:
                raise RuntimeError('synthetic boot FIFO exhausted')
            status, value = self.boot_queue.pop(0)
            self.observed['boot_fifo_reads'] += 1
            machine.reg_write(UC_M68K_REG_D0, (status<<8)|value)
            self.boot_callback_return(pc)
        elif pc == 0x2ED0:
            count = int.from_bytes(machine.mem_read(0xFF8180, 2), 'big')
            if not 0 < count <= 11:
                raise RuntimeError('boot response length escaped ownership')
            self.observed['boot_responses'].append(bytes(machine.mem_read(0xFF8175, count)).hex())
            self.boot_callback_return(pc)
        elif pc == 0x2D98:
            self.observed['boot_flush_calls'] += 1
            self.boot_callback_return(pc)
        elif not boot_span(pc, size):
            raise RuntimeError(f'boot execution escaped at {pc:#x}+{size}')

    def write_hook(self, machine, access, address, size, value, user):
        if self.phase == 'loader':
            return super().write_hook(machine, access, address, size, value, user)
        if BOOT_STACK-512 <= address and address+size <= BOOT_STACK:
            return
        if 0xFF8160 <= address and address+size <= 0xFF818A:
            return
        if BASE <= address and address+size <= BASE+len(self.code) and size == 1:
            self.uploaded_offsets.add(address-BASE)
            return
        raise RuntimeError(f'boot native write escaped ownership at {address:#x}+{size}')

    def read_hook(self, machine, access, address, size, value, user):
        if self.phase == 'boot' and address < 0x1000000 and address+size > 0xFFE000:
            raise RuntimeError('boot MMIO read escaped synthetic callbacks')
        return super().read_hook(machine, access, address, size, value, user)

    def boot_interrupt(self, events):
        if self.phase != 'boot' or self.closed:
            raise RuntimeError('boot entry unavailable after loader handoff or failure')
        if (type(events) is not tuple or len(events) > len(self.code)+14 or any(
                type(e) is not tuple or len(e) != 2 or any(
                    type(v) is not int or not 0 <= v <= 255 for v in e) for e in events)):
            raise ValueError('invalid bounded synthetic boot events')
        from unicorn.m68k_const import UC_M68K_REG_PC, UC_M68K_REG_A7, UC_M68K_REG_D7
        if self.uc.reg_read(UC_M68K_REG_A7) != BOOT_STACK:
            raise RuntimeError('boot interrupt stack not restored')
        self.mode = 'handoff'
        self.uploaded_offsets = set()
        self.boot_queue = list(events)
        self.observed = self.new_observation()
        self.closed = True
        self.uc.emu_start(START, 0, count=300000, timeout=5_000_000)
        stop = self.observed['stop']
        sp = self.uc.reg_read(UC_M68K_REG_A7)
        if stop == 'before_boot_rte':
            if sp != BOOT_STACK:
                raise RuntimeError('boot ISR stack did not restore')
        elif stop != 'receive_boundary' or self.phase != 'loader':
            raise RuntimeError('handoff execution exhausted or missed boundary')
        self.closed = False
        result = dict(self.observed, phase=self.phase, stop_pc=hex(self.uc.reg_read(UC_M68K_REG_PC)),
            stack_pointer=hex(sp), d7=hex(self.uc.reg_read(UC_M68K_REG_D7)),
            receive_budget=self.uc.mem_read(0xFFFF9A72, 1)[0],
            uploaded_bytes_observed=len(self.uploaded_offsets),
            upload_armed=self.uc.mem_read(0xFF8185, 1)[0],
            handoff=self.handoff, boot_fifo_events_remaining=len(self.boot_queue),
            same_native_session=True, actual_interrupt_delivered=False,
            exception_return_executed=False, physical_loader_execution_verified=False,
            transport_used=False, physical_recovery_verified=False,
            automatic_retry_allowed=False, live_write_enabled=False, ready_to_flash=False, would_send=[])
        return result

    def frame(self, **args):
        if self.phase != 'loader':
            raise RuntimeError('loader frame requires actual native handoff')
        return super().frame(**args)


def audit(low, code):
    arm = frame_events(bytes.fromhex('6d18f034'))
    cases = []
    for name in ('armed_upload_then_program', 'checksum_failure_then_upload_retry',
                 'unarmed_upload_rejected', 'upload_without_execution'):
        session = BootLoaderSession(low, code)
        steps = []
        if name != 'unarmed_upload_rejected':
            steps.append(session.boot_interrupt(arm))
        if name == 'checksum_failure_then_upload_retry':
            steps.append(session.boot_interrupt(captured_upload_events(code, corrupt_checksum=True)))
        steps.append(session.boot_interrupt(captured_upload_events(code, execute=name != 'upload_without_execution')))
        if session.phase == 'loader':
            steps.append(session.frame(readback='synthetic', fail_word=0 if name == 'checksum_failure_then_upload_retry' else None))
        cases.append(dict(name=name, steps=steps))
    return dict(mode='offline_native_boot_upload_loader_entry_program_continuity',
        low_sha256=EXPECTED_LOW, loader_sha256=EXPECTED_SHA,
        generator_sha256=sha256(Path(__file__).read_bytes()),
        dependency_sha256={name: sha256(Path(__file__).with_name(name).read_bytes()) for name in (
            'emulate_boot_receive_session.py', 'emulate_boot_receive_isr.py', 'emulate_boot_session.py',
            'emulate_loader_error_sender.py', 'emulate_loader_erase_failures.py',
            'emulate_loader_entry.py', 'emulate_loader_parser.py')}, cases=cases,
        limitations=['Boot interrupt entry/flag are synthetic; actual peripheral startup, IRQ and RTE are omitted.',
            'Pinned private loader bytes are copied by original boot instructions in one CPU/RAM session; no physical upload or FIFO timing is established.',
            'All flash/MMIO effects remain synthetic or suppressed. Programming models only two test words; readback/recovery remain unqualified.'],
        physical_recovery_verified=False, automatic_retry_allowed=False,
        live_write_enabled=False, ready_to_flash=False, would_send=[])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('low', 'loader', 'output'):
        parser.add_argument('--'+name, required=True, type=Path)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error('output must be a new report path')
    result = audit(args.low.read_bytes(), args.loader.read_bytes())
    with args.output.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(cases=len(result['cases']), ready_to_flash=False)))


if __name__ == '__main__':
    main()
