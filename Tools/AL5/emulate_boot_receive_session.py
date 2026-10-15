"""Join native boot ISR, dispatch and synthetic RAM transfer in one session.

Explicit interrupt entries and synthetic FIFO/send callbacks replace hardware.
RTE and every uploaded-code entry are trapped before execution. No transport.
"""
import argparse
import json
from pathlib import Path

from al5_segment import sha256
from emulate_boot_receive_isr import permitted_pc as isr_pc, START, RTE, STACK
from emulate_boot_session import EXPECTED_LOW, DISPATCH, TRANSFER, NEGATIVE

WATCHDOG_STORES = {0x33A6: 0x33AE, 0x33AE: 0x33B6, 0x33F6: 0x33FE, 0x33FE: 0x3406}


def executable_span(pc, size):
    return size > 0 and (isr_pc(pc, size) or any(
        a <= pc and pc + size <= b for a, b in (DISPATCH, TRANSFER, NEGATIVE)))


def writable_span(address, size):
    return size > 0 and any(a <= address and address + size <= b for a, b in (
        (STACK - 512, STACK), (0xFF8160, 0xFF818A), (0xFF9000, 0xFF9040)))


class ReceiveSession:
    def __init__(self, low, *, enabled=True):
        if len(low) != 0x20000 or sha256(low) != EXPECTED_LOW:
            raise ValueError('unexpected pinned LOW source')
        if type(enabled) is not bool:
            raise ValueError('enabled must be Boolean')
        import unicorn
        if unicorn.__version__ != '2.1.4':
            raise ValueError('requires Unicorn 2.1.4')
        from unicorn.m68k_const import UC_CPU_M68K_M68020, UC_M68K_REG_SR, UC_M68K_REG_A7
        self.low = low
        self.uc = unicorn.Uc(unicorn.UC_ARCH_M68K, unicorn.UC_MODE_BIG_ENDIAN)
        self.uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
        self.uc.mem_map(0, 0x5000)
        self.uc.mem_write(0, low[:0x5000])
        self.uc.mem_protect(0, 0x5000, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
        self.uc.mem_map(0xFF8000, 0x8000)
        self.uc.mem_map(0x200000, 0x10000)
        self.uc.mem_write(0xFF8010, bytes([int(enabled)]))
        self.uc.reg_write(UC_M68K_REG_SR, 0x2700)
        self.uc.reg_write(UC_M68K_REG_A7, STACK)
        self.closed = False
        self.queue = []
        self.observed = {}
        self.uc.hook_add(unicorn.UC_HOOK_CODE, self.hook)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, self.write_hook)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_READ, self.read_hook)

    def callback_return(self, target):
        from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_PC
        sp = self.uc.reg_read(UC_M68K_REG_A7)
        if not STACK - 512 <= sp <= STACK - 4:
            raise RuntimeError('callback stack escaped ownership')
        ret = int.from_bytes(self.uc.mem_read(sp, 4), 'big')
        # Validate the original caller instruction rather than accepting any
        # address within an executable range as a synthetic helper return.
        bsr = (self.low[ret-4:ret-2] == b'\x61\x00' and
               ret - 2 + int.from_bytes(self.low[ret-2:ret], 'big', signed=True) == target)
        jsr = (self.low[ret-6:ret-4] == b'\x4e\xb9' and
               int.from_bytes(self.low[ret-4:ret], 'big') == target)
        if not executable_span(ret, 2) or not (bsr or jsr):
            raise RuntimeError('unexpected callback caller')
        self.uc.reg_write(UC_M68K_REG_A7, sp + 4)
        self.uc.reg_write(UC_M68K_REG_PC, ret)

    def hook(self, machine, pc, size, _):
        from unicorn.m68k_const import UC_M68K_REG_D0, UC_M68K_REG_PC
        if pc == RTE or 0xFF9000 <= pc < 0xFF9040:
            self.observed['stop'] = 'before_rte' if pc == RTE else 'before_uploaded_execution'
            machine.emu_stop()
            return
        if pc in WATCHDOG_STORES:
            self.observed['suppressed_watchdog_stores'] += 1
            machine.reg_write(UC_M68K_REG_PC, WATCHDOG_STORES[pc])
            return
        if pc == 0x2E8C:
            if not self.queue:
                raise RuntimeError('synthetic FIFO exhausted')
            status, value = self.queue.pop(0)
            self.observed['fifo_events_consumed'] += 1
            machine.reg_write(UC_M68K_REG_D0, (status << 8) | value)
            self.callback_return(pc)
            return
        if pc == 0x2ED0:
            count = int.from_bytes(machine.mem_read(0xFF8180, 2), 'big')
            if not 0 < count <= 11:
                raise RuntimeError('response length escaped bounded buffer')
            self.observed['responses'].append(bytes(machine.mem_read(0xFF8175, count)).hex())
            self.callback_return(pc)
            return
        if pc == 0x2D98:
            self.observed['flush_calls'] += 1
            self.callback_return(pc)
            return
        if not executable_span(pc, size):
            raise RuntimeError(f'execution escaped receive session at {pc:#x}+{size}')
        if pc in (DISPATCH[0], TRANSFER[0]):
            self.observed['handler_entries'].append(hex(pc))
        self.observed['native_instructions'] += 1

    def write_hook(self, machine, access, address, size, value, _):
        if not writable_span(address, size):
            raise RuntimeError(f'write escaped receive session at {address:#x}+{size}')

    def read_hook(self, machine, access, address, size, value, _):
        if address < 0x1000000 and address + size > 0xFFE000:
            raise RuntimeError('MMIO read escaped synthetic callbacks')

    def interrupt(self, events):
        if self.closed:
            raise RuntimeError('session stopped at uploaded code or failed boundary')
        if (type(events) is not tuple or len(events) > 96 or any(
                type(e) is not tuple or len(e) != 2 or any(
                    type(v) is not int or not 0 <= v <= 255 for v in e) for e in events)):
            raise ValueError('invalid bounded synthetic FIFO events')
        from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_PC
        if self.uc.reg_read(UC_M68K_REG_A7) != STACK:
            raise RuntimeError('interrupt entry stack not restored')
        # RTE is never executed. Entry is supplied explicitly, without an
        # exception frame; all synthetic RAM and native saved registers persist.
        self.queue = list(events)
        self.observed = dict(responses=[], fifo_events_consumed=0, flush_calls=0,
                             handler_entries=[], native_instructions=0, stop=None,
                             suppressed_watchdog_stores=0)
        self.closed = True  # Any failed run is terminal; no implicit retry.
        self.uc.emu_start(START, 0, count=20000, timeout=2_000_000)
        if self.observed['stop'] is None:
            raise RuntimeError('receive session exceeded execution budget')
        sp = self.uc.reg_read(UC_M68K_REG_A7)
        if self.observed['stop'] == 'before_rte':
            if sp != STACK:
                raise RuntimeError('native ISR did not restore stack')
            self.closed = False
        result = dict(self.observed)
        result.update(stop_pc=hex(self.uc.reg_read(UC_M68K_REG_PC)), stack_delta=sp-STACK,
            fifo_events_remaining=len(self.queue), upload_armed=self.uc.mem_read(0xFF8185, 1)[0],
            processing_flag=self.uc.mem_read(0xFF8182, 1)[0],
            staged_length=int.from_bytes(self.uc.mem_read(0xFF8170, 2), 'big'),
            staged_buffer_hex=bytes(self.uc.mem_read(0xFF8164, 14)).hex(),
            synthetic_ram_hex=bytes(self.uc.mem_read(0xFF9000, 64)).hex(),
            same_native_session=True, actual_interrupt_delivered=False,
            exception_return_executed=False, uploaded_code_executed=False,
            transport_used=False, physical_recovery_verified=False,
            live_write_enabled=False, ready_to_flash=False, would_send=[])
        return result


def frame_events(frame, *, completion_status=0xA0):
    """Synthetic FIFO representation, not a physical packet encoder."""
    if type(frame) is not bytes or not 4 <= len(frame) <= 11:
        raise ValueError('frame must contain 4..11 synthetic bytes')
    if type(completion_status) is not int or not 0 <= completion_status <= 255:
        raise ValueError('completion status must be a byte')
    return tuple((0x20, v) for v in frame) + ((completion_status, 0), (0, 0))


def transfer_events(*, payload=b'\x12\x34\x56\x78', subtype=0, corrupt_checksum=False):
    """Four-byte RAM experiment only; never accepts a controller image/loader."""
    if type(payload) is not bytes or len(payload) != 4:
        raise ValueError('only four-byte synthetic payloads are modeled')
    if type(subtype) is not int or subtype not in (0, 0x80) or type(corrupt_checksum) is not bool:
        raise ValueError('invalid synthetic transfer context')
    tail = bytes([subtype]) + b'\x00\x04\xff\x90\x00' + payload
    checksum = (sum(tail) + int(corrupt_checksum)) & 0xFFFF
    data = bytes.fromhex('6d18f036') + tail + checksum.to_bytes(2, 'big')
    return tuple((0x20, v) for v in data) + ((0xA0, 0), (0, 0))


def audit(low):
    arm = frame_events(bytes.fromhex('6d18f034'))
    trials = [
        ('arm_then_transfer', (arm, transfer_events())),
        ('unarmed_transfer', (transfer_events(),)),
        ('checksum_failure_then_retry', (arm, transfer_events(payload=b'bad!', corrupt_checksum=True), transfer_events())),
        ('duplicate_transfer', (arm, transfer_events(), transfer_events())),
        ('bad_arm_length_preserves_arm', (arm, frame_events(bytes.fromhex('6d18f03400')))),
        ('wrong_destination', (frame_events(bytes.fromhex('6d19f034')),)),
        ('uploaded_entry_trapped', (arm, transfer_events(subtype=0x80))),
        ('split_arm_across_interrupt_entries', (arm[:2] + ((0, 0),), arm[2:])),
    ]
    cases = []
    for name, steps in trials:
        session = ReceiveSession(low)
        cases.append(dict(name=name, steps=[session.interrupt(events) for events in steps]))
    return dict(mode='offline_continuous_boot_isr_dispatch_ram_transfer', source_sha256=EXPECTED_LOW,
        generator_sha256=sha256(Path(__file__).read_bytes()),
        dependency_sha256={name: sha256(Path(__file__).with_name(name).read_bytes()) for name in (
            'emulate_boot_receive_isr.py', 'emulate_boot_session.py')},
        source_ranges=[dict(start=hex(a), exclusive_end=hex(b), sha256=sha256(low[a:b])) for a, b in (
            (START, RTE+2), DISPATCH, TRANSFER, NEGATIVE)], cases=cases,
        limitations=['Interrupt entry is explicit; RTE and uploaded code are trapped before execution.',
            'FIFO, sender and flush callbacks are synthetic; watchdog stores are suppressed before execution. No hardware initialization or timing is modeled.',
            'Four-byte synthetic RAM writes establish neither loader execution nor flash programming/recovery.'],
        physical_recovery_verified=False, automatic_retry_allowed=False,
        live_write_enabled=False, ready_to_flash=False, would_send=[])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('low', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error('output must be a new report path')
    result = audit(args.low.read_bytes())
    with args.output.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(cases=len(result['cases']), ready_to_flash=False)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
