"""Join loader error/status handling to native sender timeout and software entry.

FIFO control/data stores are suppressed and readiness is synthetic. Native
sender execution establishes neither physical transmission nor flash recovery.
"""
import argparse
import json
from pathlib import Path

from al5_segment import sha256
from emulate_loader_erase_failures import EraseSession, executable_span as erase_span
from emulate_loader_entry import ENTRY_STACK
from emulate_loader_parser import BASE, EXPECTED_SHA

SENDER_RANGE = (BASE+0x52E, BASE+0x5FC)


def executable_span(pc, size):
    return erase_span(pc, size) or size > 0 and SENDER_RANGE[0] <= pc and pc+size <= SENDER_RANGE[1]


class ErrorSenderSession(EraseSession):
    executable_span = staticmethod(executable_span)

    def __init__(self, code, *, timeout_at_byte=None):
        if timeout_at_byte is not None and (type(timeout_at_byte) is not int or not 1 <= timeout_at_byte <= 6):
            raise ValueError('timeout byte must be None or 1..6')
        self.timeout_at_byte = timeout_at_byte
        super().__init__(code)

    def new_observation(self):
        return dict(super().new_observation(), staged_fifo_bytes=[], synthetic_control_values=[],
            native_sender_returns=0, synthetic_ready_reads=0, sender_timeout_jumps=[])

    def hook(self, machine, pc, size, user):
        from unicorn.m68k_const import UC_M68K_REG_PC, UC_M68K_REG_D0, UC_M68K_REG_D1, UC_M68K_REG_A7
        if pc == BASE+0x52E:
            if machine.reg_read(UC_M68K_REG_D1) & 255 != 3:
                raise RuntimeError('unexpected sender body length')
            self.observed['responses'].append(bytes(machine.mem_read(0xFFFF9A80, 3)).hex())
        if pc in (BASE+0x52E, BASE+0x5BE, BASE+0x5B2):
            self.observed['synthetic_control_values'].append(20 if pc == BASE+0x52E else 4 if pc == BASE+0x5BE else 12)
            machine.reg_write(UC_M68K_REG_PC, pc+6)
        elif pc == BASE+0x5C4:
            if len(self.observed['staged_fifo_bytes']) >= 6:
                raise RuntimeError('bounded sender byte count exceeded')
            self.observed['staged_fifo_bytes'].append(machine.reg_read(UC_M68K_REG_D0) & 255)
            machine.reg_write(UC_M68K_REG_PC, pc+4)
        elif pc == BASE+0x5D8:
            self.observed['synthetic_ready_reads'] += 1
            busy = len(self.observed['staged_fifo_bytes']) == self.timeout_at_byte
            machine.reg_write(UC_M68K_REG_D0, 3 if busy else 0)
            machine.reg_write(UC_M68K_REG_PC, pc+4)
        elif pc == BASE+0x5E8:
            sp = machine.reg_read(UC_M68K_REG_A7)
            self.observed['sender_timeout_jumps'].append(dict(stack_delta=sp-ENTRY_STACK,
                pending_words=[hex(int.from_bytes(machine.mem_read(a, 4), 'big')) for a in range(sp, ENTRY_STACK, 4)]))
            # Execute the original JMP to loader entry, then its real stack/
            # budget initialization. No selected restart call is substituted.
        elif pc == BASE+0x54E:
            self.observed['native_sender_returns'] += 1
        elif SENDER_RANGE[0] <= pc < SENDER_RANGE[1] and pc != BASE+0x550:
            if not executable_span(pc, size):
                raise RuntimeError('sender instruction span escaped')
        else:
            return super().hook(machine, pc, size, user)


def audit(code):
    cases = []
    for name, timeout, method, args in (
        ('program_error_sender_ready', None, 'frame', {'readback': 'synthetic', 'fail_word': 0}),
        ('erase_error_sender_ready', None, 'erase', {'patterns': ('persistent_toggle', 'stable')}),
        ('program_error_first_byte_timeout', 1, 'frame', {'readback': 'synthetic', 'fail_word': 0}),
        ('erase_error_first_byte_timeout', 1, 'erase', {'patterns': ('persistent_toggle', 'stable')}),
        ('erase_error_last_byte_timeout', 6, 'erase', {'patterns': ('persistent_toggle', 'stable')}),
        ('program_success_last_byte_timeout', 6, 'frame', {'readback': 'synthetic'}),
    ):
        session = ErrorSenderSession(code, timeout_at_byte=timeout)
        cases.append(dict(name=name, timeout_at_byte=timeout,
                          steps=[session.start(), getattr(session, method)(**args)]))
    return dict(mode='offline_error_to_native_sender_timeout_to_software_entry', payload_sha256=EXPECTED_SHA,
        generator_sha256=sha256(Path(__file__).read_bytes()),
        dependency_sha256={name: sha256(Path(__file__).with_name(name).read_bytes()) for name in (
            'emulate_loader_erase_failures.py', 'emulate_loader_entry.py', 'emulate_loader_parser.py')},
        source_range=dict(start=hex(SENDER_RANGE[0]), exclusive_end=hex(SENDER_RANGE[1]),
                          sha256=sha256(code[SENDER_RANGE[0]-BASE:SENDER_RANGE[1]-BASE])),
        cases=cases, limitations=['Sender readiness and FIFO stores are synthetic; staged bytes and logical status bodies do not establish transmission or reception.',
            'Actual sender polling counter/JMP and software entry run; hardware reset, FIFO timing, flash mode and recovery remain unverified.',
            'Broadcast cleanup, delays and watchdog are guarded synthetic helpers; all flash/MMIO command stores remain suppressed.'],
        physical_transport_verified=False, physical_recovery_verified=False, automatic_retry_allowed=False,
        live_write_enabled=False, ready_to_flash=False, would_send=[])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('loader', 'output'):
        parser.add_argument('--'+name, required=True, type=Path)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error('output must be a new report path')
    result = audit(args.loader.read_bytes())
    with args.output.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(cases=len(result['cases']), ready_to_flash=False)))


if __name__ == '__main__':
    main()
