"""Native erase/ID/error call stacks with synthetic ID and toggle samples.

Every flash command/reset store is suppressed before execution. Erased bytes,
physical flash mode, sender delivery, hardware reset and recovery are unmodeled.
"""
import argparse
import json
from pathlib import Path

from al5_segment import sha256
from emulate_loader_entry import LoaderSession, ENTRY_STACK, executable_span as entry_span
from emulate_loader_parser import BASE, EXPECTED_SHA

ERASE_RANGES = ((BASE+0x252, BASE+0x25A), (BASE+0x34A, BASE+0x4A8))
POLL_PATTERNS = {
    'stable': (0, 0, 0, 0, 0),
    'persistent_toggle': (0, 0x40, 0x20, 0, 0x40),
    'toggle_then_stable': (0, 0x40, 0x20, 0, 0),
    'busy': (0, 0x40, 0, 0, 0),
}


def executable_span(pc, size):
    return entry_span(pc, size) or size > 0 and any(a <= pc and pc+size <= b for a, b in ERASE_RANGES)


class EraseSession(LoaderSession):
    executable_span = staticmethod(executable_span)

    def __init__(self, code):
        self.erase_active = False
        self.manufacturer, self.device = 1, 0x2258
        self.patterns = ('stable', 'stable')
        self.poll_budget = 3
        self.sector_index = -1
        super().__init__(code)

    def hook(self, machine, pc, size, user):
        from unicorn.m68k_const import UC_M68K_REG_PC, UC_M68K_REG_D0, UC_M68K_REG_D1, UC_M68K_REG_D5, UC_M68K_REG_A0
        if not self.erase_active:
            return super().hook(machine, pc, size, user)
        if pc == BASE+0x252:
            return  # Execute original BSR; only this opt-in model admits erase.
        if pc == BASE+0x46E:
            self.observed['suppressed_id_command_stores'] += 3
            machine.reg_write(UC_M68K_REG_PC, BASE+0x47A)
        elif pc in (BASE+0x47A, BASE+0x486):
            machine.reg_write(UC_M68K_REG_D5, self.manufacturer if pc == BASE+0x47A else self.device)
            machine.reg_write(UC_M68K_REG_PC, pc+4)
            self.observed['synthetic_id_reads'] += 1
        elif pc == BASE+0x48E:
            self.observed['suppressed_id_reset_stores'] += 1
            machine.reg_write(UC_M68K_REG_PC, BASE+0x494)
        elif pc == BASE+0x37A:
            self.sector_index += 1
            if self.sector_index >= 2:
                raise RuntimeError('erase sector-call budget exceeded')
            address = machine.reg_read(UC_M68K_REG_A0)
            if address != (0x8000, 0x10000)[self.sector_index]:
                raise RuntimeError('unexpected native erase target')
            self.observed['sectors'].append(dict(address=hex(address), poll_iterations=0,
                synthetic_pattern=self.patterns[self.sector_index], reset_stores_suppressed=0))
            return super().hook(machine, pc, size, user)
        elif pc == BASE+0x38C:
            self.observed['suppressed_erase_command_stores'] += 6
            machine.reg_write(UC_M68K_REG_PC, BASE+0x3A4)
        elif pc == BASE+0x3A4:
            sector = self.observed['sectors'][self.sector_index]
            if sector['poll_iterations'] >= self.poll_budget:
                self.observed['stop'] = 'synthetic_poll_budget'
                machine.emu_stop()
                return
            sector['poll_iterations'] += 1
            return super().hook(machine, pc, size, user)
        elif pc in (BASE+0x3A8, BASE+0x3AA, BASE+0x3B8, BASE+0x3C0, BASE+0x3C2):
            offsets = (BASE+0x3A8, BASE+0x3AA, BASE+0x3B8, BASE+0x3C0, BASE+0x3C2)
            value = POLL_PATTERNS[self.patterns[self.sector_index]][offsets.index(pc)]
            register = UC_M68K_REG_D1 if pc in (BASE+0x3AA, BASE+0x3C2) else UC_M68K_REG_D0
            machine.reg_write(register, value)
            machine.reg_write(UC_M68K_REG_PC, pc+2)
            self.observed['synthetic_poll_reads'] += 1
        elif pc == BASE+0x3D6:
            self.observed['sectors'][self.sector_index]['reset_stores_suppressed'] += 2
            machine.reg_write(UC_M68K_REG_PC, BASE+0x3DE)
        else:
            return super().hook(machine, pc, size, user)

    def write_hook(self, machine, access, address, size, value, user):
        if self.erase_active and address == 0xFFFF9A70 and size == 2:
            return  # Original device-ID shadow write, never a flash operation.
        return super().write_hook(machine, access, address, size, value, user)

    def new_observation(self):
        return dict(super().new_observation(), sectors=[], suppressed_id_command_stores=0,
            suppressed_id_reset_stores=0, suppressed_erase_command_stores=0,
            synthetic_id_reads=0, synthetic_poll_reads=0)

    def execute(self, entry, mode):
        self.sector_index = -1
        result = super().execute(entry, mode)
        from unicorn.m68k_const import UC_M68K_REG_A7
        sp = self.uc.reg_read(UC_M68K_REG_A7)
        if not ENTRY_STACK-256 <= sp <= ENTRY_STACK or (ENTRY_STACK-sp) % 4:
            raise RuntimeError('unclassified pending stack layout')
        result['pending_stack_words'] = [hex(int.from_bytes(self.uc.mem_read(a, 4), 'big'))
                                          for a in range(sp, ENTRY_STACK, 4)]
        result.update(physical_erase_mode_verified=False, erased_contents_modeled=False,
                      synthetic_poll_budget=self.poll_budget)
        return result

    def erase(self, *, manufacturer=1, device=0x2258, patterns=('stable', 'stable'), poll_budget=3):
        if (any(type(v) is not int or not 0 <= v <= 65535 for v in (manufacturer, device)) or
                type(patterns) is not tuple or len(patterns) != 2 or
                any(type(p) is not str or p not in POLL_PATTERNS for p in patterns) or
                type(poll_budget) is not int or not 1 <= poll_budget <= 8):
            raise ValueError('invalid bounded synthetic erase context')
        self.manufacturer, self.device = manufacturer, device
        self.patterns, self.poll_budget = patterns, poll_budget
        self.erase_active = True
        try:
            return self.frame(subtype=0xEE)
        finally:
            self.erase_active = False

def audit(code):
    trials = (
        ('both_sectors_stable', [('erase', {})]),
        ('manufacturer_mismatch', [('erase', {'manufacturer': 2})]),
        ('device_mismatch', [('erase', {'device': 0xFFFF})]),
        ('first_sector_failure', [('erase', {'patterns': ('persistent_toggle', 'stable')})]),
        ('second_sector_failure', [('erase', {'patterns': ('stable', 'persistent_toggle')})]),
        ('toggle_then_stable_recheck', [('erase', {'patterns': ('toggle_then_stable', 'stable')})]),
        ('busy_poll_model_guard', [('erase', {'patterns': ('busy', 'stable')})]),
        ('mixed_failures_and_success_do_not_unwind', [
            ('erase', {'patterns': ('persistent_toggle', 'stable')}),
            ('frame', {'readback': 'synthetic', 'fail_word': 1}), ('erase', {}),
            ('frame', {'readback': 'synthetic'}), ('restart', {})]),
        ('repeated_erase_then_id_failure', [
            ('erase', {'patterns': ('persistent_toggle', 'stable')}),
            ('erase', {'patterns': ('stable', 'persistent_toggle')}),
            ('erase', {'manufacturer': 2}), ('frame', {'readback': 'synthetic'}), ('restart', {})]),
    )
    cases = []
    for name, steps in trials:
        session = EraseSession(code)
        observations = [session.start()]
        observations.extend(getattr(session, method)(**args) for method, args in steps)
        cases.append(dict(name=name, steps=observations))
    return dict(mode='offline_native_loader_erase_failure_stacks', payload_sha256=EXPECTED_SHA,
        generator_sha256=sha256(Path(__file__).read_bytes()),
        dependency_sha256={name: sha256(Path(__file__).with_name(name).read_bytes()) for name in (
            'emulate_loader_entry.py', 'emulate_loader_parser.py')},
        source_ranges=[dict(start=hex(a), exclusive_end=hex(b), sha256=sha256(code[a-BASE:b-BASE]))
                       for a, b in ERASE_RANGES], cases=cases,
        limitations=['ID words and flash toggle samples are synthetic; every ID/erase/reset command store is suppressed before execution.',
            'No erased-byte, physical flash-mode, timing, sender-delivery, hardware reset or recovery model.',
            'Poll and 256-byte stack guards are model resource bounds, not physical timeout or stack capacity.',
            'Mixed retries are explicitly selected offline inputs, not authorized automatic retry or a physical recovery recipe.'],
        physical_recovery_verified=False, automatic_retry_allowed=False,
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
