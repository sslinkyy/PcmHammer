"""Offline interruption snapshots and explicit retry experiments, never recovery authority.

Fresh emulators select synthetic boot entry; no physical reset/boot is proven.
Fault word values and persistence are chosen model assumptions, not chip behavior.
"""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path

from al5_segment import START, END, LENGTH, sha256
from emulate_al5_program_session import ProgramSession, fixture, MARKER
from emulate_boot_loader_handoff import captured_upload_events, frame_events
from emulate_loader_parser import BASE

FLASH_LENGTH = 0x20000-START
FAULTS = ('after_sector_erase', 'after_word', 'overprogrammed_word', 'before_marker', 'after_marker')


@dataclass(frozen=True)
class ModelSnapshot:
    flash: bytes
    collateral_backup: bytes | None

    def __post_init__(self):
        if type(self.flash) is not bytes or len(self.flash) != FLASH_LENGTH:
            raise ValueError('requires exact conditional flash-model bytes')
        if self.collateral_backup is not None and (
                type(self.collateral_backup) is not bytes or len(self.collateral_backup) != MARKER-END):
            raise ValueError('backup must be absent or exact collateral bytes')


class InterruptionSession(ProgramSession):
    def __init__(self, low, code, *, snapshot=None):
        if snapshot is not None and type(snapshot) is not ModelSnapshot:
            raise ValueError('requires explicit model snapshot')
        self.fault = None
        self.fault_count = 0
        super().__init__(low, code)
        self.imported_snapshot_sha256 = sha256(snapshot.flash) if snapshot is not None else None
        if snapshot is not None:
            self.uc.mem_write(START, snapshot.flash)
            # Do not retain the constructor's fixture baseline after a restart.
            # An absent external backup stays unknown, rather than being rebuilt.
            self.collateral_before = snapshot.collateral_backup

    def new_observation(self):
        return dict(super().new_observation(), interruption=None)

    def arm_interruption(self, kind, *, occurrence=1):
        if type(kind) is not str or kind not in FAULTS or type(occurrence) is not int or not 1 <= occurrence <= 128:
            raise ValueError('invalid bounded interruption context')
        if occurrence > (2 if kind == 'after_sector_erase' else 1 if 'marker' in kind else 128):
            raise ValueError('interruption occurrence exceeds modeled operation')
        if self.closed:
            raise RuntimeError('cannot arm a closed session')
        self.fault, self.fault_count = (kind, occurrence), 0

    def stop_at_fault(self, machine, pc, *, detail=None):
        from unicorn.m68k_const import UC_M68K_REG_A7
        self.observed['interruption'] = dict(kind=self.fault[0], source_pc=hex(pc),
            stack_pointer=hex(machine.reg_read(UC_M68K_REG_A7)), detail=detail,
            physical_interruption_observed=False)
        self.observed['stop'] = 'modeled_interruption'
        machine.emu_stop()

    def hook(self, machine, pc, size, user):
        if self.phase != 'loader' or self.fault is None:
            return super().hook(machine, pc, size, user)
        kind, occurrence = self.fault
        if pc == BASE+0x3D6 and self.erase_active and kind == 'after_sector_erase':
            super().hook(machine, pc, size, user)
            self.fault_count += 1
            if self.fault_count == occurrence:
                self.stop_at_fault(machine, pc)
            return
        if pc == BASE+0x40E:
            if self.finalizing and kind == 'before_marker':
                self.stop_at_fault(machine, pc)
                return
            if self.finalizing and kind == 'after_marker':
                super().hook(machine, pc, size, user)
                self.stop_at_fault(machine, pc)
                return
            if not self.finalizing and kind in ('after_word', 'overprogrammed_word'):
                self.fault_count += 1
                from unicorn.m68k_const import UC_M68K_REG_A1, UC_M68K_REG_D0
                address = machine.reg_read(UC_M68K_REG_A1)
                requested = machine.reg_read(UC_M68K_REG_D0) & 65535
                super().hook(machine, pc, size, user)
                if self.fault_count == occurrence:
                    detail = None
                    if kind == 'overprogrammed_word':
                        if not requested:
                            raise RuntimeError('chosen fault requires a requested one bit')
                        current = int.from_bytes(machine.mem_read(address, 2), 'big')
                        value = current & ~(requested & -requested)
                        machine.mem_write(address, value.to_bytes(2, 'big'))
                        detail = dict(address=hex(address), requested=hex(requested),
                                      chosen_fault_word=hex(value), physical_word_state_known=False)
                    self.stop_at_fault(machine, pc, detail=detail)
                return
        return super().hook(machine, pc, size, user)

    def snapshot(self, *, include_backup=True):
        if type(include_backup) is not bool:
            raise ValueError('backup option must be Boolean')
        return ModelSnapshot(bytes(self.uc.mem_read(START, FLASH_LENGTH)),
                             self.collateral_before if include_backup else None)


def enter_loader(session):
    arm = session.boot_interrupt(frame_events(bytes.fromhex('6d18f034')))
    upload = session.boot_interrupt(captured_upload_events(session.code))
    if arm['boot_responses'] != ['6df0187444'] or upload['phase'] != 'loader':
        raise RuntimeError('native loader entry did not complete')
    return upload['handoff']


def reconstruct(session, image, *, erase=True):
    if erase:
        result = session.erase()
        if result['responses'] != ['7600ee']:
            raise RuntimeError('modeled erase did not complete')
    calibration = session.program_region(START, image, sparse=True)
    if session.collateral_before is not None:
        session.program_region(END, session.collateral_before, sparse=True)
    final = session.finalize()
    return dict(calibration=calibration, finalize_responses=final['responses'],
                final_stack_delta=final['stack_delta'], imported_snapshot_sha256=session.imported_snapshot_sha256,
                verification=session.verify(image))


def restarted(low, code, snapshot):
    session = InterruptionSession(low, code, snapshot=snapshot)
    enter_loader(session)
    return session


def audit(low, code):
    image = fixture()
    payload = image[0x1000:0x1100]
    cases = []
    for keep_backup in (True, False):
        session = InterruptionSession(low, code)
        enter_loader(session)
        session.arm_interruption('after_sector_erase')
        interrupted = session.erase()
        snapshot = session.snapshot(include_backup=keep_backup)
        fresh = restarted(low, code, snapshot)
        result = reconstruct(fresh, image)
        cases.append(dict(name='erase_interruption_with_backup' if keep_backup else 'erase_interruption_backup_missing',
            interruption=interrupted['interruption'], interrupted_stack_delta=interrupted['stack_delta'],
            snapshot_sha256=sha256(snapshot.flash), external_backup_retained=keep_backup,
            fresh_emulator_selected_boot_entry=True, old_ram_not_copied=True, result=result))
    for kind in ('after_word', 'overprogrammed_word'):
        session = InterruptionSession(low, code)
        enter_loader(session)
        session.erase()
        session.arm_interruption(kind, occurrence=4 if kind == 'after_word' else 1)
        interrupted = session.program_block(START+0x1000, payload)
        fresh = restarted(low, code, session.snapshot())
        retried = fresh.program_block(START+0x1000, payload)
        result = reconstruct(fresh, image, erase=kind == 'overprogrammed_word')
        cases.append(dict(name='partial_block_retry' if kind == 'after_word' else 'overprogrammed_word_requires_reerase',
            interruption=interrupted['interruption'], interrupted_stack_delta=interrupted['stack_delta'],
            retry_responses=retried['responses'], retry_stack_delta=retried['stack_delta'],
            fresh_emulator_selected_boot_entry=True, old_ram_not_copied=True, result=result))
    session = InterruptionSession(low, code)
    enter_loader(session)
    session.erase()
    session.timeout_at_byte = 6
    lost = session.program_block(START+0x1000, payload)
    session.timeout_at_byte = None
    retry = session.program_block(START+0x1000, payload)
    conflict = session.program_block(START+0x1000, b'\xFF'*len(payload))
    result = reconstruct(session, image, erase=False)
    cases.append(dict(name='lost_ack_duplicate_and_conflicting_retry',
        lost_ack_sender_returns=lost['native_sender_returns'], sender_timeout_jumps=lost['sender_timeout_jumps'],
        duplicate_responses=retry['responses'], conflicting_responses=conflict['responses'],
        conflicting_stack_delta=conflict['stack_delta'], result=result))
    for kind in ('before_marker', 'after_marker'):
        session = InterruptionSession(low, code)
        enter_loader(session)
        session.erase()
        session.program_region(START, image, sparse=True)
        session.program_region(END, session.collateral_before, sparse=True)
        session.arm_interruption(kind)
        interrupted = session.finalize()
        before = session.verify(image)
        fresh = restarted(low, code, session.snapshot())
        final = fresh.finalize()
        cases.append(dict(name='interruption_'+kind, interruption=interrupted['interruption'],
            final_status_before_interruption=interrupted['responses'], verification_before_restart=before,
            fresh_emulator_selected_boot_entry=True, old_ram_not_copied=True,
            final_responses=final['responses'], verification_after_restart=fresh.verify(image)))
    return dict(mode='offline_integrated_interruption_and_retry_matrix', low_sha256=sha256(low), loader_sha256=sha256(code),
        generator_sha256=sha256(Path(__file__).read_bytes()),
        dependency_sha256={name: sha256(Path(__file__).with_name(name).read_bytes()) for name in (
            'emulate_al5_program_session.py', 'emulate_boot_loader_handoff.py', 'emulate_loader_error_sender.py',
            'emulate_loader_erase_failures.py', 'emulate_loader_entry.py', 'emulate_loader_parser.py')}, cases=cases,
        limitations=['Interruption points, flash persistence and fault word values are explicit model assumptions, not measured chip power-loss behavior.',
            'Fresh emulator reconstruction explicitly selects synthetic boot entry; physical reset/boot availability and RAM retention are unproven.',
            'Only flash bytes and an optionally retained external collateral baseline cross the model restart; no old CPU/RAM state is copied.',
            'Successful model reconstruction does not authorize retry, reerase, recovery or vehicle writes.'],
        physical_programming_verified=False, physical_readback_verified=False,
        physical_recovery_verified=False, physical_interruption_verified=False, automatic_retry_allowed=False,
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
