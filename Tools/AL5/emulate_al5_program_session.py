"""Same-session offline boot/upload/erase/program/finalize/readback experiment.

Flash is an explicit host-owned conditional sector model. No device APIs,
physical write qualification, reset execution or automatic recovery.
"""
import argparse
import json
from pathlib import Path

from al5_segment import START, END, LENGTH, ANCHORS, sha256, word_sum, validate
from checksum import native_field, checksum_valid
from emulate_boot_loader_handoff import BootLoaderSession, captured_upload_events, frame_events
from emulate_loader_error_sender import executable_span as sender_span
from emulate_loader_parser import BASE, RX

MARKER = 0x1FFFE
BLOCK_BYTES = 256  # Experiment resource bound, not a proven protocol maximum.
MOCK_SECTORS = {0x8000: (0x8000, 0x10000), 0x10000: (0x10000, 0x20000)}


def executable_span(pc, size):
    return sender_span(pc, size) or size > 0 and BASE+0x1D6 <= pc and pc+size <= BASE+0x236


def fixture():
    data = bytearray(b'\xFF'*LENGTH)
    for address, value in ANCHORS.items():
        data[address-START:address-START+len(value)] = value
    data[0x1000:0x1400] = bytes(range(256))*4
    data[-4:] = native_field(data)
    return bytes(data)


class ProgramSession(BootLoaderSession):
    executable_span = staticmethod(executable_span)

    def __init__(self, low, code):
        super().__init__(low, code)
        self.finalizing = False
        self.marker_matches = True
        self.block = None
        self.block_offset = 0
        backing = bytearray(b'\xFF'*(0x20000-START))
        backing[:LENGTH] = b'\x5A'*LENGTH
        backing[END-START+0x20:END-START+0x30] = b'collateral-one!!'
        backing[0x1F000-START:0x1F010-START] = bytes(range(16))
        self.uc.mem_write(START, bytes(backing))
        self.collateral_before = bytes(self.uc.mem_read(END, MARKER-END))
        # Explicit synthetic pointer table; not a recovered physical table.
        self.uc.mem_write(0x20046, START.to_bytes(4, 'big')+(END-1).to_bytes(4, 'big'))

    def new_observation(self):
        return dict(super().new_observation(), modeled_erase_ranges=[], modeled_program_words=0,
                    modeled_marker_writes=0)

    def hook(self, machine, pc, size, user):
        if self.phase != 'loader':
            return super().hook(machine, pc, size, user)
        from unicorn.m68k_const import UC_M68K_REG_PC, UC_M68K_REG_A0, UC_M68K_REG_A1, UC_M68K_REG_D0, UC_M68K_REG_D1, UC_M68K_REG_D3
        if pc == BASE+0x1D6 and self.finalizing:
            return  # Execute original finalizer from real receive dispatch.
        if pc == BASE+0x3D6 and self.erase_active:
            target = machine.reg_read(UC_M68K_REG_A0)
            if target not in MOCK_SECTORS:
                raise RuntimeError('unknown conditional erase target')
            a, b = MOCK_SECTORS[target]
            machine.mem_write(a, b'\xFF'*(b-a))
            self.observed['modeled_erase_ranges'].append(dict(start=hex(a), exclusive_end=hex(b)))
            return super().hook(machine, pc, size, user)
        if pc in (BASE+0x66, BASE+0x86):
            dest = machine.reg_read(UC_M68K_REG_A0)
            if not RX <= dest < RX+self.frame_length:
                raise RuntimeError('receive exceeded current bounded frame')
            machine.mem_write(dest, bytes([self.pop()]))
            machine.reg_write(UC_M68K_REG_A0, dest+1)
            machine.reg_write(UC_M68K_REG_PC, pc+4)
            return
        if pc == BASE+0x40E:
            dest = machine.reg_read(UC_M68K_REG_A1)
            word = machine.reg_read(UC_M68K_REG_D0) & 65535
            if self.finalizing:
                context = (dest, word, machine.reg_read(UC_M68K_REG_D1)&255,
                           machine.reg_read(UC_M68K_REG_D3)&65535)
                if context != (MARKER, 0x4AFC, 0xAA, 2) or self.observed['modeled_marker_writes']:
                    raise RuntimeError('unexpected marker context')
                value = word if self.marker_matches else word ^ 1
                machine.mem_write(dest, value.to_bytes(2, 'big'))
                self.observed['modeled_marker_writes'] += 1
            else:
                if self.block is None:
                    raise RuntimeError('word write outside declared block')
                address, payload = self.block
                if (dest != address+self.block_offset or self.block_offset >= len(payload) or
                        word != int.from_bytes(payload[self.block_offset:self.block_offset+2], 'big')):
                    raise RuntimeError('native parser/word context differs from declared block')
                old = int.from_bytes(machine.mem_read(dest, 2), 'big')
                machine.mem_write(dest, (old & word).to_bytes(2, 'big'))
                self.block_offset += 2
                self.observed['modeled_program_words'] += 1
            self.observed['suppressed_flash_stores'] += 4
            machine.reg_write(UC_M68K_REG_PC, BASE+0x41C)
            return
        return super().hook(machine, pc, size, user)

    def write_hook(self, machine, access, address, size, value, user):
        if self.phase == 'loader' and self.finalizing and address == 0xFFFF9A6E and size == 2:
            return
        return super().write_hook(machine, access, address, size, value, user)

    def read_hook(self, machine, access, address, size, value, user):
        if self.phase == 'loader' and RX <= address < RX+BLOCK_BYTES+12:
            if address+size > RX+self.frame_length:
                raise RuntimeError('read beyond current bounded frame')
        return super().read_hook(machine, access, address, size, value, user)

    def exchange(self, data):
        if self.phase != 'loader' or self.closed:
            raise RuntimeError('exchange requires active loader receive boundary')
        if type(data) is not bytes or not 5 <= len(data) <= BLOCK_BYTES+12:
            raise ValueError('invalid bounded model frame')
        self.frame_length = len(data)
        self.events = [(1, v) for v in data[:-1]]+[(5, data[-1]), (0, 0)]
        return self.execute(BASE+0x3A, 'frame')

    def frame(self, *, subtype=0xEE, **options):
        if subtype != 0xEE or options:
            raise ValueError('use program_block or finalize for this model')
        return self.exchange(bytes.fromhex('6d18f036ee'))

    def program_block(self, address, payload):
        if (type(address) is not int or address % 2 or type(payload) is not bytes or
                not 2 <= len(payload) <= BLOCK_BYTES or len(payload) % 2 or
                not START <= address or address+len(payload) > MARKER):
            raise ValueError('requires aligned block within conditional model region, excluding marker')
        self.block, self.block_offset = (address, payload), 0
        tail = b'\x00'+len(payload).to_bytes(2, 'big')+address.to_bytes(3, 'big')+payload
        data = bytes.fromhex('6d18f036')+tail+(sum(tail)&65535).to_bytes(2, 'big')
        try:
            return self.exchange(data)
        finally:
            self.block = None

    def program_region(self, address, data, *, sparse=False):
        if self.phase != 'loader' or self.closed:
            raise RuntimeError('region programming requires active loader receive boundary')
        if (type(address) is not int or address % 2 or type(data) is not bytes or
                len(data) < 2 or len(data) % 2 or type(sparse) is not bool or
                not START <= address or address+len(data) > MARKER):
            raise ValueError('requires even byte region and Boolean sparse option')
        completed = words = skipped = 0
        for offset in range(0, len(data), BLOCK_BYTES):
            payload = data[offset:offset+BLOCK_BYTES]
            if sparse and payload == b'\xFF'*len(payload):
                if bytes(self.uc.mem_read(address+offset, len(payload))) != payload:
                    raise RuntimeError('cannot skip a block that is not modeled erased')
                skipped += 1
                continue
            result = self.program_block(address+offset, payload)
            if result['responses'] != ['760073'] or result['stop'] != 'receive_boundary':
                raise RuntimeError('block did not complete successfully in model')
            if result['modeled_program_words']*2 != len(payload):
                raise RuntimeError('native programmed-byte coverage mismatch')
            completed += 1
            words += result['modeled_program_words']
        return dict(region_start=hex(address), bytes_reconstructed=len(data), blocks_completed=completed,
                    blocks_skipped_erased=skipped, native_program_bytes=words*2, expected_sha256=sha256(data))

    def finalize(self, *, marker_matches=True):
        if type(marker_matches) is not bool:
            raise ValueError('marker option must be Boolean')
        self.finalizing, self.marker_matches = True, marker_matches
        try:
            return self.exchange(bytes.fromhex('6d18f036ff'))
        finally:
            self.finalizing = False

    def verify(self, expected):
        if type(expected) is not bytes or len(expected) != LENGTH:
            raise ValueError('verification requires exact calibration size')
        actual = bytes(self.uc.mem_read(START, LENGTH))
        collateral = bytes(self.uc.mem_read(END, MARKER-END))
        marker = int.from_bytes(self.uc.mem_read(MARKER, 2), 'big')
        facts = dict(expected_sha256=sha256(expected), readback_sha256=sha256(actual),
            exact_calibration_match=actual == expected, native_checksum_valid=checksum_valid(actual),
            calibration_layout_valid=not validate(actual),
            be16_sum_zero=word_sum(actual) == 0, marker=hex(marker), completion_marker_matches=marker == 0x4AFC,
            collateral_before_sha256=sha256(self.collateral_before), collateral_after_sha256=sha256(collateral),
            collateral_matches=collateral == self.collateral_before,
            scope='Host inspection of the same synthetic flash backing; no physical readback exchange.')
        facts['offline_verification_pass'] = all(facts[k] for k in (
            'exact_calibration_match', 'calibration_layout_valid', 'native_checksum_valid', 'be16_sum_zero',
            'completion_marker_matches', 'collateral_matches'))
        return dict(facts, physical_readback_verified=False, physical_recovery_verified=False,
                    live_write_enabled=False, ready_to_flash=False)


def run_case(low, code, candidate, *, restore_collateral=True, sparse=False, marker_matches=True):
    if type(candidate) is not bytes or len(candidate) != LENGTH:
        raise ValueError('requires exact calibration segment')
    session = ProgramSession(low, code)
    arm = session.boot_interrupt(frame_events(bytes.fromhex('6d18f034')))
    upload = session.boot_interrupt(captured_upload_events(code))
    erase = session.erase()
    if erase['responses'] != ['7600ee']:
        raise RuntimeError('modeled erase did not complete')
    programmed = session.program_region(START, candidate, sparse=sparse)
    collateral = session.program_region(END, session.collateral_before, sparse=True) if restore_collateral else None
    final = session.finalize(marker_matches=marker_matches)
    verified = session.verify(candidate)
    return session, dict(boot_arm_response=arm['boot_responses'], handoff=upload['handoff'],
        erase_ranges=erase['modeled_erase_ranges'], calibration=programmed, collateral=collateral,
        finalization=dict(stop=final['stop'], responses=final['responses'], stack_delta=final['stack_delta'],
                          marker_writes=final['modeled_marker_writes']), verification=verified,
        same_native_session=True, synthetic_pointer_table=True, conditional_sector_map=True,
        physical_programming_verified=False, live_write_enabled=False, ready_to_flash=False, would_send=[])


def audit(low, code):
    good = fixture()
    bad_crc = bytearray(good)
    bad_crc[-4] ^= 1
    bad_crc[-2:] = b'\x00\x00'
    bad_crc[-2:] = ((-word_sum(bad_crc))&65535).to_bytes(2, 'big')
    cases = []
    for name, candidate, options in (
        ('complete_dense_calibration', good, {}),
        ('zero_sum_bad_crc_rejected', bytes(bad_crc), {'sparse': True}),
        ('collateral_not_restored_rejected', good, {'sparse': True, 'restore_collateral': False}),
        ('marker_failure_rejected', good, {'sparse': True, 'marker_matches': False}),
    ):
        session, result = run_case(low, code, candidate, **options)
        if name == 'complete_dense_calibration':
            session.uc.mem_write(START+0x1000, bytes([good[0x1000]^1]))
            result['post_finalization_fault_check'] = session.verify(good)
        cases.append(dict(name=name, **result))
    return dict(mode='offline_joined_boot_erase_program_finalize_verify',
        low_sha256=sha256(low), loader_sha256=sha256(code),
        generator_sha256=sha256(Path(__file__).read_bytes()),
        dependency_sha256={name: sha256(Path(__file__).with_name(name).read_bytes()) for name in (
            'emulate_boot_loader_handoff.py', 'emulate_loader_error_sender.py', 'emulate_loader_erase_failures.py',
            'emulate_loader_entry.py', 'emulate_loader_parser.py', 'checksum.py', 'al5_segment.py')},
        cases=cases, limitations=['Conditional 32 KiB/64 KiB sector mapping is a host model, not proven installed-chip erase scope.',
            'ID/FIFO/readiness and erased/programmed bytes are synthetic. Command/MMIO stores remain suppressed; stops before reset.',
            'Collateral snapshot/restore and verification use synthetic memory, not current physical backups or independent wire readback.',
            '256-byte block bound is an experiment limit, not a physical protocol or buffer-size qualification.'],
        physical_programming_verified=False, physical_readback_verified=False, physical_recovery_verified=False,
        automatic_retry_allowed=False, live_write_enabled=False, ready_to_flash=False, would_send=[])


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
