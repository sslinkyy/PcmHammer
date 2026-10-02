"""Inspect synthetic/captured block bytes and model RAM edits; no packet builder or I/O."""
from al5_segment import START, END, validate, sha256
from checksum import checksum_valid


def inspect_block(frame):
    errors = []
    address = count = None
    if len(frame) < 14:
        errors.append('complete header and at least one payload word required')
    if len(frame) >= 10:
        if frame[0] not in (0x6C, 0x6D) or frame[1] != 0x18 or frame[2] not in (0xF0, 0xF1):
            errors.append('unsupported header; global destination is excluded')
        if frame[3:5] != b'\x36\x00':
            errors.append('only offline inspection of word-program blocks is supported')
        count = int.from_bytes(frame[5:7], 'big')
        address = int.from_bytes(frame[7:10], 'big')
        if not count or count % 2:
            errors.append('payload length must be nonzero and even')
        if len(frame) != count + 12:
            errors.append('frame length does not match declared payload length')
        if address % 2:
            errors.append('destination must be word aligned')
        if not START <= address < END or address + count > END:
            errors.append('entire block must fit the calibration range')
        if len(frame) >= 12 and sum(frame[4:-2]) & 65535 != int.from_bytes(frame[-2:], 'big'):
            errors.append('block byte sum mismatch')
    return {'frame_sha256': sha256(frame), 'input_errors': sorted(set(errors)),
            'address': hex(address) if address is not None else None,
            'declared_length': count, 'offline_input_valid': not errors,
            'physical_frame_verified': False, 'ready_to_flash': False,
            'live_write_enabled': False, 'erase_scope': None, 'would_send': []}


def simulate_batch(frames, baseline, *, fault_index=None, fault_kind=None):
    """Preflight all blocks before any synthetic edit; failures never imply safe retry."""
    if fault_kind not in (None, 'timeout', 'negative_response', 'interrupted_word'):
        raise ValueError('unknown synthetic fault')
    if (fault_index is None) != (fault_kind is None):
        raise ValueError('fault index and kind must be supplied together')
    if fault_index is not None and not 0 <= fault_index < len(frames):
        raise ValueError('fault index outside supplied batch')
    errors = [f'baseline: {e}' for e in validate(baseline)]
    if not checksum_valid(baseline):
        errors.append('baseline native checksum invalid')
    if not frames:
        errors.append('empty batch')
    reports = [inspect_block(frame) for frame in frames]
    occupied = set()
    for index, report in enumerate(reports):
        errors.extend(f'block {index}: {e}' for e in report['input_errors'])
        if report['offline_input_valid']:
            address = int(report['address'], 16)
            touched = set(range(address, address + report['declared_length']))
            if occupied & touched:
                errors.append(f'block {index}: duplicate or overlapping range; retry semantics unverified')
            occupied.update(touched)
    memory = bytearray(baseline)
    writes = 0
    stop = 'preflight_rejected' if errors else 'synthetic_complete'
    if not errors:
        for index, (frame, report) in enumerate(zip(frames, reports)):
            offset = int(report['address'], 16) - START
            payload = frame[10:-2]
            fault = fault_kind if index == fault_index else None
            # Model ambiguous failures after possible writes, never a no-change guarantee.
            applied = payload[:2] if fault == 'interrupted_word' else payload
            memory[offset:offset + len(applied)] = applied
            writes += len(applied)
            if fault:
                stop = f'synthetic_{fault}'; break
    return {'mode': 'offline_logical_memory_model', 'input_errors': sorted(set(errors)),
            'blocks': reports, 'modeled_bytes_written': writes, 'stop': stop,
            'baseline_sha256': sha256(baseline), 'modeled_result_sha256': sha256(memory),
            'modeled_result_native_checksum_valid': checksum_valid(memory),
            'automatic_retry_allowed': False, 'physical_write_outcome_verified': False,
            'physical_acknowledgments_verified': False, 'physical_block_size_verified': False,
            'ready_to_flash': False, 'live_write_enabled': False, 'erase_scope': None,
            'would_send': [], 'erase_packets': [], 'program_packets': [],
            'limits': 'Logical RAM edits only, no erase/NOR/transport model. Synthetic completion is not readiness. Faults permit partial or complete edits and do not authorize retry.'}
