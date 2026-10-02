"""Offline event ordering and supplied-byte readback checks; no adapter or packet I/O."""
from al5_segment import START, validate, sha256
from checksum import checksum_valid
from host_validation import simulate_batch


def replay(frames, baseline, events):
    preflight = simulate_batch(frames, baseline)
    errors = list(preflight['input_errors'])
    if not preflight['modeled_result_native_checksum_valid']:
        errors.append('complete modeled candidate native checksum invalid')
    expected = bytearray(baseline)
    if not errors:
        for frame, block in zip(frames, preflight['blocks']):
            offset = int(block['address'], 16) - START
            expected[offset:offset + block['declared_length']] = frame[10:-2]
        errors.extend(f'candidate: {error}' for error in validate(expected))
    state = 'preflight_rejected' if errors else 'ready'
    index = 0
    issued = confirmed = 0
    history = []
    for event_number, event in enumerate(events):
        if errors:
            break
        kind = event.get('kind')
        reason = None
        if kind == 'issue':
            if state != 'ready' or index >= len(frames) or event.get('index') != index:
                reason = 'unexpected, duplicate or out-of-order issue'
            else:
                issued += 1
                state = 'awaiting_status'
        elif kind == 'response':
            data = event.get('data', b'')
            if state != 'awaiting_status':
                reason = 'response without a pending block; duplicate/stale status is unsafe'
            elif len(data) != 6:
                reason = 'incomplete software response; physical framing is unverified'
            elif data[:3] != bytes([frames[index][0], frames[index][2], 0x18]) or data[3:5] != b'\x76\x00':
                reason = 'response header/service mismatch'
            elif data[5] != 0x73:
                reason = f'non-success block status 0x{data[5]:02x}; writes may already have occurred'
            else:
                state = 'awaiting_readback'
        elif kind == 'block_readback':
            data = event.get('data', b'')
            if state != 'awaiting_readback' or event.get('index') != index:
                reason = 'readback without the expected pending block'
            elif data != frames[index][10:-2]:
                reason = 'block readback mismatch'
            else:
                confirmed += 1
                index += 1
                state = 'awaiting_final_snapshot' if index == len(frames) else 'ready'
        elif kind == 'final_snapshot':
            data = event.get('data', b'')
            if state != 'awaiting_final_snapshot':
                reason = 'final snapshot before all block readbacks'
            elif data != expected or not checksum_valid(data):
                reason = 'final snapshot differs from complete checksummed candidate'
            else:
                state = 'offline_complete'
        elif kind in ('timeout', 'disconnect'):
            reason = f'{kind}; physical write outcome unknown'
        else:
            reason = 'unknown replay event'
        if reason:
            errors.append(reason)
            state = 'aborted'
        history.append({'event': event_number, 'kind': kind, 'state': state})
    if not errors and state != 'offline_complete':
        errors.append('replay ended before final verified snapshot')
        state = 'incomplete'
    return {'mode': 'offline_supplied_event_replay', 'state': state, 'input_errors': errors,
            'issued_blocks': issued, 'matched_block_readbacks': confirmed, 'history': history,
            'baseline_sha256': sha256(baseline), 'expected_candidate_sha256': sha256(expected),
            'automatic_retry_allowed': False, 'wire_sequence_number_verified': False,
            'physical_acknowledgment_correlation_verified': False,
            'physical_readback_verified': False, 'ready_to_flash': False,
            'live_write_enabled': False, 'erase_scope': None,
            'would_send': [], 'erase_packets': [], 'program_packets': [],
            'limits': 'Replay indices exist only in supplied offline events. Status bodies contain no verified block sequence identity. A stale identical status during a later pending block cannot be detected from these bytes alone. Readbacks and final snapshot are caller-supplied, not physical evidence. No session entry/erase/exit or transport is implemented.'}
