"""Compare a saved fixed-4x GT capture with an EFILive E54 read HTX, offline.

This command accepts existing files only; it never opens a serial transport.
A passing result means exact agreement within the stated trace window and
direction. It does not establish electrical silence or programming readiness.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

from audit_trace_wrappers import framed_message
from decode_trace_containers import decode, records
from obdx_capture import SETTINGS, replay_jsonl


FLASH_BYTES = 0x80000
TRANSFER_END = FLASH_BYTES - 2  # Observed E54 read omits the final two bytes.
A1 = bytes.fromhex('6cfef0a1')
DATA_HEADER = bytes.fromhex('6df01036')
VPW_HEADERS = (0x6c, 0x6d, 0x8c)
# Wrapper route bytes observed around E54 read traffic. These other routes
# contain device queries/control, not the 008A TX / 0010 or 0000 RX payloads.
# Keep the exclusion explicit; new routes require review, not silent skipping.
LOCAL_ROUTES = {bytes.fromhex(s) for s in
                ('0182', '0382', '0482', '0582', '0682', '2383', '2483', '2e83', '0486')}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def crc8_j1850(data):
    crc = 0xff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ (0x1d if crc & 0x80 else 0)) & 0xff
    return crc ^ 0xff


def sequence_sha256(messages):
    digest = hashlib.sha256()
    for message in messages:
        digest.update(len(message).to_bytes(4, 'big'))
        digest.update(message)
    return digest.hexdigest()


def frame_counts(messages):
    return [{'header_and_service': m[:4].hex(), 'message_bytes': len(m),
             'message_sha256': sha256(m), 'count': count}
            for m, count in Counter(messages).items()]


def trace_window(data, source_id):
    """Reject unrecognized binary wrappers, rather than silently dropping them."""
    decoded = decode(data)
    frames = []
    parsed = list(records(decoded))
    for ordinal, row in enumerate(parsed):
        if row['kind'] != 0x42:
            continue
        payload, channel = row['payload'], row['channel']
        framed = framed_message(row)
        if framed is None:
            raise ValueError(f'Unsupported binary wrapper shape at record {ordinal}')
        frames.append((ordinal, channel, framed[1], payload[2:4]))
    starts = [i for i, channel, m, route in frames
              if channel == 1 and m == A1 and route == b'\x00\x8a']
    if len(starts) != 1:
        raise ValueError('Exactly one A1 speed-start request is required')
    begin = starts[0]
    ends = [i for i, channel, m, route in frames
            if channel == 2 and m[:4] == DATA_HEADER and i > begin
            and route in (b'\x10\x00', b'\x00\x00')]
    if not ends:
        raise ValueError('No E54 data responses follow A1')
    end = ends[-1]
    window, excluded = [], []
    for ordinal, ch, message, route in frames:
        if not begin < ordinal <= end:
            continue
        if route in LOCAL_ROUTES:
            if len(message) >= 4 and message[0] in VPW_HEADERS and message[2] in (0x10, 0xf0):
                raise ValueError(f'VPW-looking message in excluded local route at record {ordinal}')
            excluded.append({'record_ordinal_zero_based': ordinal,
                             'channel': ch, 'route_bytes': route.hex()})
            continue
        if route not in ({b'\x00\x8a'} if ch == 1 else {b'\x10\x00', b'\x00\x00'}):
            raise ValueError(f'Unsupported binary wrapper route at record {ordinal}')
        window.append((ordinal, ch, message))
    expected = []
    channel = None if source_id is None else 2 if source_id == 0x10 else 1
    for ordinal, ch, message in window:
        if len(message) < 4 or message[0] not in VPW_HEADERS:
            raise ValueError(f'Unsupported VPW message at record {ordinal}')
        if source_id is None or message[2] == source_id:
            if channel is not None and ch != channel:
                raise ValueError(f'Source and wrapper direction disagree at record {ordinal}')
            expected.append(message)
    if not expected:
        raise ValueError('Selected direction has no messages in the trace window')
    return expected, [m for _, ch, m in window if ch == 2 and m[:4] == DATA_HEADER], {
        'a1_record_ordinal_zero_based': begin,
        'final_data_record_ordinal_zero_based': end,
        'selection': 'Strictly after A1 through last E54 data response, inclusive',
        'source_id': source_id, 'wrapper_channel': channel,
        'direction_inference': ('host_tx_or_device_rx_candidate' if channel is None else
                                'device_rx_candidate' if channel == 2 else 'host_tx_candidate'),
        'expected_message_count': len(expected), 'record_count': len(parsed),
        'decoded_trace_sha256': sha256(decoded),
        'excluded_local_wrapper_records': excluded,
        'gt_frame_alignment': 'None; every replayed GT network frame is compared, including extras',
    }


def blocks_summary(messages):
    """Summarize addressed bytes without filling gaps or copying a previous BIN."""
    image = bytearray(FLASH_BYTES)
    covered = bytearray(FLASH_BYTES)
    failures, addresses, malformed, conflicts = [], [], [], []
    blocks = [m for m in messages if m[:4] == DATA_HEADER]
    for ordinal, message in enumerate(blocks):
        if len(message) < 12:
            malformed.append(ordinal)
            continue
        length = int.from_bytes(message[5:7], 'big')
        address = int.from_bytes(message[7:10], 'big')
        if (message[4] != 0 or not 0 < length <= 4096
                or len(message) != length + 12 or address + length > TRANSFER_END):
            malformed.append(ordinal)
            continue
        if sum(message[4:-2]) & 0xffff != int.from_bytes(message[-2:], 'big'):
            failures.append(ordinal)
        addresses.append(address)
        body = message[10:-2]
        if any(covered[address + i] and image[address + i] != value
               for i, value in enumerate(body)):
            conflicts.append(ordinal)
        image[address:address + length] = body
        covered[address:address + length] = b'\x01' * length
    ranges = []
    start = None
    for address in range(FLASH_BYTES + 1):
        present = address < FLASH_BYTES and covered[address]
        if present and start is None:
            start = address
        elif not present and start is not None:
            ranges.append({'start': start, 'end_exclusive': address,
                           'sha256': sha256(image[start:address])})
            start = None
    complete = (sum(covered) == TRANSFER_END and not malformed
                and not failures and not conflicts)
    return {
        'count': len(blocks), 'unique_addresses': len(set(addresses)),
        'duplicate_address_count': len(addresses) - len(set(addresses)),
        'malformed_block_ordinals_zero_based': malformed,
        'checksum_failed_block_ordinals_zero_based': failures,
        'conflicting_block_ordinals_zero_based': conflicts,
        'checksum_method': 'sum(message[4:-2]) modulo 65536, final two bytes big-endian',
        'covered_bytes': sum(covered), 'covered_ranges': ranges,
        'expected_transfer_end_exclusive': TRANSFER_END,
        'complete_observed_e54_read_range': complete,
        'reconstructed_partial_sha256': sha256(image[:TRANSFER_END]) if complete else None,
        'full_512kib_image': False,
        'untransferred_tail': {'start': TRANSFER_END, 'end_exclusive': FLASH_BYTES},
    }


def capture_context(replayed, source_id, *, all_sources=False):
    """Require separate, correlated GET responses, never SET echoes or labels.

    The existing replay parser owns DVI framing and guards. This narrow audit
    owns whether the raw setting evidence supports this comparison's scope at
    each received frame. It establishes adapter context, not physical bus rate.
    """
    required = {
        (0x31, 1): ('vpw_protocol', {b'\x01\x01'}),
        (0x31, 2): ('listen_only', {b'\x02\x02'}),
        (0x33, 0): ('to_filter_clear_preparation', {b'\x00\x00\x00'}),
        (0x33, 1): ('exact_source', {bytes([1, 0x10 if all_sources else source_id, 1])}),
        (0x33, 2): ('to_range_clear_preparation', {bytes([2, 0, 0, 0])}),
        (0x33, 3): ('from_range_clear_preparation', {bytes([3, 0, 0, 0])}),
        (0x33, 4): ('zero_mask_preparation', {bytes([4, 0, 0, 0, 0]), bytes([4, 0, 0, 0, 1])}),
        (0x33, 6): ('speed_4x', {b'\x06\x01'}),
        (0x33, 7): ('crc_validation_on', {b'\x07\x01'}),
        (0x33, 8): ('crc_display_on', {b'\x08\x01'}),
    }
    profile_payloads = (b'\x00\x00\x01', b'\x01\x10\x01',
                        b'\x02\x00\x00\x00', b'\x03\x00\x00\x00',
                        b'\x04\x00\x00\x00\x01')
    if all_sources:
        for sub, payload in enumerate(profile_payloads):
            required[0x33, sub] = ('experimental_filter_' + str(sub), {payload})
    state = {key: None for key in required}
    pending = None
    failures, correlation_errors = [], []
    count = 0
    first_context = None
    last_filter_write = None
    recent_transactions = []
    profile_before_listen = False
    mask_last_after_from_enable = False
    setting_gets = []
    for row in replayed:
        kind = row['kind']
        if kind == 'recorded_tx_audit':
            raw = bytes.fromhex(row['raw_hex'])
            # ELM identity/switch bytes are audited by replay, not DVI requests.
            if len(raw) < 3 or len(raw) != raw[1] + 3 or sum(raw) & 255 != 255:
                continue
            command, payload = raw[0], raw[2:-1]
            if all_sources and command == 0x31 and payload == b'\x02\x02':
                profile_before_listen = recent_transactions == [
                    (0x33, bytes([sub]), value) for sub, value in enumerate(profile_payloads)]
            if pending is not None:
                correlation_errors.append({'reason': 'overlapping_requests',
                                           'source_line': row['source_line']})
                if pending['key'] in state:
                    state[pending['key']] = None
            key = (command, payload[0]) if payload else None
            if command == 0x33 and len(payload) > 1 and payload[0] in range(5):
                # Exact TO/FROM and mask enable flags are coupled on the tested
                # GT. Another filter SET invalidates the previous source route.
                if all_sources:
                    profile_before_listen = False
                    mask_last_after_from_enable = (
                        payload == profile_payloads[4] and last_filter_write is not None
                        and last_filter_write['key'] == (0x33, 1)
                        and last_filter_write['payload_hex'] == profile_payloads[1].hex())
                    for sub in range(5):
                        state[0x33, sub] = None
                else:
                    state[0x33, 1] = None
                last_filter_write = {'key': key, 'payload_hex': payload.hex(),
                                     'source_line': row['source_line']}
            if key in state:
                state[key] = None  # SET and pending GET both invalidate context.
            pending = {'key': key, 'command': command, 'payload': payload,
                       'source_line': row['source_line']}
        elif kind == 'adapter':
            command = row['command'] - 0x10
            payload = bytes.fromhex(row['payload_hex'])
            key = (command, payload[0]) if payload else None
            matched = (pending is not None and pending['command'] == command
                       and pending['key'] == key)
            if key in state:
                state[key] = None
                if not matched:
                    correlation_errors.append({'reason': 'uncorrelated_setting_status',
                                               'source_line': row['source_line_end'],
                                               'setting': required[key][0]})
                elif len(pending['payload']) == 1:
                    state[key] = {'payload_hex': payload.hex(),
                                  'request_source_line': pending['source_line'],
                                  'response_source_line': row['source_line_end']}
                elif payload != pending['payload']:
                    correlation_errors.append({'reason': 'setting_acknowledgment_mismatch',
                                               'source_line': row['source_line_end'],
                                               'setting': required[key][0]})
            if matched:
                if len(pending['payload']) == 1 and key in {(cmd, sub) for cmd, sub, _, _ in SETTINGS}:
                    setting_gets.append({'command': command, 'subcommand': payload[0],
                                         'payload_hex': payload.hex(),
                                         'request_source_line': pending['source_line'],
                                         'response_source_line': row['source_line_end']})
                recent_transactions.append((command, pending['payload'], payload))
                recent_transactions = recent_transactions[-5:]
                pending = None
        elif kind == 'network':
            invalid = [label for key, (label, allowed) in required.items()
                       if state[key] is None
                       or bytes.fromhex(state[key]['payload_hex']) not in allowed]
            if all_sources:
                if not mask_last_after_from_enable:
                    invalid.append('zero_mask_was_not_last_after_exact_from_enable')
                if not profile_before_listen:
                    invalid.append('full_filter_profile_not_read_back_immediately_before_listen')
            elif (last_filter_write is None or last_filter_write['key'] != (0x33, 1)
                  or last_filter_write['payload_hex'] != bytes([1, source_id, 1]).hex()):
                invalid.append('last_filter_write_is_not_the_checked_exact_source')
            if first_context is None:
                first_context = {label: state[key] for key, (label, _) in required.items()}
            if invalid:
                failures.append({'network_frame_ordinal_zero_based': count,
                                 'source_line_end': row['source_line_end'],
                                 'missing_or_contradictory_settings': invalid})
            count += 1
    final_off = state[0x31, 2]
    off_verified = final_off is not None and final_off['payload_hex'] == '0200'
    return {
        'scope': 'Raw separately correlated GET context at each GT network frame',
        'verified': bool(count) and not failures and not correlation_errors and off_verified,
        'network_frames': count, 'frames_with_matching_context': count - len(failures),
        'first_frame_readbacks': first_context,
        'filter_interpretation': (
            'All five experimental filter GETs must follow the final zero-MASK SET and immediately precede LISTEN. FROM10 ON must precede that final MASK SET. Matching observable GETs do not establish hidden independent register states or receive coverage.'
            if all_sources else
            'TO/range/mask preparation readbacks are historical; their later independent register states are unknown because filter controls can alias. Exact FROM must be the last filter SET and separately read back before every frame.'),
        'frame_context_failures': failures, 'correlation_errors': correlation_errors,
        'final_network_off_readback': final_off,
        'final_network_off_verified': off_verified,
        'correlated_setting_gets': setting_gets,
        'actual_bus_speed': 'unknown',
    }


def observable_restoration(replayed, gets, rows, start_line, cleanup_line, restore_line, restored):
    """Cross-check source summaries against initial/final correlated raw GETs."""
    issues, original, final = [], [], []
    saved = [(i, r) for i, r in enumerate(rows, 1) if r.get('kind') == 'saved_setting']
    if len(saved) != len(SETTINGS):
        issues.append('Exactly nine original saved-setting records are required')
    setting_keys = {(cmd, sub) for cmd, sub, _, _ in SETTINGS}
    mutations = []
    for row in replayed:
        if row['kind'] != 'recorded_tx_audit':
            continue
        wire = bytes.fromhex(row['raw_hex'])
        if len(wire) >= 4 and len(wire) == wire[1] + 3:
            if (wire[0], wire[2]) in setting_keys and len(wire[2:-1]) > 1:
                mutations.append(row['source_line'])
    original_end = max((line for line, _ in saved), default=0)
    if any(line < original_end for line in mutations):
        issues.append('Settings changed before the complete original snapshot')
    if any(line >= restore_line for line in mutations):
        issues.append('Settings changed after the restoration record')
    final_mutation = max((line for line in mutations if line < restore_line), default=0)
    for command, sub, size, label in SETTINGS:
        candidates = [(line, row) for line, row in saved if row.get('label') == label]
        if len(candidates) != 1:
            issues.append('Missing or ambiguous original setting: ' + label)
            continue
        line, row = candidates[0]
        value = row.get('payload_hex')
        raw_initial = [g for g in gets if g['command'] == command and g['subcommand'] == sub
                       and g['response_source_line'] < line]
        raw_final = [g for g in gets if g['command'] == command and g['subcommand'] == sub
                     and max(cleanup_line, final_mutation) < g['response_source_line'] < restore_line]
        valid_value = (isinstance(value, str) and len(value) == size * 2
                       and value.startswith(f'{sub:02x}') and value[-2:] in ('00', '01'))
        if (not valid_value or row.get('command') != command or line >= start_line
                or not raw_initial or raw_initial[-1]['payload_hex'] != value):
            issues.append('Original setting lacks matching raw GET: ' + label)
        if not raw_final or raw_final[-1]['payload_hex'] != value:
            issues.append('Final setting lacks matching raw GET after all restoration writes: ' + label)
        original.append(value)
        final.append(raw_final[-1]['payload_hex'] if raw_final else None)
    if restored.get('expected_readbacks') != original or restored.get('observed_readbacks') != final:
        issues.append('Restoration summary arrays disagree with original/final raw GETs')
    return {'verified': not issues, 'issues': issues,
            'original_readbacks': original, 'final_readbacks': final,
            'hidden_setting_state_restored': None,
            'scope': 'Nine observable GET payloads; hidden register state remains unknown'}


def ordered_subsequence(expected, observed):
    """Describe extra frames explicitly; this never changes the strict result."""
    matched, extra = [], []
    for ordinal, message in enumerate(observed):
        if len(matched) < len(expected) and message == expected[len(matched)]:
            matched.append(ordinal)
        else:
            extra.append(ordinal)
    return {
        'expected_is_subsequence': len(matched) == len(expected),
        'matched_expected_message_count': len(matched),
        'matched_observed_ordinals_zero_based': matched,
        'unmatched_observed_ordinals_zero_based': extra,
        'unmatched_observed_frames': frame_counts(observed[i] for i in extra),
        'method': 'Greedy exact ordered match; duplicate messages can make attribution ambiguous',
        'changes_strict_comparison_result': False,
    }


def compare(capture, trace, source_id=None, *, all_sources=False):
    if type(all_sources) is not bool or (all_sources and source_id is not None):
        raise ValueError('Choose exact source or experimental all-sources comparison')
    if not all_sources and (type(source_id) is not int or source_id not in (0x10, 0xf0)):
        raise ValueError('Only VPW header source 0x10 or 0xF0 is supported for this E54 comparison')
    paths = [Path(capture), Path(trace)]
    inputs = [path.read_bytes() for path in paths]
    result = {
        'schema_version': 1,
        'scope': ('Offline comparison of the full host/device fixed-4x E54 trace window against an experimental all-source capture'
                  if all_sources else 'Offline comparison of one fixed-4x, single-header-source E54 read window'),
        'inputs': [{'path': str(path.resolve()), 'bytes': len(data), 'sha256': sha256(data)}
                   for path, data in zip(paths, inputs)],
        'source_id': source_id, 'all_sources': all_sources, 'comparison_passed': False, 'issues': [],
        'normalization': 'Remove one final physical VPW CRC byte from each GT frame only',
        'sequence_digest_encoding': 'Concatenated 4-byte big-endian lengths and message bytes',
        'expected_window': None, 'strict_replay': None,
        'ordered_messages_equal': None, 'observed_network_frame_count': 0,
        'trace_blocks': None, 'capture_blocks': None,
        'live_write_enabled': False, 'ready_to_flash': False, 'would_send': [],
        'complete_bus_capture_proven': False,
        'limits': [
            'Comparison is relative to the HTX window; its physical-bus completeness is unknown.',
            'Wrapper directions are inferred; wrapper checksums are not independently verified.',
            'Explicit known device-query wrapper routes are excluded from the VPW window.',
            'Configured 4x is not a physical pulse-timing measurement.',
            ('Fixed 4x excludes 1x startup/return; all-source filter reception coverage remains experimental.'
             if all_sources else 'Other direction and 1x startup/return are outside this single-source fixed-speed comparison.'),
            'VPW source addresses do not identify physical transmitters; physical origins of F0/F1 keepalives remain unverified.',
            'Identical acknowledgments cannot exclude offsetting physical loss and duplication.',
            'No waveform, electrical silence/loading, programming, recovery or flash-readiness proof.',
            'The final two flash bytes are absent and are never filled from another image.',
        ],
        'reproduction': {'implementation_sha256': {
            name: sha256(Path(__file__).with_name(name).read_bytes()) for name in
            (Path(__file__).name, 'audit_trace_wrappers.py', 'decode_trace_containers.py', 'inspect_trace_containers.py',
             'al5_segment.py', 'obdx_capture.py', 'obdx_speed.py')}},
    }
    issues = result['issues']
    expected, observed = None, None
    try:
        expected, data_blocks, window = trace_window(inputs[1], source_id)
        result['expected_window'] = window
        result['trace_blocks'] = blocks_summary(data_blocks)
        if not result['trace_blocks']['complete_observed_e54_read_range']:
            issues.append('HTX E54 data coverage/checksums are incomplete or invalid')
    except (ValueError, KeyError, TypeError, struct.error) as error:
        issues.append('HTX unsupported or malformed: ' + str(error))

    replayed = []
    try:
        replay_jsonl(paths[0], replayed.append)
    except (ValueError, KeyError, TypeError, OSError) as error:
        issues.append('Strict replay failed: ' + str(error))
    summaries = [r for r in replayed if r['kind'] == 'replay_summary']
    if len(summaries) == 1:
        summary = result['strict_replay'] = summaries[0]
        if (summary['replay_complete'] is not True or summary['source_fully_read'] is not True
                or summary['source_result_seen'] is not True or summary['source_reported_failure']
                or summary['adapter_errors'] or summary['outgoing_guard_violations']
                or summary['undecoded_dvi_hex'] or summary['input_sha256'] != sha256(inputs[0])):
            issues.append('Strict replay does not establish a complete successful guarded source')
    else:
        issues.append('Strict replay summary missing or ambiguous')
    result['raw_capture_context'] = capture_context(replayed, source_id, all_sources=all_sources)
    if not result['raw_capture_context']['verified']:
        issues.append('Raw correlated setting evidence does not establish the declared capture context')
    if len(summaries) == 1:
        speeds = summaries[0]['speed_analysis']['qualification']['frames_by_adapter_readback']
        if (speeds['1x'] or speeds['unknown'] or not speeds['4x']
                or speeds['4x'] != summaries[0]['network_frames']):
            issues.append('Raw replay does not attribute every network frame to a 4x adapter readback')
    try:
        rows = [json.loads(line) for line in inputs[0].splitlines()]
        if not rows or any(not isinstance(r, dict) for r in rows):
            raise ValueError('JSONL must contain objects')
        starts = [(i, r) for i, r in enumerate(rows, 1) if r.get('kind') == 'capture_started']
        cleanup = [(i, r) for i, r in enumerate(rows, 1) if r.get('kind') == 'cleanup']
        restore_kind = 'settings_readback_restoration' if all_sources else 'settings_restored'
        restored = [(i, r) for i, r in enumerate(rows, 1) if r.get('kind') == restore_kind]
        if len(starts) != 1 or len(cleanup) != 1 or len(restored) != 1:
            raise ValueError('Exactly one capture start, cleanup and settings restoration required')
        start_line, start = starts[0]
        cleanup_line, cleanup_row = cleanup[0]
        restored_line, restored_row = restored[0]
        result['capture_declared_scope'] = start
        result['cleanup_record'] = cleanup_row
        result['settings_restoration_record'] = restored_row
        if (start.get('fixed_speed') != '4x' or start.get('crc_in_payload') is not True
                or start.get('receive_scope') != ('experimental_mask_all' if all_sources else 'exact_source')
                or start.get('source_filter') != source_id
                or start.get('automatic_speed_tracking') is not False):
            issues.append('Capture declared speed/CRC/filter scope does not match comparison')
        if all_sources and (restored_row.get('observable_readbacks_match_original') is not True
                            or restored_row.get('hidden_setting_state_restored', 'missing') is not None):
            issues.append('Experimental observable restoration evidence is missing or overstates hidden-state restoration')
        if all_sources:
            original = restored_row.get('expected_readbacks')
            if (not isinstance(original, list) or len(original) != 9
                    or restored_row.get('observed_readbacks') != original):
                issues.append('Experimental final nine-setting snapshot is absent or mismatched')
            result['raw_observable_restoration'] = observable_restoration(
                replayed, result['raw_capture_context']['correlated_setting_gets'], rows,
                start_line, cleanup_line, restored_line, restored_row)
            if not result['raw_observable_restoration']['verified']:
                issues.append('Experimental observable restoration lacks matching initial/final raw GET evidence')
        if (not start_line < cleanup_line < restored_line < len(rows)
                or cleanup_row.get('network_off_acknowledged') is not True
                or restored_row.get('success') is not True
                or rows[-1].get('kind') != 'result' or rows[-1].get('success') is not True):
            issues.append('Successful terminal result, network OFF and settings restoration required')
        network = [r for r in replayed if r['kind'] == 'network']
        if any(not start_line < r['source_line_end'] < cleanup_line for r in network):
            issues.append('Network frames occur outside the declared capture interval')
        physical = [bytes.fromhex(r['payload_hex']) for r in network]
        result['observed_network_frame_count'] = len(physical)
        bad_crc = [i for i, m in enumerate(physical) if not m or crc8_j1850(m[:-1]) != m[-1]]
        result['vpw_crc'] = {
            'algorithm': 'CRC-8 SAE J1850, poly1D initFF xoroutFF nonreflected',
            'check_vector_123456789': f'{crc8_j1850(b"123456789"):02x}',
            'checked_frames': len(physical), 'failed_frame_ordinals_zero_based': bad_crc,
        }
        if bad_crc:
            issues.append('Physical VPW CRC failures')
        observed = [m[:-1] for m in physical]
        if any(len(m) < 4 or m[0] not in VPW_HEADERS
               or (not all_sources and m[2] != source_id) for m in observed):
            issues.append('Observed message is outside the supported VPW/source scope')
        result['message_length_histogram_without_physical_crc'] = dict(Counter(map(len, observed)))
        result['dvi_network_commands'] = dict(Counter(hex(r['command']) for r in network))
        result['observed_header_source_counts'] = dict(Counter(f'{m[2]:02x}' for m in observed if len(m) >= 3))
        if source_id == 0x10 or all_sources:
            result['capture_blocks'] = blocks_summary(observed)
            if not result['capture_blocks']['complete_observed_e54_read_range']:
                issues.append('GT E54 data coverage/checksums are incomplete or invalid')
        else:
            result['capture_blocks'] = {'available': False, 'reason': 'Selected F0 header excludes source10 E54 data responses; physical transmitter is not inferred'}
    except (ValueError, KeyError, TypeError) as error:
        issues.append('Capture scope unsupported or malformed: ' + str(error))

    if expected is not None and observed is not None:
        missing, extra = Counter(expected) - Counter(observed), Counter(observed) - Counter(expected)
        result.update({
            'ordered_messages_equal': observed == expected,
            'expected_sequence_sha256': sequence_sha256(expected),
            'observed_sequence_sha256': sequence_sha256(observed),
            'expected_header_source_counts': dict(Counter(f'{m[2]:02x}' for m in expected)),
            'missing_frame_count': sum(missing.values()), 'extra_frame_count': sum(extra.values()),
            'missing_frames': frame_counts(missing.elements()), 'extra_frames': frame_counts(extra.elements()),
            'ordered_subsequence_analysis': ordered_subsequence(expected, observed),
            'first_mismatch_ordinal_zero_based': next(
                (i for i, (a, b) in enumerate(zip(expected, observed)) if a != b),
                min(len(expected), len(observed)) if len(expected) != len(observed) else None),
        })
        result['per_header_source_comparison'] = {}
        for source in sorted({m[2] for m in expected + observed if len(m) >= 3}):
            wanted = [m for m in expected if m[2] == source]
            seen = [m for m in observed if len(m) >= 3 and m[2] == source]
            result['per_header_source_comparison'][f'{source:02x}'] = {
                'expected_count': len(wanted), 'observed_count': len(seen),
                'ordered_messages_equal': wanted == seen,
                'missing_count': sum((Counter(wanted) - Counter(seen)).values()),
                'extra_count': sum((Counter(seen) - Counter(wanted)).values()),
                'ordered_subsequence': ordered_subsequence(wanted, seen),
                'scope': 'Diagnostic header-source partition only; never changes the complete comparison',
            }
        if observed != expected:
            issues.append('Ordered messages differ from selected HTX window')
    for path, original in zip(paths, inputs):
        if sha256(path.read_bytes()) != sha256(original):
            issues.append('Input changed during comparison: ' + str(path))
    result['comparison_passed'] = not issues and result['ordered_messages_equal'] is True
    return result


def source_byte(value):
    try:
        result = int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError('Use 0x10 or 0xF0') from error
    if result not in (0x10, 0xf0):
        raise argparse.ArgumentTypeError('Use 0x10 or 0xF0')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True, help='Closed GT capture JSONL')
    parser.add_argument('--trace', type=Path, required=True, help='Matching E54 read HTX')
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument('--source-id', type=source_byte,
                       help='Header source 0x10 (expected RX) or 0xF0 (expected host TX); not physical sender identity')
    scope.add_argument('--all-sources', action='store_true',
                       help='Experimental zero-mask capture; compare both HTX directions without dropping extra GT frames')
    parser.add_argument('--output', type=Path, required=True, help='New JSON receipt; never overwritten')
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error('Output already exists; choose a new receipt path')
    try:
        result = compare(args.capture, args.trace, args.source_id, all_sources=args.all_sources)
        with args.output.open('x', encoding='utf8') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps({'receipt': str(args.output.resolve()),
                      'comparison_passed': result['comparison_passed'],
                      'frames': result['observed_network_frame_count'],
                      'issues': result['issues'], 'live_write_enabled': False}))
    return 0 if result['comparison_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
