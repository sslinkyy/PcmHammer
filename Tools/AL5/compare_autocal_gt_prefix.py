"""Offline paired AutoCal/GT audit for the fixed E54 64-byte prefix experiment.

GT decoded rows are rebuilt from original serial chunks. No serial/native I/O,
firmware export, inferred clock synchronization or modification of inputs.
"""
import argparse
from collections import Counter
import json
import math
from pathlib import Path

from al5_segment import sha256
from compare_vpw_read_capture import crc8_j1850
from inspect_autocal_read_gap import frame, is_vpw, pin
from inspect_trace_containers import MAX_INPUT
from obdx_capture import replay_jsonl, SETTINGS


REQUEST = bytes.fromhex('6d10f035010040000000')
REPLY_HEADER = bytes.fromhex('6df01036010040000000')
BASELINE_SHA = 'a3b010af7e04df03be699198920aac26ba0645c2ad608e72eacf0bc3970beb58'
PREFIX_SHA = '5b20a24c0d5c5618de617dd929c4baffe7ba4cf151648398f68f0105bd43a5d9'
PROFILES = ('e54-read-prefix', 'e54-read-prefix-recorded-setup')
RECORDED_FLAGS = ('RecordedReadSetupAttempted', 'RecordedReadSetupApplied',
                  'RecordedOrdinaryConfigurationRestored')
ORDINARY_SETUP = ((0x8201, b'', b'ACV2\0'), (0x8604, b'\0', b''),
                  (0x8800, bytes(2), b'\0'), (0x8604, bytes(6), b''))
RECORDED_SETUP = ((0x8603, bytes.fromhex('0100f401'), b''),
                  (0x8604, bytes.fromhex('010010000000'), b''),
                  (0x8604, bytes(6), b''))
ADAPTER_CLEANUP = ((0x8604, bytes(6), b''), (0x8b01, bytes.fromhex('00010000'), b''),
                   (0x8b01, bytes.fromhex('01010000'), b''))


def parse_rows(source):
    rows = [json.loads(line) for line in source.decode('utf-8-sig').splitlines() if line.strip()]
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError('Journal rows must be objects')
    return rows


def setup_lifecycle(plan, result, receipt, tx, rx, request):
    """Check the two explicit profiles against original framed commands/replies."""
    recorded = plan['profile'] == PROFILES[1]
    # The ordinary experiment predates these fields. Accept that all-absent
    # historical representation, never a partially omitted or contradictory one.
    flag_keys = ['recorded_read_setup_experiment'] + list(RECORDED_FLAGS)
    flags = [plan.get(flag_keys[0])] + [result.get(k) for k in RECORDED_FLAGS]
    legacy = flag_keys[0] not in plan and all(k not in result for k in RECORDED_FLAGS)
    if not (not recorded and legacy) and any(value is not recorded for value in flags):
        raise ValueError('AutoCal profile/recorded-setup flags disagree or are missing')
    if result.get('FlashWriteEnabled') is not False:
        raise ValueError('AutoCal result does not explicitly disable flash writing')
    if receipt.get('setup_accepted') is not True or type(receipt.get('recorded_cleanup_accepted')) is not bool:
        raise ValueError('AutoCal setup/cleanup status is missing or unsupported')
    cleanup = receipt['recorded_cleanup_accepted']
    expected = ORDINARY_SETUP + (RECORDED_SETUP if recorded else ()) + (ADAPTER_CLEANUP if cleanup else ())
    local_tx, local_rx = [r for r in tx if not is_vpw(r)], [r for r in rx if not is_vpw(r)]
    if len(local_tx) != len(expected) or len(local_rx) != len(expected):
        raise ValueError('AutoCal exact local setup/cleanup lifecycle counts differ')
    evidence = []
    for index, (sent, received, (command, payload, reply)) in enumerate(zip(local_tx, local_rx, expected)):
        following = next((r['line'] for r in tx if r['line'] > sent['line']), float('inf'))
        if (sent['command'] != command or sent['payload'] != payload
                or sent['raw'][4:10] != b'\x07\x00' + bytes(4)
                or int.from_bytes(received['raw'][2:4], 'little') != command
                or received['payload'] != reply or not sent['line'] < received['line'] < following):
            raise ValueError('AutoCal exact local command/reply lifecycle differs')
        evidence.append({'command_hex': f'{command:04X}', 'payload_hex': payload.hex(),
                         'tx_journal_line_one_based': sent['line'], 'rx_journal_line_one_based': received['line'],
                         'tx_wrapper_sha256': sha256(sent['raw']), 'rx_wrapper_sha256': sha256(received['raw']),
                         'reply_payload_matches': True})
    vpw_tx = [r for r in tx if is_vpw(r)]
    if local_rx[3]['line'] >= vpw_tx[0]['line']:
        raise ValueError('AutoCal ordinary setup was not completed before VPW traffic')
    if recorded:
        identities = [r for r in rx if is_vpw(r) and r['payload'] in
                      (bytes.fromhex('6cf0107c0a00e7c434'), bytes.fromhex('6cf0107c0a00e7c434444e'))
                      and r['line'] < request['line']]
        versions = [r for r in rx if is_vpw(r) and r['payload'] == bytes.fromhex('6cf0107d006ab178ec36')
                    and r['line'] < request['line']]
        flash_ids = [r for r in vpw_tx if r['payload'] == bytes.fromhex('6c10f03d01') and r['line'] < request['line']]
        if len(identities) != 1 or len(versions) != 1 or len(flash_ids) != 1:
            raise ValueError('Recorded setup requires exact identity, kernel and flash-ID boundaries')
        next_vpw = next(r for r in vpw_tx if r['line'] > identities[0]['line'])
        if not (identities[0]['line'] < local_tx[4]['line'] < local_rx[5]['line'] < next_vpw['line']
                and versions[0]['line'] < local_tx[6]['line'] < local_rx[6]['line'] < flash_ids[0]['line']):
            raise ValueError('Recorded setup did not follow the exact identity/kernel boundaries')
    if cleanup:
        if (result.get('ExitAcknowledged') is not True or result.get('PostExitIdentityVerified') is not True
                or local_tx[-3]['line'] <= vpw_tx[-1]['line']):
            raise ValueError('AutoCal cleanup lacks confirmed exit and final identity')
    return {'recorded_setup_experiment': recorded, 'legacy_ordinary_flags_absent': legacy,
            'plan_and_result_flags_consistent': True, 'exact_local_sequence_and_replies_verified': True,
            'ordinary_setup_commands': 4, 'recorded_extra_commands': 3 if recorded else 0,
            'adapter_cleanup_commands': 3 if cleanup else 0,
            'recorded_preparation_and_restore_boundaries_verified': recorded,
            'local_command_counts': dict(Counter(f'{r[0]:04X}:{r[1].hex()}' for r in expected)),
            'commands': evidence,
            'configuration_effect_on_firmware_or_physical_receive_path_proven': False}


def late_read_coverage(receipt):
    """Unreconciled native bytes or unknown completion cannot prove non-delivery."""
    late = receipt.get('late_transfer')
    blockers, observation = [], None
    if not isinstance(late, dict):
        blockers.append('late_transfer_missing_or_not_an_object')
    else:
        raw = None
        if isinstance(late.get('hex'), str):
            try:
                raw = bytes.fromhex(late['hex'])
            except ValueError:
                pass
        observation = {k: late.get(k) for k in ('Operation', 'RequestedByteCount', 'ReturnedByteCount',
                                               'IsCompleted', 'error')}
        observation.update(data_bytes=len(raw) if raw is not None else None,
                           data_sha256=sha256(raw) if raw is not None else None, raw_bytes_exported=False)
        if late.get('Operation') != 'read':
            blockers.append('late_transfer_is_not_a_read')
        if late.get('IsCompleted') is not True:
            blockers.append('late_read_not_confirmed_complete')
        if 'error' not in late or late['error'] is not None:
            blockers.append('late_read_error_or_unknown_error_status')
        returned, requested = late.get('ReturnedByteCount'), late.get('RequestedByteCount')
        if type(returned) is not int or returned < 0:
            blockers.append('late_read_returned_count_unknown_or_invalid')
        if type(requested) is not int or requested <= 0:
            blockers.append('late_read_requested_count_unknown_or_invalid')
        if raw is None:
            blockers.append('late_read_bytes_unknown_or_invalid')
        elif type(returned) is int and returned != len(raw):
            blockers.append('late_read_returned_count_differs_from_preserved_bytes')
        if raw or (type(returned) is int and returned > 0):
            # Do not parse these bytes as an independent stream: their receive
            # extent/order against the journal has not been reconciled.
            blockers.append('nonempty_late_read_is_not_reconciled_with_journal')
    return observation, {'completed_empty_read_reported': not blockers,
                         'eligible_for_no_delivery_conclusion': not blockers,
                         'qualification_blockers': blockers,
                         'nonempty_late_bytes_reconciled': False}


def autocal_audit(receipt_bytes, journal_bytes):
    receipt, rows = json.loads(receipt_bytes.decode('utf-8-sig')), parse_rows(journal_bytes)
    plans = [r['data'] for r in rows if r.get('kind') == 'plan']
    results = [r['data'] for r in rows if r.get('kind') == 'kernel_result']
    if plans != [receipt.get('plan')] or results != [receipt.get('kernel_result')]:
        raise ValueError('AutoCal receipt/journal plan or result differs')
    plan = plans[0]
    required_flags = {'flash_programming_enabled': False, 'live_kernel_execution_enabled': True,
                      'full_baseline_read_enabled': False, 'baseline_prefix_read_enabled': True}
    if plan.get('profile') not in PROFILES or any(plan.get(k) is not value for k, value in required_flags.items()):
        raise ValueError('AutoCal receipt is outside the fixed prefix-read profile')
    tx, rx, reads = [], [], []
    pending = None
    buffered = bytearray()
    previous = -1
    for line, row in enumerate(rows, 1):
        kind = row.get('kind')
        if kind not in ('write_attempt', 'write_completed', 'read_completed'):
            continue
        time, d = row.get('elapsed_ms'), row['data']
        if type(time) not in (int, float) or not math.isfinite(time) or time < previous:
            raise ValueError('AutoCal native times must be finite and monotonic')
        previous = time
        count = d.get('count')
        if type(count) is not int or count < 0:
            raise ValueError('Invalid AutoCal native count')
        if kind == 'write_attempt':
            raw = bytes.fromhex(d['hex'])
            if pending is not None or d.get('offset') != 0 or len(raw) != count:
                raise ValueError('Unsupported partial/overlapping AutoCal write')
            item = frame(raw, 1)
            item.update(line=line, elapsed_ms=time)
            tx.append(item); pending = item
        elif kind == 'write_completed':
            if pending is None or count != len(pending['raw']):
                raise ValueError('Unmatched/partial AutoCal write completion')
            pending = None
        else:
            raw = bytes.fromhex(d['hex'])
            if len(raw) != count:
                raise ValueError('AutoCal read count differs from raw bytes')
            reads.append({'line': line, 'elapsed_ms': time, 'bytes': count})
            buffered.extend(raw)
            while len(buffered) >= 12:
                extent = int.from_bytes(buffered[10:12], 'little') + 15
                if len(buffered) < extent:
                    break
                item = frame(bytes(buffered[:extent]), 2)
                del buffered[:extent]
                item.update(line=line, elapsed_ms=time)
                rx.append(item)
    if pending is not None or buffered:
        raise ValueError('Incomplete AutoCal write or RX wrapper')
    vpw_tx, vpw_rx = [r for r in tx if is_vpw(r)], [r for r in rx if is_vpw(r)]
    requests = [r for r in vpw_tx if r['payload'] == REQUEST]
    if len(requests) != 1:
        raise ValueError('Expected exactly one fixed64-byte request')
    request = requests[0]
    after = [r for r in reads if r['line'] > request['line']]
    if not after:
        raise ValueError('No read observations after the AutoCal request')
    result = results[0]
    if (result.get('VpwTransmissions') != len(vpw_tx) or result.get('VpwReceivedFrames') != len(vpw_rx)
            or receipt.get('vpw_payload_commands_completed') != len(vpw_tx)):
        raise ValueError('AutoCal receipt counts differ from native journal')
    lifecycle = setup_lifecycle(plan, result, receipt, tx, rx, request)
    late_observation, late_coverage = late_read_coverage(receipt)
    metadata = {
        'profile': plan['profile'], 'adapter_serial': receipt.get('serial'),
        'setup_lifecycle': lifecycle,
        'recorded_kernel_pin': plan.get('kernel'),
        'application_tx_frames': len(tx), 'application_rx_frames': len(rx),
        'vpw_tx_frames': len(vpw_tx), 'vpw_rx_frames': len(vpw_rx),
        'all_complete_wrapper_crcs_valid': True,
        'request': {'payload_hex': REQUEST.hex(), 'outer_wrapper_sha256': sha256(request['raw']),
                    'journal_line_one_based': request['line'], 'elapsed_ms': request['elapsed_ms']},
        'post_request_native_reads': {
            'completion_count': len(after), 'returned_bytes': sum(r['bytes'] for r in after),
            'first_completion_elapsed_ms': after[0]['elapsed_ms'], 'last_completion_elapsed_ms': after[-1]['elapsed_ms'],
            'last_completion_from_request_ms': after[-1]['elapsed_ms'] - request['elapsed_ms'],
            'all_returned_zero': all(r['bytes'] == 0 for r in after),
        },
        'receipt_observations': {k: receipt.get(k) for k in ('setup_accepted', 'recorded_cleanup_accepted',
            'readback_saved_bytes', 'transport_disposed', 'retained_native_owners', 'channel_fault', 'cleanup_exception')},
        'reported_late_transfer': late_observation,
        'late_read_coverage': late_coverage,
        'kernel_result': {k: result.get(k) for k in ('Success', 'InitialIdentityVerified', 'KernelVersionVerified',
            'ExitAcknowledged', 'PostExitIdentityVerified', 'BenchPowerCycleRequired', 'ReadbackLength',
            'ReadbackScope', 'ReadbackCrcVerified', 'BaselineMatched', 'FlashWriteEnabled', *RECORDED_FLAGS)},
        'read_policy': {k: receipt.get('kernel_policy', {}).get(k) for k in ('ReadBlockAttempts', 'ReadBlockReplies',
            'IsShortReadVerified', 'CrcQueryAttempts', 'VerifiedCrcRanges')},
        'recorded_source_sha256': plan.get('source_sha256'),
        'recorded_probe_sha256': plan.get('probe_sha256'),
        'recorded_pcmlibrary_sha256': plan.get('pcmlibrary_sha256'),
    }
    return vpw_rx, metadata


def gt_context(replayed, rows):
    """Correlate GET replies independently of decoded source annotations."""
    required = {(0x31, 1): b'\x01\x01', (0x31, 2): b'\x02\x02', (0x24, 3): b'\x03\x01',
                (0x33, 1): b'\x01\x10\x01', (0x33, 6): b'\x06\x00',
                (0x33, 7): b'\x07\x01', (0x33, 8): b'\x08\x01'}
    starts = [(i, r) for i, r in enumerate(rows, 1) if r.get('kind') == 'capture_started']
    if len(starts) != 1:
        raise ValueError('GT capture must have one start checkpoint')
    start_line, start = starts[0]
    state, gets, pending, failures, before_start, checked = {}, [], None, [], [], []
    last_filter_set = None
    network_count = 0
    for row in replayed:
        kind = row.get('kind')
        if kind == 'recorded_tx_audit':
            raw = bytes.fromhex(row['raw_hex']); command, p = raw[0], raw[2:-1]
            if pending is not None:
                raise ValueError('GT adapter transaction overlapped without response')
            pending = (command, p, row['source_line'])
            if command in (0x24, 0x31, 0x33) and len(p) > 1:
                state.pop((command, p[0]), None)
                if command == 0x33 and p[0] <= 4:
                    last_filter_set = p
        elif kind == 'adapter':
            if pending is None:
                raise ValueError('Unmatched GT adapter response')
            command, requested, line = pending
            p = bytes.fromhex(row['payload_hex'])
            if row['command'] != command + 0x10 or not p or p[0] != requested[0]:
                raise ValueError('GT adapter response did not match pending request')
            if len(requested) > 1 and not (command == 0x33 and requested[0] == 0x0e) and p != requested:
                raise ValueError('GT setter echo differs')
            if len(requested) == 1:
                state[command, p[0]] = p
                gets.append({'command': command, 'payload_hex': p.hex(), 'request_line': line,
                             'reply_line': row['source_line_end']})
            pending = None
        elif kind == 'network':
            missing = [f'{c:02x}:{s:02x}' for (c, s), value in required.items() if state.get((c, s)) != value]
            if last_filter_set != b'\x01\x10\x01':
                missing.append('last_filter_set_is_not_exact_source10')
            if row['source_line_end'] <= start_line:
                before_start.append({'network_ordinal': network_count,
                                     'missing_checked_context': missing})
            elif missing:
                failures.append({'network_ordinal': network_count, 'missing': missing})
            else:
                checked.append(network_count)
            network_count += 1
    if pending is not None:
        raise ValueError('GT transaction pending at capture end')
    saved = [r for r in rows if r.get('kind') == 'saved_setting']
    cleanup = [r for r in rows if r.get('kind') == 'cleanup']
    restored = [r for r in rows if r.get('kind') == 'settings_restored']
    if start.get('fixed_speed') != '1x' or start.get('source_filter') != 0x10:
        raise ValueError('GT capture declaration is not fixed1x/exactsource10')
    if start.get('crc_in_payload') is not True or start.get('adapter_crc_validation_enabled') is not True:
        raise ValueError('GT CRC-display/validation context is unsupported')
    if len(saved) != len(SETTINGS) or len({(r['command'], bytes.fromhex(r['payload_hex'])[0]) for r in saved}) != len(SETTINGS):
        raise ValueError('GT original setting inventory incomplete')
    restoration_matches = all(state.get((r['command'], bytes.fromhex(r['payload_hex'])[0])) == bytes.fromhex(r['payload_hex']) for r in saved)
    off = state.get((0x31, 2)) == b'\x02\x00'
    if failures or not off or not restoration_matches or cleanup != [{'kind': 'cleanup', 'network_off_acknowledged': True}] or restored != [{'kind': 'settings_restored', 'success': True}]:
        raise ValueError('GT listen context, OFF cleanup or checked restoration failed')
    ranges = []
    for index in checked:
        if ranges and ranges[-1]['end_exclusive'] == index:
            ranges[-1]['end_exclusive'] += 1
        else:
            ranges.append({'start': index, 'end_exclusive': index + 1})
    return {'network_frames': network_count, 'capture_started_source_line_one_based': start_line,
            'network_frames_before_capture_started': before_start,
            'checked_network_ordinal_ranges_zero_based': ranges,
            'checked_network_frame_count': len(checked),
            'all_post_start_network_frames_have_checked_context': True,
            'fixed_speed_setting': '1x', 'physical_speed_measured': False, 'exact_source': 16,
            'crc_display_and_validation_enabled': True, 'final_network_off_get_verified': off,
            'all_nine_saved_settings_separately_restored_and_read_back': restoration_matches,
            'hidden_coupled_filter_state_proven': False,
            'counter_snapshots': [r for r in rows if r.get('kind') == 'vpw_error_counter_snapshot'],
            'correlated_setting_get_count': len(gets)}


def audit_gt(path, source):
    rows = parse_rows(source)
    replayed = []
    replay_jsonl(path, replayed.append)
    summaries = [r for r in replayed if r.get('kind') == 'replay_summary']
    if len(summaries) != 1:
        raise ValueError('Missing GT replay summary')
    result = summaries[0]
    if (not result['source_fully_read'] or not result['replay_complete'] or not result['source_result_seen']
            or result['source_reported_failure'] or result['adapter_errors'] or result['outgoing_guard_violations']
            or result['undecoded_dvi_hex'] or result['input_sha256'] != sha256(source)):
        raise ValueError('GT capture has not completed a successful guarded replay')
    context = gt_context(replayed, rows)
    network = [r for r in replayed if r.get('kind') == 'network']
    physical = [bytes.fromhex(r['payload_hex']) for r in network]
    bad = [i for i, b in enumerate(physical) if len(b) < 2 or crc8_j1850(b[:-1]) != b[-1]]
    if bad:
        raise ValueError('GT physical CRC mismatch at network ordinals ' + repr(bad))
    tx = [r for r in replayed if r.get('kind') == 'recorded_tx_audit']
    return network, [b[:-1] for b in physical], {
        'strict_replay_complete': True, 'original_serial_chunks': result['serial_chunks'],
        'adapter_tx_frames': len(tx), 'adapter_rx_frames': result['adapter_frames'],
        'network_frames': len(network), 'adapter_errors': 0, 'outgoing_guard_violations': 0,
        'message_prefix_counts': dict(Counter(b[:-1][:4].hex() for b in physical)),
        'all_network_vpw_crcs_valid': True, 'checked_physical_crc_frames': len(physical),
        'context': context,
        'source_reported_success': True,
        'monotonic_timing_scope': 'GT serial receipt time, not physical edge time; no shared origin with AutoCal elapsed_ms.',
    }


def compare_data(auto_receipt, auto_journal, gt_path, gt_source, baseline):
    if len(baseline) != 524288 or sha256(baseline) != BASELINE_SHA or sha256(baseline[:64]) != PREFIX_SHA:
        raise ValueError('Baseline does not match the pinned512KiB image and64-byte prefix')
    auto_rx, auto = autocal_audit(auto_receipt, auto_journal)
    gt_network, gt_messages, gt = audit_gt(gt_path, gt_source)
    expected = [r['payload'] for r in auto_rx]
    # Only exact whole messages match. The GT physical CRC was validated before
    # stripping; no corrected header, reordering or fuzzy match is allowed.
    positions, cursor = [], 0
    for message in expected:
        while cursor < len(gt_messages) and gt_messages[cursor] != message:
            cursor += 1
        if cursor == len(gt_messages):
            raise ValueError('An AutoCal reply is missing from the GT ordered sequence')
        positions.append(cursor); cursor += 1
    def checked(index):
        return any(r['start'] <= index < r['end_exclusive']
                   for r in gt['context']['checked_network_ordinal_ranges_zero_based'])
    if any(not checked(index) for index in positions):
        raise ValueError('Common AutoCal replies precede checked GT capture context')
    candidates = []
    for index, message in enumerate(gt_messages):
        if not message.startswith(bytes.fromhex('6df01036')):
            continue
        extent = len(message) == 76 and message[:10] == REPLY_HEADER
        checksum = extent and sum(message[4:-2]) & 0xffff == int.from_bytes(message[-2:], 'big')
        equal = extent and message[10:-2] == baseline[:64]
        candidates.append({'gt_network_ordinal_zero_based': index,
            'within_checked_gt_capture_context': checked(index),
            'gt_source_line_end': gt_network[index]['source_line_end'],
            'gt_serial_chunk_end_monotonic_ns': gt_network[index]['host_monotonic_ns_at_chunk_end'],
            'physical_vpw_bytes': len(message) + 1, 'message_bytes_without_physical_crc': len(message),
            'message_sha256': sha256(message), 'physical_message_sha256': sha256(message + bytes([crc8_j1850(message)])),
            'exact_submode_address_extent': extent, 'block_additive_checksum_valid': checksum,
            'data_sha256': sha256(message[10:-2]) if extent else None,
            'equals_saved_baseline_prefix': equal,
            'same_message_in_autocal_rx': any(r['payload'] == message for r in auto_rx),
            'follows_last_common_autocal_reply_in_gt_order': bool(positions) and index > positions[-1]})
    matching = [r for r in candidates if r['within_checked_gt_capture_context'] and r['exact_submode_address_extent'] and r['block_additive_checksum_valid']
                and r['equals_saved_baseline_prefix']]
    anchors = [{'autocal_rx_ordinal_zero_based': i, 'autocal_journal_line_one_based': r['line'],
                'autocal_elapsed_ms': r['elapsed_ms'], 'gt_network_ordinal_zero_based': index,
                'gt_source_line_end': gt_network[index]['source_line_end'],
                'gt_serial_chunk_end_monotonic_ns': gt_network[index]['host_monotonic_ns_at_chunk_end'],
                'vpw_prefix_hex': r['payload'][:4].hex(), 'message_bytes': len(r['payload']),
                'message_sha256': sha256(r['payload'])} for i, (r, index) in enumerate(zip(auto_rx, positions))]
    # A valid baseline body alone may be stale. Preserve such observations but
    # qualify this session's delivery gap only after nonempty shared anchors.
    correlated = [r for r in matching if anchors and r['follows_last_common_autocal_reply_in_gt_order']]
    late_covered = auto['late_read_coverage']['eligible_for_no_delivery_conclusion']
    positive_gap = len(correlated) == 1 and not correlated[0]['same_message_in_autocal_rx'] and late_covered
    return {'schema': 'autocal-gt-fixed-prefix-comparison-v1',
        'scope': 'Completed paired application journals, exact ECM-response comparison and fixed64-byte baseline validation; offline audit only.',
        'autocal': auto, 'gt': gt, 'ordered_common_replies': anchors, 'data_candidates': candidates,
        'comparison': {'all_autocal_vpw_replies_found_in_gt_order': bool(anchors),
            'nonempty_ordered_reply_anchors_present': bool(anchors),
            'common_reply_count': len(anchors), 'matching_gt_prefix_reply_count': len(matching),
            'correlated_gt_prefix_reply_count': len(correlated),
            'autocal_late_read_coverage_complete': late_covered,
            'valid_prefix_observed_by_gt_but_not_delivered_to_autocal_host': positive_gap,
            'no_verified_prefix_reply_in_gt_capture': not matching,
            'physical_ecu_transmit_cause_proven': False,
            'valid_baseline_prefix_reply_observed_on_gt': bool(matching),
            'known_kernel_prefix_reply_correlated_to_session': bool(correlated),
            'autocal_read_qualified': False, 'flash_programming_qualified': False},
        'baseline': {'length': len(baseline), 'sha256': sha256(baseline), 'prefix_length': 64,
                     'prefix_sha256': sha256(baseline[:64]), 'data_exported': False},
        'limits': [
            'GT receives only source10 responses. It does not independently record the AutoCal request on VPW.',
            'The valid GT reply establishes reception of the expected kernel data on this bench; it does not locate the AutoCal physical receiver, firmware filter, buffer or USB-delivery fault.',
            'Exact shared replies establish ordered correlation, not synchronized clocks. Both timestamps describe host receipt rather than physical bus timing.',
            'A matching data reply before the shared reply anchors, or with no shared anchors, is retained as an uncorrelated observation and cannot establish this session delivery gap.',
            'A nonempty, incomplete, errored or unknown retained native read blocks the non-delivery conclusion; late bytes are not reconciled into the receive journal by this analyzer.',
            'No shorter ACK or repair is invented. Only a valid trailing GT VPW CRC is removed before whole-message comparison.',
            'A matching64-byte prefix does not verify the whole image, controller CRC ranges, erase/programming or interrupted-flash recovery.',
            'Successful GT software cleanup is checked separately from AutoCal failure closure; neither establishes electrical bus silence.',
            'Recorded setup acceptance proves only the exact acknowledged host-command lifecycle; its firmware semantics and receive-path effect remain unknown.',
            'No raw tune data, kernel bytes or complete data reply is exported. Inputs remain private and unchanged.',
        ], 'adapter_opened': False, 'al5_live_writes_enabled': False, 'ready_to_flash': False}


def inspect(receipt, journal, capture, baseline):
    paths = [Path(p) for p in (receipt, journal, capture, baseline)]
    helpers = [Path(__file__).with_name(n) for n in ('compare_autocal_gt_prefix.py', 'inspect_autocal_read_gap.py',
        'obdx_capture.py', 'obdx_speed.py', 'compare_vpw_read_capture.py', 'audit_trace_wrappers.py',
        'checksum.py', 'al5_segment.py', 'decode_trace_containers.py', 'inspect_trace_containers.py')]
    snapshots = {}
    for path in paths + helpers:
        if not 0 < path.stat().st_size <= MAX_INPUT:
            raise ValueError('Input exceeds existing16MiB analysis bound')
        snapshots[path] = path.read_bytes()
        if len(snapshots[path]) > MAX_INPUT:
            raise ValueError('Input grew beyond bound')
    result = compare_data(snapshots[paths[0]], snapshots[paths[1]], paths[2], snapshots[paths[2]], snapshots[paths[3]])
    if any(p.read_bytes() != raw for p, raw in snapshots.items()):
        raise ValueError('Evidence or implementation changed during analysis')
    result['inputs'] = {name: pin(p, snapshots[p]) for name, p in zip(('autocal_receipt', 'autocal_journal', 'gt_capture', 'baseline'), paths)}
    result['implementation'] = [pin(p, snapshots[p]) for p in helpers]
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('receipt', 'journal', 'capture', 'baseline', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    args = p.parse_args(argv)
    try:
        if args.output.exists():
            raise ValueError('Output already exists; no evidence overwrite')
        result = inspect(args.receipt, args.journal, args.capture, args.baseline)
        with args.output.open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(result, stream, indent=2); stream.write('\n')
    except (ValueError, OSError, KeyError, TypeError) as error:
        p.error(str(error))
    print(json.dumps(result['comparison']))


if __name__ == '__main__':
    main()
