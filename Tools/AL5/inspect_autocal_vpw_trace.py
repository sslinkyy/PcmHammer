"""File-only HTX bus-context/setup inventory; never an AutoCal transport.

TX command 8A00 is distinguished from observed RX raw header groups. RX
bytes 2:6 are not a command route, and this tool cannot supply request context
or pair responses. Only exact small setup payloads are exported literally.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from al5_segment import sha256
from audit_trace_wrappers import framed_message
from checksum import crc16
from decode_trace_containers import decode, records, RECORD_BYTES
from inspect_trace_containers import MAX_INPUT
from validate_vm_buffers import read_bounded


TX_BUS = bytes.fromhex('008a')
RX_OBSERVED_GROUPS = {bytes.fromhex('1000'), bytes.fromhex('0000')}
# These are observed shapes, not permission to send nor decoded setter semantics.
SETUP_SHAPES = {(1, '0386'): 4, (2, '0386'): 0,
                (1, '0486'): 6, (2, '0486'): 0,
                (1, '018b'): 4, (2, '018b'): 1}
MARKERS = {bytes.fromhex('6cfef0a0'): 'A0', bytes.fromhex('6cfef0a1'): 'A1'}
COLUMNS = ['record_ordinal_zero_based', 'record_decoded_offset', 'channel',
           'raw_header_up_to_12_bytes_hex', 'wrapper_bytes', 'wrapper_sha256',
           'payload_bytes', 'payload_sha256', 'outer_crc_matches',
           'bus_context_candidate', 'bus_header_service_prefix_hex']


def pin(path, raw):
    return {'path': str(Path(path).resolve()), 'bytes': len(raw), 'sha256': sha256(raw)}


def checked_read(path, expected, maximum=MAX_INPUT):
    if not isinstance(expected, str) or not re.fullmatch('[0-9a-fA-F]{64}', expected):
        raise ValueError('Expected SHA256 must be exactly 64 hex characters')
    raw = read_bounded(Path(path), 1, maximum)
    if sha256(raw) != expected.lower():
        raise ValueError(f'Source SHA256 mismatch: {path}')
    return raw


def sequence_sha256(messages):
    h = hashlib.sha256()
    for message in messages:
        h.update(len(message).to_bytes(4, 'big'))
        h.update(message)
    return h.hexdigest()


def analyze_bytes(source):
    decoded = decode(source)
    parsed = list(records(decoded))
    ledger, envelopes, bus, setup, markers, unsupported, crc_bad = [], [], [], [], [], [], []
    for ordinal, row in enumerate(parsed):
        if row['kind'] != 0x42:
            continue
        wrapper = row['payload']
        framed = framed_message(row)
        payload = None if framed is None else framed[1]
        crc_ok = None
        if payload is not None:
            end = 12 + len(payload)
            crc_ok = int.from_bytes(wrapper[end:end + 2], 'little') == crc16(wrapper[:end], 0)
            if not crc_ok:
                crc_bad.append(ordinal)
        else:
            unsupported.append(ordinal)
        group = wrapper[2:4]
        # This is an empirical context candidate, not an RX route dispatch rule.
        context = payload is not None and ((row['channel'] == 1 and group == TX_BUS)
                   or (row['channel'] == 2 and group in RX_OBSERVED_GROUPS))
        header_ok = context and len(payload) >= 4 and payload[0] in (0x6c, 0x6d, 0x8c)
        prefix = payload[:4].hex() if header_ok else None
        item = {'record': ordinal, 'offset': row['offset'], 'channel': row['channel'],
                'group': group.hex(), 'header': wrapper[:12].hex(), 'payload': payload,
                'crc_ok': crc_ok, 'context': context, 'header_ok': header_ok,
                'word2': wrapper[2:6].hex(), 'word6': wrapper[6:10].hex()}
        envelopes.append(item)
        ledger.append([ordinal, row['offset'], row['channel'], wrapper[:12].hex(),
                       len(wrapper), sha256(wrapper), None if payload is None else len(payload),
                       None if payload is None else sha256(payload), crc_ok, context, prefix])
        if context:
            bus.append(item)
        shape = SETUP_SHAPES.get((row['channel'], group.hex()))
        if shape is not None and payload is not None and len(payload) == shape:
            setup.append({'record_ordinal_zero_based': ordinal, 'record_decoded_offset': row['offset'],
                          'wrapper_decoded_offset': row['offset'] + RECORD_BYTES,
                          'payload_decoded_offset': row['offset'] + RECORD_BYTES + 12,
                          'channel': row['channel'], 'raw_header_hex': wrapper[:12].hex(),
                          'tx_command_le16': int.from_bytes(group, 'little') if row['channel'] == 1 else None,
                          'rx_raw_bytes_2_through_5_hex': wrapper[2:6].hex() if row['channel'] == 2 else None,
                          'literal_small_setup_payload_hex': payload.hex(), 'outer_crc_matches': crc_ok,
                          'request_response_pairing': None, 'payload_semantics_verified': False})
        if row['channel'] == 1 and group == TX_BUS and payload in MARKERS:
            markers.append({'name': MARKERS[payload], 'record_ordinal_zero_based': ordinal,
                            'record_decoded_offset': row['offset'], 'raw_header_hex': wrapper[:12].hex(),
                            'bus_header_service_prefix_hex': prefix, 'outer_crc_matches': crc_ok,
                            'preceding_setup_tx_record': next((s['record_ordinal_zero_based'] for s in reversed(setup)
                                                              if s['channel'] == 1), None)})
    first = bus[0]['record'] if bus else None
    a1 = [m['record_ordinal_zero_based'] for m in markers if m['name'] == 'A1']
    def histogram(values):
        return dict(sorted(Counter(values).items()))
    groups = []
    for ch, raw_group in sorted({(b['channel'], b['group']) for b in bus}):
        selected = [b for b in bus if b['channel'] == ch and b['group'] == raw_group]
        groups.append({'channel': ch, 'raw_bytes_2_and_3_hex': raw_group,
                       'meaning': 'TX command bytes' if ch == 1 else 'Observed RX raw grouping only; not a route',
                       'count': len(selected), 'record_ordinals': [b['record'] for b in selected],
                       'payload_length_histogram': histogram(len(b['payload']) for b in selected),
                       'raw_bytes_2_through_5_histogram': histogram(b['word2'] for b in selected),
                       'raw_bytes_6_through_9_histogram': histogram(b['word6'] for b in selected),
                       'unrecognized_payload_prefix_records': [b['record'] for b in selected if not b['header_ok']]})
    split = None
    if len(a1) == 1:
        split = {'a1_record_ordinal_zero_based': a1[0],
                 'before_a1_tx_bytes_6_through_9': histogram(b['word6'] for b in bus if b['channel'] == 1 and b['record'] < a1[0]),
                 'a1_and_later_tx_bytes_6_through_9': histogram(b['word6'] for b in bus if b['channel'] == 1 and b['record'] >= a1[0]),
                 'physical_speed_or_flag_meaning_proven': False}
    report = {'decoded_bytes': len(decoded), 'decoded_sha256': sha256(decoded),
              'record_count': len(parsed), 'binary_record_count': len(envelopes),
              'nonbinary_record_count': len(parsed) - len(envelopes),
              'unsupported_wrapper_record_ordinals': unsupported, 'outer_crc_failed_record_ordinals': crc_bad,
              'records_consume_decoded_file': True, 'binary_record_columns': COLUMNS, 'binary_records': ledger,
              'offsets': 'Decoded HTX record offset +18 is wrapper start; +30 is framed payload start. No encoded-file offset is inferred.',
              'first_bus_context_candidate_record': first,
              'pre_first_bus_binary_record_ordinals': [e['record'] for e in envelopes if first is not None and e['record'] < first],
              'pre_first_bus_tx_command_sequence': [{'record': e['record'], 'command_bytes_hex': e['group'], 'payload_bytes': None if e['payload'] is None else len(e['payload'])}
                                                   for e in envelopes if first is not None and e['record'] < first and e['channel'] == 1],
              'observed_bus_header_groups': groups, 'small_setup_events': setup,
              'speed_marker_candidates': markers, 'same_tx_header_field_across_a1': split,
              'rx_request_context_supplied': False, 'rx_route_verified': False, 'response_pairing': None}
    return report, bus


def correlate_saved_gt(trace_source_hash, trace_report, bus, gt):
    """Bind the existing forensic report; compare exact message digests, not pairs."""
    if trace_source_hash not in [s['sha256'] for s in gt['sources']]:
        return None
    window = gt['trace_window']
    if trace_report['decoded_sha256'] != window['decoded_trace_sha256']:
        raise ValueError('GT review decoded trace does not match this HTX')
    start, end = window['a1_record_ordinal_zero_based'], window['final_data_record_ordinal_zero_based']
    selected = [b for b in bus if start < b['record'] <= end]
    if any(not b['header_ok'] or not b['crc_ok'] for b in selected):
        raise ValueError('GT comparison window has unsupported/CRC-invalid HTX candidates')
    expected = [b['payload'] for b in selected]
    literal = gt['literal_comparison']
    if len(expected) != literal['expected_count'] or sequence_sha256(expected) != literal['expected_sequence_sha256']:
        raise ValueError('Reconstructed candidate sequence differs from prior GT review')
    expected_counts = Counter((len(m), sha256(m)) for m in expected)
    observed_counts = Counter((f['message_without_crc']['bytes'], f['message_without_crc']['sha256']) for f in gt['all_frames'])
    missing, extra = expected_counts - observed_counts, observed_counts - expected_counts
    if sum(missing.values()) != literal['missing_count'] or sum(extra.values()) != literal['extra_count']:
        raise ValueError('GT digest-count comparison contradicts saved report')
    def compact(counter):
        return [{'bytes': key[0], 'sha256': key[1], 'count': count} for key, count in sorted(counter.items())]
    valid_observed = Counter((f['message_without_crc']['bytes'], f['message_without_crc']['sha256'])
                             for f in gt['all_frames'] if f['physical_crc_valid'])
    channel_counts = {
        channel: Counter((len(b['payload']), sha256(b['payload'])) for b in selected if b['channel'] == channel)
        for channel in (1, 2)
    }
    shared_keys = set(channel_counts[1]) & set(channel_counts[2])
    by_channel = []
    for channel in (1, 2):
        counts = channel_counts[channel]
        exclusive = Counter({key: count for key, count in counts.items() if key not in shared_keys})
        by_channel.append({'channel': channel, 'htx_occurrences': sum(counts.values()),
                           'matching_valid_crc_gt_body_occurrences_upper_bound': sum((counts & valid_observed).values()),
                           'exclusive_channel_matching_occurrences': sum((exclusive & valid_observed).values())})
    return {'method': 'Exact message length/SHA256 multiset comparison to pinned prior GT report. No individual pairing or alignment assigned.',
            'window': {'a1_exclusive_record': start, 'final_data_inclusive_record': end},
            'expected_messages': len(expected), 'observed_gt_messages': sum(observed_counts.values()),
            'expected_ordered_sequence_sha256': sequence_sha256(expected),
            'expected_sequence_matches_prior_report': True,
            'matching_occurrences': sum((expected_counts & observed_counts).values()),
            'valid_gt_body_matches_by_htx_channel': by_channel,
            'htx_channel_payload_digests_disjoint': not shared_keys,
            'shared_channel_payloads': [
                {'bytes': key[0], 'sha256': key[1], 'tx_occurrences': channel_counts[1][key],
                 'rx_occurrences': channel_counts[2][key], 'valid_gt_occurrences': valid_observed[key]}
                for key in sorted(shared_keys)],
            'channel_attribution_limit': 'Per-channel upper bounds independently reuse observed counts and must not be summed when payloads overlap. Exclusive matches use only digests present in one HTX channel; neither establishes a physical sender.',
            'gt_body_definition': 'Prior forensic report removes exactly its one declared trailing GT CRC byte. HTX payload is otherwise compared verbatim, with no prefix stripping.',
            'missing': compact(missing), 'extra': compact(extra),
            'gt_valid_crc_frames': gt['valid_crc_frame_count'], 'gt_invalid_crc_frames': gt['invalid_or_absent_crc_frame_count'],
            'strict_qualification_passed': gt['qualification_passed'],
            'baseline_ordered_htx_messages_identical': gt['baseline_htx_comparison']['ordered_trace_messages_identical'],
            'baseline_observed_data_equal': gt['baseline_htx_comparison']['observed_data_equal'],
            'complete_bus_capture_proven': False}


def inspect(inputs, gt_input=None):
    helpers = [Path(__file__)] + [Path(__file__).with_name(n) for n in ('audit_trace_wrappers.py', 'decode_trace_containers.py', 'checksum.py', 'al5_segment.py', 'inspect_trace_containers.py', 'validate_vm_buffers.py')]
    helper_bytes = [(p, p.read_bytes()) for p in helpers]
    helper_pins = [pin(p, raw) for p, raw in helper_bytes]
    loaded = [(Path(p), checked_read(p, h)) for p, h in inputs]
    if not loaded:
        raise ValueError('At least one trace is required')
    gt_loaded = None if gt_input is None else (Path(gt_input[0]), checked_read(*gt_input, maximum=16 * 1024 * 1024))
    gt = None if gt_loaded is None else json.loads(gt_loaded[1])
    cases = []
    for path, raw in loaded:
        case, bus = analyze_bytes(raw)
        case['source'] = pin(path, raw)
        case['prior_gt_correspondence'] = None if gt is None else correlate_saved_gt(sha256(raw), case, bus, gt)
        cases.append(case)
    for path, raw in loaded + ([] if gt_loaded is None else [gt_loaded]):
        if read_bounded(path, 1, max(MAX_INPUT, len(raw))) != raw:
            raise ValueError('Input changed during analysis')
    if any(p.read_bytes() != raw for p, raw in helper_bytes):
        raise ValueError('Implementation source changed during analysis')
    return {'schema': 'autocal-vpw-saved-trace-context-v1', 'scope': 'Offline saved E54 HTX setup and bus-context candidates; no generic replay or adapter access',
            'traces': cases, 'prior_gt_report': None if gt_loaded is None else pin(*gt_loaded),
            'implementation': helper_pins,
            'limits': ['RX bytes 2:6 are raw returned metadata/status in native bus-request context; raw 1000/0000 groups are not command routes.',
                       'No request context is recovered by this empirical grouping and no RX/TX pairing is inferred.',
                       'Bus candidate payloads begin at wrapper offset12; only their first four header/service bytes are shown. No scan within local payloads occurs.',
                       'Only exact small 0386/0486/018b setup shapes export payload literals; all other payloads are represented by length and SHA256.',
                       'Observed A0/A1 messages and unchanged TX fields do not prove physical speed, initialization completeness or setting semantics.',
                       'A saved failed-license W trace contains loader-related traffic but is not a completed flash or recovery demonstration.',
                       'Previous GT comparison is forensic and includes invalid CRC/missing/extra frames; digest agreement is not losslessness or electrical noninterference.',
                       'HTX framing/outer CRC checks do not establish physical bus CRC, full USB capture, or device execution.'],
            'adapter_opened': False, 'active_transport_implemented': False, 'complete_bus_capture_proven': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', nargs=2, action='append', required=True, metavar=('PATH', 'SHA256'))
    parser.add_argument('--gt-review', nargs=2, metavar=('PATH', 'SHA256'))
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = inspect(args.trace, args.gt_review)
        with args.output.open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')
    except (OSError, ValueError, KeyError) as error:
        parser.error(str(error))
    print(json.dumps({'output': str(args.output.resolve()), 'traces': len(result['traces']), 'adapter_opened': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
