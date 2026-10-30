"""Offline saved AutoCal setup/speed timeline; no transport or executable replay.

Records stay in file order. Temporal adjacency never supplies request context.
Only recognized exact small setup shapes and exact A0/A1 markers export bodies.
All other bodies, including local transformation inputs, remain length/digests.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from al5_segment import sha256
from audit_trace_wrappers import framed_message
from checksum import crc16
from decode_trace_containers import decode, records, RECORD_BYTES
from inspect_autocal_vpw_trace import checked_read, pin
from inspect_trace_containers import MAX_INPUT
from validate_vm_buffers import read_bounded


SETUP = {0x8603, 0x8604, 0x8800, 0x8b01}
SMALL_SHAPES = {(1, 0x8603): {4}, (2, 0x8603): {0},
                (1, 0x8604): {1, 6}, (2, 0x8604): {0},
                (1, 0x8800): {2}, (2, 0x8800): {0},
                (1, 0x8b01): {4}, (2, 0x8b01): {1}}
MARKERS = {bytes.fromhex('6cfef0a0'): 'A0', bytes.fromhex('6cfef0a1'): 'A1'}


def analyze_bytes(source):
    decoded = decode(source)
    parsed = list(records(decoded))
    if not parsed:
        raise ValueError('Empty trace records')
    first_date = parsed[0]['date']
    envelopes, unsupported, crc_bad = [], [], []
    final_data = None
    for ordinal, row in enumerate(parsed):
        if row['kind'] != 0x42:
            continue
        raw = row['payload']
        framed = framed_message(row)
        payload = None if framed is None else framed[1]
        word = int.from_bytes(raw[2:4], 'little') if len(raw) >= 4 else None
        crc_ok = None
        if payload is None:
            unsupported.append(ordinal)
        else:
            end = 12 + len(payload)
            crc_ok = crc16(raw[:end], 0) == int.from_bytes(raw[end:end + 2], 'little')
            if not crc_ok:
                crc_bad.append(ordinal)
        bus_candidate = payload is not None and (
            row['channel'] == 1 and word == 0x8a00 or
            row['channel'] == 2 and word in (0x10, 0))
        marker = MARKERS.get(payload) if row['channel'] == 1 and word == 0x8a00 else None
        small = payload is not None and len(payload) in SMALL_SHAPES.get((row['channel'], word), ())
        event = {
            'record_ordinal_zero_based': ordinal,
            'record_decoded_offset': row['offset'],
            'wrapper_decoded_offset': row['offset'] + RECORD_BYTES,
            'saved_date_f64_le_hex': struct.pack('<d', row['date']).hex(),
            'saved_date_serial_days': row['date'],
            'elapsed_from_first_record_ms': (row['date'] - first_date) * 86400000,
            'channel': row['channel'],
            'raw_header_up_to_12_bytes_hex': raw[:12].hex(),
            'tx_command_le16': word if row['channel'] == 1 else None,
            'rx_raw_header_bytes_2_through_5_hex': raw[2:6].hex() if row['channel'] == 2 else None,
            'setup_header_candidate': word in SETUP,
            'wrapper_bytes': len(raw), 'wrapper_sha256': sha256(raw),
            'payload_bytes': None if payload is None else len(payload),
            'payload_sha256': None if payload is None else sha256(payload),
            'literal_small_setup_payload_hex': payload.hex() if small else None,
            'exact_tx_marker': marker,
            'literal_exact_marker_hex': payload.hex() if marker else None,
            'bus_context_candidate': bus_candidate,
            'bus_prefix_up_to_four_bytes_hex': payload[:4].hex() if bus_candidate else None,
            'outer_crc_matches': crc_ok,
            'request_context': None, 'response_pairing': None,
        }
        envelopes.append(event)
        # A narrow observed E54 read-data prefix, never an inner payload scan.
        if row['channel'] == 2 and bus_candidate and payload.startswith(bytes.fromhex('6df01036')) and len(payload) > 4:
            final_data = ordinal
    markers = [e for e in envelopes if e['exact_tx_marker'] is not None]
    setups = [e for e in envelopes if e['setup_header_candidate']]
    local_tx = [e for e in envelopes if e['channel'] == 1 and e['tx_command_le16'] != 0x8a00]
    marker_windows = []
    for marker in markers:
        index = envelopes.index(marker)
        nearby = envelopes[max(0, index - 2):index + 4]
        marker_windows.append({'marker': marker,
                               'nearby_binary_records_in_file_order': nearby,
                               'nearby_is_request_response_pairing': False})
    intervals = []
    for left, right in zip(markers, markers[1:]):
        lo, hi = left['record_ordinal_zero_based'], right['record_ordinal_zero_based']
        selected = [e for e in envelopes if lo < e['record_ordinal_zero_based'] < hi]
        intervals.append({
            'from_marker': left['exact_tx_marker'], 'to_marker': right['exact_tx_marker'],
            'from_record': lo, 'to_record': hi,
            'saved_log_delta_ms': (right['saved_date_serial_days'] - left['saved_date_serial_days']) * 86400000,
            'intervening_binary_records_in_file_order': selected,
            'intervening_nonbus_tx_record_ordinals': [e['record_ordinal_zero_based'] for e in selected
                                                     if e['channel'] == 1 and e['tx_command_le16'] != 0x8a00],
            'physical_speed_or_wait_duration_proven': False})
    tx_setup_counts = Counter(f"{e['tx_command_le16']:04X}" for e in setups if e['channel'] == 1)
    return {
        'decoded_bytes': len(decoded), 'decoded_sha256': sha256(decoded),
        'record_count': len(parsed), 'binary_record_count': len(envelopes),
        'records_consume_decoded_file': True,
        'unsupported_wrapper_record_ordinals': unsupported,
        'outer_crc_failed_record_ordinals': crc_bad,
        'timestamp_rule': 'Record order is authoritative. The saved f64 serial-day field is preserved bit-for-bit; deltas multiply by 86400000 ms/day. Epoch, timezone, clock monotonicity and wire timing are not established.',
        'timestamp_regression_record_ordinals': [i for i in range(1, len(parsed)) if parsed[i]['date'] < parsed[i - 1]['date']],
        'setup_tx_counts': {f'{word:04X}': tx_setup_counts[f'{word:04X}'] for word in sorted(SETUP)},
        'setup_envelopes_in_file_order': setups,
        'marker_windows': marker_windows, 'between_markers': intervals,
        'all_nonbus_tx_in_file_order': local_tx,
        'last_observed_e54_36_data_record': final_data,
        'after_last_observed_e54_36_data_binary_records': None if final_data is None else [e for e in envelopes if e['record_ordinal_zero_based'] > final_data],
        'response_pairing': None, 'speed_change_verified': False,
    }


def inspect(inputs):
    names = ('al5_segment.py', 'audit_trace_wrappers.py', 'checksum.py', 'decode_trace_containers.py',
             'inspect_autocal_vpw_trace.py', 'inspect_trace_containers.py', 'validate_vm_buffers.py')
    helpers = [(p, p.read_bytes()) for p in [Path(__file__)] + [Path(__file__).with_name(n) for n in names]]
    loaded = [(Path(path), checked_read(path, expected)) for path, expected in inputs]
    if not loaded:
        raise ValueError('At least one trace is required')
    cases = []
    for path, source in loaded:
        result = analyze_bytes(source)
        result['source'] = pin(path, source)
        cases.append(result)
    if any(read_bounded(path, 1, MAX_INPUT) != source for path, source in loaded):
        raise ValueError('Input changed during analysis')
    if any(path.read_bytes() != source for path, source in helpers):
        raise ValueError('Implementation source changed during analysis')
    return {
        'schema': 'autocal-saved-speed-timeline-v1', 'traces': cases,
        'implementation': [pin(path, source) for path, source in helpers],
        'limits': [
            'File-only evidence; no adapter, target executable, VM callback or vehicle access.',
            'Setup-looking RX headers are candidates until an independent caller supplies requested command context; file adjacency never pairs requests/replies.',
            'RX raw 1000/0000 groups are returned metadata in bus-request context, not commands.',
            'Setup RX payloads are opaque: empty is not proof of device success; 8B01 byte01 is not decoded as success.',
            'Exact A0/A1 messages are observed protocol markers; saved host timing and unchanged metadata do not prove physical 1x/4x speed.',
            'All local TX headers are inventoried, including large transform operations; payloads are hashed without inner-pattern scans or tune export.',
            'An absent local command means absent from this saved trace only, not absent from firmware or earlier initialization.',
            'A failed-license W trace is not a successful flash, erase or recovery test.'],
        'adapter_opened': False, 'live_write_enabled': False, 'ready_to_flash': False, 'would_send': [],
    }


def setup_reply_corpus(source):
    """Private exact small frames for a caller-context projection, never replay.

    The context is deliberately selected from the observed echoed header for
    offline testing. A preceding TX is only provenance, not a response pair.
    Oversized/unrecognized bodies are rejected rather than exported.
    """
    cases = []
    previous_tx = None
    for ordinal, row in enumerate(records(decode(source))):
        framed = framed_message(row)
        if framed is None:
            continue
        raw, payload = row['payload'], framed[1]
        word = int.from_bytes(raw[2:4], 'little')
        if row['channel'] == 1:
            previous_tx = {'record_ordinal_zero_based': ordinal,
                           'tx_command_le16': word, 'wrapper_sha256': sha256(raw),
                           'payload_bytes': len(payload), 'payload_sha256': sha256(payload)}
        if row['channel'] != 2 or word not in SETUP:
            continue
        if len(payload) not in SMALL_SHAPES[(2, word)]:
            raise ValueError('Setup corpus body is outside exact small observed shapes')
        end = 12 + len(payload)
        crc_ok = crc16(raw[:end], 0) == int.from_bytes(raw[end:end + 2], 'little')
        cases.append({
            'source_sha256': sha256(source), 'record_ordinal_zero_based': ordinal,
            'record_decoded_offset': row['offset'],
            'direction': 'device_to_host', 'requested_command_context': f'0x{word:04X}',
            'wrapper_hex': raw.hex(), 'wrapper_sha256': sha256(raw),
            'outer_crc_matches': crc_ok, 'payload_bytes': len(payload),
            'payload_sha256': sha256(payload), 'opaque_header_4_9_hex': raw[4:10].hex(),
            'context_basis': 'Offline hypothesis selected from the echo header, not a recovered request association',
            'previous_observed_tx': previous_tx, 'response_pairing': None,
            'expected': {'outer_crc_matches': crc_ok, 'header_echo_matches_selected_context': True,
                         'error_marker_present': False, 'payload_hex': payload.hex(),
                         'received_payload_bytes': len(payload), 'device_success': None}})
    return cases


def inspect_setup_reply_corpus(inputs):
    loaded = [(Path(path), checked_read(path, expected)) for path, expected in inputs]
    if not loaded:
        raise ValueError('At least one trace is required')
    cases = [case for _, source in loaded for case in setup_reply_corpus(source)]
    if any(read_bounded(path, 1, MAX_INPUT) != source for path, source in loaded):
        raise ValueError('Input changed during corpus analysis')
    return {'schema_version': 1, 'sources': [pin(path, source) for path, source in loaded],
            'rx_context_assumed_for_projection_tests': True, 'rx_request_pairing_established': False,
            'physical_protocol_validation': False, 'receive_cases': len(cases), 'cases': cases}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', nargs=2, action='append', required=True, metavar=('PATH', 'SHA256'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--private-setup-corpus', type=Path,
                        help='Optional exact small setup RX envelopes with explicitly assumed contexts, never replay')
    args = parser.parse_args(argv)
    try:
        if args.output.exists() or args.private_setup_corpus is not None and args.private_setup_corpus.exists():
            raise ValueError('Output already exists; preserve prior artifacts and select a new path')
        if args.private_setup_corpus is not None and args.output.resolve() == args.private_setup_corpus.resolve():
            raise ValueError('Report and private corpus require distinct output paths')
        result = inspect(args.trace)
        corpus = None if args.private_setup_corpus is None else inspect_setup_reply_corpus(args.trace)
        with args.output.open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')
        if corpus is not None:
            with args.private_setup_corpus.open('x', encoding='utf-8', newline='\n') as stream:
                json.dump(corpus, stream, indent=2)
                stream.write('\n')
    except (OSError, ValueError, KeyError) as error:
        parser.error(str(error))
    print(json.dumps({'output': str(args.output.resolve()), 'traces': len(result['traces']), 'adapter_opened': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
