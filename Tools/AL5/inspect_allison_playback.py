"""Inspect the observed Allison J1939/LCT v2 playback format, offline only.

The fixed record framing is supported by one complete demo file. Field meanings
are RP1210-style interpretations, not qualified wire traffic or programming proof.
No adapter, transport, target process or optional dependency is used.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct


HEADER = (b'[Allison Playback File]\r\nProtocol=J1939\r\nType=LCT\r\n'
          b'Version=2.0\r\n[Static]\r\n')
SEPARATOR = b'\r\n[Data]\r\n'
RECORD_SIZE = 30


def _record(raw, offset, index):
    length, flags = struct.unpack_from('<HH', raw)
    message = raw[4:4+length]
    payload = message[10:]
    return {
        'index': index, 'offset': offset, 'raw_hex': raw.hex(),
        'prefix_hex': raw[:4].hex(), 'message_length_low_word': length,
        'opaque_high_word': flags, 'message_hex': message.hex(),
        'unused_slot_hex': raw[4+length:22].hex(),
        'trailing_eight_hex': raw[22:].hex(),
        'timestamp_raw_big_endian': int.from_bytes(message[:4], 'big'),
        'timestamp_units': 'unknown',
        'header_interpretation': {
            'status': 'inferred_rp1210_style_not_wire_qualified',
            'pgn_raw_hex': message[4:7].hex(),
            'pgn_little_endian_candidate': int.from_bytes(message[4:7], 'little'),
            'priority_raw': message[7], 'source_address_candidate': message[8],
            'destination_address_candidate': message[9],
            'direction': 'not_established_by_playback_record',
        },
        'payload_hex': payload.hex(),
    }


def _counts(values):
    return dict(sorted(Counter(values).items()))


def _summary(records):
    timestamps = [r['timestamp_raw_big_endian'] for r in records]
    short_matches = Counter()
    for previous, current in zip(records, records[1:]):
        length = current['message_length_low_word']
        if length < 18:
            previous_slot = bytes.fromhex(previous['message_hex'] + previous['unused_slot_hex'])
            matches = bytes.fromhex(current['unused_slot_hex']) == previous_slot[length:]
            short_matches['same_as_previous_slot' if matches else 'different_from_previous_slot'] += 1
    special = {}
    for lead in ('12', '52', '20', '60', '2c', '6c', '44', '7f'):
        special[lead] = [r for r in records if r['payload_hex'].startswith(lead)][:12]
    identification = []
    for r in records:
        payload = bytes.fromhex(r['payload_hex'])
        if payload.startswith(b'\x62\x1a\x40'):
            value = payload[3:]
            identification.append({'offset': r['offset'], 'payload_hex': payload.hex(),
                                   'ascii_candidate': value.decode('ascii', errors='backslashreplace'),
                                   'status': 'identification_candidate_not_controller_qualification'})
    return {
        'record_count': len(records),
        'message_length_counts': _counts(str(r['message_length_low_word']) for r in records),
        'opaque_high_word_counts': _counts(f"0x{r['opaque_high_word']:04x}" for r in records),
        'payload_leading_byte_counts': _counts(r['payload_hex'][:2] or 'empty' for r in records),
        'pgn_raw_counts': _counts(r['header_interpretation']['pgn_raw_hex'] for r in records),
        'priority_address_bytes_counts': _counts(r['message_hex'][14:20] for r in records),
        'trailing_eight_counts': _counts(r['trailing_eight_hex'] for r in records),
        'timestamp_first_raw': timestamps[0] if timestamps else None,
        'timestamp_last_raw': timestamps[-1] if timestamps else None,
        'timestamp_units': 'unknown',
        'timestamp_backwards_count': sum(a > b for a, b in zip(timestamps, timestamps[1:])),
        'short_record_previous_slot_comparison': dict(short_matches),
        'special_payload_samples': special,
        'identification_candidates': identification[:12],
    }


def inspect_bytes(data, source='<bytes>', include_records=False):
    """Return complete or partial evidence; never scan ahead to recover framing."""
    report = {
        'schema': 'allison-playback-inspection-v1',
        'source': {'path': str(source), 'size_bytes': len(data),
                   'sha256': hashlib.sha256(data).hexdigest()},
        'format_scope': 'observed J1939 LCT Version=2.0 fixed 30-byte records',
        'interpretation_status': 'offline_observed_format_not_wire_qualified',
        'gates': {'transport_used': False, 'vehicle_commands_sent': False,
                  'programming_proven': False, 'recovery_proven': False,
                  'ready_to_flash': False, 'protocol_interpretation_qualified': False},
        'limitations': [
            'Framing was derived from one demo file; other playback variants are unsupported.',
            'Only the declared message length belongs to the message; unused and trailing bytes are opaque.',
            'A payload byte of 0x52 does not establish erase or programming behavior.',
            'Stored address fields do not establish transmitted requests or complete bidirectional capture.',
            'Timestamp units and opaque high-word semantics are unknown.',
        ],
        'complete': False, 'coverage': {'examined_end_offset': 0, 'unexamined_bytes': len(data)},
        'sections': {}, 'error': None,
    }
    section_records = {'static': [], 'data': []}
    offset = 0
    section = 'static'
    if not data.startswith(HEADER):
        report['error'] = {'code': 'unsupported_or_truncated_header', 'offset': 0}
    else:
        offset = len(HEADER)
        report['sections']['static'] = {'start_offset': offset}
        while offset < len(data):
            if section == 'static' and data.startswith(SEPARATOR, offset):
                report['sections']['static']['end_offset'] = offset
                offset += len(SEPARATOR)
                section = 'data'
                report['sections']['data'] = {'start_offset': offset}
                continue
            if len(data) - offset < RECORD_SIZE:
                report['error'] = {'code': 'truncated_record_or_separator', 'offset': offset,
                                   'remaining_bytes': len(data)-offset, 'section': section}
                break
            length = struct.unpack_from('<H', data, offset)[0]
            if not 10 <= length <= 18:
                report['error'] = {'code': 'invalid_message_length', 'offset': offset,
                                   'length_low_word': length, 'section': section}
                break
            raw = data[offset:offset+RECORD_SIZE]
            section_records[section].append(_record(raw, offset, len(section_records[section])))
            offset += RECORD_SIZE
        if report['error'] is None and section != 'data':
            report['error'] = {'code': 'missing_data_separator', 'offset': offset}
        report['complete'] = report['error'] is None and offset == len(data)
    report['coverage'] = {'examined_end_offset': offset, 'unexamined_bytes': len(data)-offset,
                          'parsed_record_bytes': sum(map(len, section_records.values())) * RECORD_SIZE,
                          'resynchronization_used': False}
    for name, records in section_records.items():
        info = report['sections'].setdefault(name, {})
        info.setdefault('end_offset', offset if name == section else None)
        info.update(_summary(records))
        if include_records:
            info['records'] = records
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--include-records', action='store_true')
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error('output already exists; refusing overwrite')
    try:
        data = args.input.read_bytes()
        report = inspect_bytes(data, args.input.resolve(), args.include_records)
        with args.output.open('x', encoding='utf-8') as handle:
            json.dump(report, handle, indent=2)
            handle.write('\n')
    except OSError as error:
        parser.error(str(error))
    print(json.dumps({'complete': report['complete'], 'error': report['error'],
                      'output': str(args.output.resolve()), 'coverage': report['coverage']}))
    return 0 if report['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
