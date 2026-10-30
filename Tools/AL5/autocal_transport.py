"""Offline replay of saved EFILive HTX host-interface envelopes.

This is not an AutoCal device driver or a USB-wire parser. It reads an existing,
hash-pinned HTX and reuses the established container and wrapper producers.
No adapter, DLL, IPC endpoint, serial port, or vehicle connection is opened.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import re

from al5_segment import sha256
from audit_trace_wrappers import framed_message
from checksum import crc16
from decode_trace_containers import decode, records, RECORD_BYTES
from inspect_trace_containers import MAX_INPUT
from validate_vm_buffers import read_bounded


# Raw route bytes, not controller service identifiers. Route interpretation is
# bounded to the supplied HTX evidence; unknown routes remain unknown.
BUS_ROUTES = {1: {b'\x00\x8a'}, 2: {b'\x10\x00', b'\x00\x00'}}
ADAPTER_ROUTES = {
    bytes.fromhex(value) for value in (
        '0182', '0382', '0482', '0582', '0682', '2383', '2483', '2e83', '0486',
        '1484', '1584')
}
EVIDENCE = (
    'Docs/AL5/AUTOCAL_TRANSPORT_STATIC.json',
    'Docs/AL5/EFILIVE_HOST_IPC.json',
    'Docs/AL5/VM_CALLBACK_OUTCOMES_STATIC.json',
    'Docs/AL5/AUTOCAL_GT_BENCH_20261029.json',
)


def span(data, offset):
    """Retain exact decoded-file provenance without exporting tune payloads."""
    return {'decoded_offset': offset, 'bytes': len(data), 'sha256': sha256(data)}


def envelope_evidence(record, ordinal):
    """Describe one binary HTX record, including unsupported/malformed shapes.

    ``framed_message`` owns wrapper acceptance and payload extraction. This
    function adds evidence fields, route classification, and the outer CRC.
    """
    if record['kind'] != 0x42:
        raise ValueError('A binary HTX record is required')
    wrapper = record['payload']
    wrapper_offset = record['offset'] + RECORD_BYTES
    framed = framed_message(record)
    route = wrapper[2:4] if len(wrapper) >= 4 else None
    result = {
        'record_ordinal': ordinal, 'record_offset': record['offset'],
        'record_channel': record['channel'], 'record_category': record['category'],
        'record_subtype': record['subtype'], 'date_serial_days': record['date'],
        'domain': 'saved_htx_host_interface_wrapper',
        'wrapper': span(wrapper, wrapper_offset),
        'raw_prefix_up_to_12_bytes_hex': wrapper[:12].hex(),
        'route_bytes_hex': None if route is None else route.hex(),
        'route_word_le16': None if route is None else int.from_bytes(route, 'little'),
        'declared_payload_bytes': int.from_bytes(wrapper[10:12], 'little') if len(wrapper) >= 12 else None,
        'framing_supported': framed is not None,
        'direction_inference': None, 'route_role': 'unknown',
        'payload': None, 'raw_metadata_4_through_9_hex': None,
        'outer_crc16': {'checked': False, 'matches': None},
        'trailing_byte_after_crc_hex': None,
        'sequence_number_semantics_verified': False,
        'response_pairing': None,
    }
    if framed is None:
        result['unsupported_reason'] = 'Wrapper prefix, channel, declared length, or exact record size is unsupported'
        return result
    direction, payload = framed
    payload_end = 12 + len(payload)
    observed = int.from_bytes(wrapper[payload_end:payload_end + 2], 'little')
    calculated = crc16(wrapper[:payload_end], 0)
    result.update({
        'direction_inference': direction,
        'payload': span(payload, wrapper_offset + 12),
        'raw_metadata_4_through_9_hex': wrapper[4:10].hex(),
        'outer_crc16': {
            'checked': True, 'matches': observed == calculated,
            'algorithm': 'CRC16 reflected polynomial A001, seed0000, no final XOR',
            'covered_wrapper_range': {'start': 0, 'end_exclusive': payload_end},
            'stored_little_endian_hex': wrapper[payload_end:payload_end + 2].hex(),
            'stored_value': observed, 'calculated_value': calculated,
            'crc_decoded_offset': wrapper_offset + payload_end,
            'scope': 'HTX outer host-interface wrapper only; not VPW payload CRC',
        },
        'trailing_byte_after_crc_hex': wrapper[-1:].hex() if record['channel'] == 2 else None,
    })
    if route in BUS_ROUTES.get(record['channel'], set()):
        result['route_role'] = 'bus_send_candidate' if record['channel'] == 1 else 'bus_receive_candidate'
    elif route in ADAPTER_ROUTES:
        result['route_role'] = 'adapter_local_candidate'
    # No payload-header scan: local transform bytes can resemble vehicle frames.
    return result


def replay_bytes(source):
    """Replay saved record order without matching requests, repairing, or sending."""
    decoded = decode(source)
    envelopes, others = [], []
    total = 0
    for ordinal, record in enumerate(records(decoded)):
        total += 1
        if record['kind'] == 0x42:
            envelopes.append(envelope_evidence(record, ordinal))
        else:
            others.append({'record_ordinal': ordinal, 'record_offset': record['offset'],
                           'record_channel': record['channel'], 'record_category': record['category'],
                           'record_subtype': record['subtype'], 'kind': record['kind'],
                           'date_serial_days': record['date'],
                           'payload': span(record['payload'], record['offset'] + RECORD_BYTES)})
    supported = [r for r in envelopes if r['framing_supported']]
    failures = [r['record_ordinal'] for r in supported if not r['outer_crc16']['matches']]
    unsupported = [r['record_ordinal'] for r in envelopes if not r['framing_supported']]
    return {
        'decoded_bytes': len(decoded), 'decoded_sha256': sha256(decoded),
        'records_consume_decoded_file': True, 'record_count': total,
        'binary_record_count': len(envelopes), 'other_record_count': len(others),
        'supported_wrapper_count': len(supported), 'unsupported_wrapper_record_ordinals': unsupported,
        'outer_crc_checked_count': len(supported), 'outer_crc_failed_record_ordinals': failures,
        'complete_outer_crc_agreement': bool(envelopes) and not unsupported and not failures,
        'unknown_route_record_ordinals': [r['record_ordinal'] for r in supported if r['route_role'] == 'unknown'],
        'role_counts': dict(sorted(Counter(r['route_role'] for r in envelopes).items())),
        'route_counts': [{'channel': ch, 'route_bytes_hex': route, 'count': count}
                         for (ch, route), count in sorted(Counter(
                             (r['record_channel'], r['route_bytes_hex'] or '') for r in envelopes).items())],
        'metadata_observation': {
            'raw_4_through_9_values': dict(sorted(Counter(r['raw_metadata_4_through_9_hex'] for r in supported).items())),
            'rx_trailing_byte_values': dict(sorted(Counter(r['trailing_byte_after_crc_hex'] for r in supported
                                                           if r['record_channel'] == 2).items())),
            'interpretation': 'Opaque values are preserved; no clock, sequence, status, or pairing semantics are assigned',
        },
        'envelopes': envelopes, 'other_records': others,
    }


def report(trace, expected_sha256):
    trace = Path(trace)
    if not isinstance(expected_sha256, str) or not re.fullmatch('[0-9a-fA-F]{64}', expected_sha256):
        raise ValueError('Expected trace SHA256 must contain 64 hex characters')
    source = read_bounded(trace, 1, MAX_INPUT)
    if sha256(source) != expected_sha256.lower():
        raise ValueError('Trace SHA256 differs from caller-pinned source')
    replay = replay_bytes(source)
    if read_bounded(trace, 1, MAX_INPUT) != source:
        raise ValueError('Source changed during replay')
    base = Path(__file__).resolve().parents[2]
    return {
        'schema_version': 1,
        'scope': 'Offline saved HTX envelope replay; not USB-wire framing or an active AutoCal transport',
        'input': {'path': str(trace.resolve()), 'bytes': len(source), 'sha256': sha256(source)},
        'replay': replay,
        'evidence': [{'path': path, 'sha256': sha256((base / path).read_bytes())} for path in EVIDENCE],
        'implementation_sha256': {name: sha256(Path(__file__).with_name(name).read_bytes()) for name in (
            Path(__file__).name, 'audit_trace_wrappers.py', 'decode_trace_containers.py',
            'inspect_trace_containers.py', 'checksum.py', 'al5_segment.py', 'validate_vm_buffers.py')},
        'limits': [
            'HTX is host logging evidence, not a captured AutoCal USB byte stream.',
            'Stored outer CRC agreement does not prove device execution, VPW CRC, bus completeness, or absence of synthesized log messages.',
            'Known bus-route classification does not decode controller services or identify physical transmitters.',
            'Adapter-local routes do not imply requests are safe, read-only, or independently callable.',
            'Opaque metadata and RX trailing bytes have no assigned sequence, time, status, or request/reply correlation semantics.',
            'Unknown routes and unsupported wrappers remain visible and are never repaired, filtered, or promoted to verified messages.',
            'This tool cannot open devices, transmit, perform firmware/object transforms, or authorize programming.',
        ],
        'usb_wire_framing_verified': False, 'device_identity_verified': False,
        'complete_bus_capture_proven': False, 'active_transport_implemented': False,
        'live_write_enabled': False, 'ready_to_flash': False, 'would_send': [],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', required=True, type=Path)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path, help='New JSON evidence file; never overwritten')
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.resolve() == args.trace.resolve():
        parser.error('Choose a new output path distinct from the input')
    try:
        result = report(args.trace, args.expected_sha256)
        with args.output.open('x', encoding='utf8', newline='\n') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')
    except (OSError, ValueError) as error:
        parser.error(str(error))
    replay = result['replay']
    print(json.dumps({'output': str(args.output.resolve()), 'record_count': replay['record_count'],
                      'binary_records': replay['binary_record_count'],
                      'unsupported_wrappers': len(replay['unsupported_wrapper_record_ordinals']),
                      'outer_crc_failures': len(replay['outer_crc_failed_record_ordinals']),
                      'active_transport_implemented': False, 'live_write_enabled': False}))
    return 0 if replay['complete_outer_crc_agreement'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
