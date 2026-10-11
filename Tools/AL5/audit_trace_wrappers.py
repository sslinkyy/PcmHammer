"""Redacted audit of every binary record in saved AL5 write traces; no transport."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct
from al5_segment import sha256
from decode_trace_containers import decode, records, NAME


def recognized_header(message):
    if len(message) < 4 or message[0] not in (0x6C, 0x6D, 0x8C):
        return False
    return (message[1] in (0x18, 0xFE) and message[2] in (0xF0, 0xF1) or
            message[1] in (0xF0, 0xF1) and message[2] == 0x18)


def key(message):
    result = message[:4].hex()
    if message[3] in (0x36, 0x76) and len(message) > 4:
        result += ':' + hex(message[4])
    return result


def framed_message(record):
    """Return the direction and bytes of one complete known binary wrapper.

    Header classification belongs to the caller; an unrecognized vehicle
    message can still have a fully supported wrapper.
    """
    payload = record['payload']
    if record['kind'] != 0x42 or len(payload) < 14:
        return None
    length = struct.unpack_from('<H', payload, 10)[0]
    if payload[:2] == b'\x01\x54' and record['channel'] == 1 and len(payload) == length + 14:
        direction = 'host_tx_candidate'
    elif payload[:2] == b'\x01\x52' and record['channel'] == 2 and len(payload) == length + 15:
        direction = 'device_rx_candidate'
    else:
        return None
    return direction, payload[12:12 + length]


def analyze(path):
    path = Path(path)
    match = NAME.fullmatch(path.name)
    if not match or (match[4] or match[5]).upper() != 'W':
        raise ValueError('explicit saved AL5 W trace required')
    source = path.read_bytes()
    parsed = list(records(decode(source)))
    shapes = Counter(); services = Counter(); diagnostic = Counter()
    binary_count = unsupported = supported = 0
    destructive = Counter(); responses = Counter()
    for record in parsed:
        if record['kind'] != 0x42:
            continue
        binary_count += 1
        payload = record['payload']
        # Two bytes identify the wrapper command, not private payload contents.
        shapes[f"channel={record['channel']},command={payload[:2].hex()},subtype={record['subtype']}"] += 1
        framed = framed_message(record)
        message = framed[1] if framed is not None else None
        if message is not None:
            supported += 1
            if recognized_header(message):
                services[key(message)] += 1
                if message[1] in (0x18, 0xFE) and message[3] == 0x36 and len(message) >= 5:
                    if message[4] in (0, 0xEE, 0xFF):
                        destructive[hex(message[4])] += 1
                if message[1] in (0xF0, 0xF1) and message[3] == 0x76 and len(message) >= 6:
                    responses[hex(message[5])] += 1
        else:
            unsupported += 1
            # Unframed signatures are diagnostic only: loader bytes can mimic headers.
            for offset in range(max(0, len(payload) - 3)):
                candidate = payload[offset:offset + 6]
                if recognized_header(candidate):
                    diagnostic[key(candidate)] += 1
    return {'source_name': path.name, 'source_sha256': sha256(source),
            'record_count': len(parsed), 'binary_records': binary_count,
            'supported_wrapper_records': supported, 'unsupported_wrapper_records': unsupported,
            'binary_wrapper_counts': dict(sorted(shapes.items())),
            'framed_service_counts': dict(sorted(services.items())),
            'framed_destructive_request_counts': dict(destructive),
            'framed_mode76_status_counts': dict(responses),
            'unsupported_record_signature_hits': dict(sorted(diagnostic.items())),
            'complete_programming_exchange_verified': False, 'operation_outcome': None}


def report(paths):
    cases = [analyze(path) for path in paths]
    if not cases:
        raise ValueError('no saved W traces')
    return {'scope': 'Every binary record in supplied saved W traces inventoried; known wrappers accept module/global/tester address variants. Unsupported records scanned for diagnostic signatures only.',
            'limits': 'Complete container framing is not complete bus capture. Unframed signatures are not messages; checksum, missing traffic, programming outcomes and recovery remain unverified. No private text, loader or raw payload exported.',
            'generator_sha256': sha256(Path(__file__).read_bytes()),
            'trace_count': len(cases), 'traces': cases,
            'complete_programming_exchange_verified': False,
            'physical_transport_verified': False, 'ready_to_flash': False,
            'live_write_enabled': False, 'erase_scope': None, 'would_send': []}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--trace', type=Path, action='append', required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    result = report(args.trace)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'traces': result['trace_count'], 'complete_programming_exchange_verified': False}))
