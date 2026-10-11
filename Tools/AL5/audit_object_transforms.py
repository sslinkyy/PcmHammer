"""Census of saved host-interface 0x8414/0x8415 records; no decoder or I/O."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct
from al5_segment import sha256
from decode_trace_containers import decode, records, NAME
from inspect_trace_containers import MAX_INPUT
from validate_vm_buffers import read_bounded
from audit_trace_wrappers import framed_message

COMMANDS = {0x8414: 'transform_initialization_candidate',
            0x8415: 'transform_chunk_candidate'}


def census(parsed):
    entries = []
    shapes = Counter()
    binary_count = 0
    for ordinal, record in enumerate(parsed):
        if record['kind'] != 0x42:
            continue
        binary_count += 1
        payload = record['payload']
        shapes[f"channel={record['channel']},prefix={payload[:2].hex()}"] += 1
        if len(payload) < 4 or payload[:2] not in (b'\x01\x54', b'\x01\x52'):
            continue
        command = struct.unpack_from('<H', payload, 2)[0]
        if command not in COMMANDS:
            continue
        framed = framed_message(record)
        entry = {'record_ordinal': ordinal, 'record_offset': record['offset'],
                 'channel': record['channel'], 'subtype': record['subtype'],
                 'command_le16': command, 'role_inference': COMMANDS[command],
                 'wrapper_sha256': sha256(payload), 'wrapper_bytes': len(payload),
                 'supported_complete_wrapper': framed is not None,
                 'direction_inference': framed[0] if framed else None,
                 'declared_data_bytes': struct.unpack_from('<H', payload, 10)[0] if len(payload)>=12 else None,
                 'data_sha256': sha256(framed[1]) if framed else None,
                 'successful_transform_verified': False}
        entries.append(entry)
    return {'binary_records': binary_count, 'wrapper_shape_counts': dict(sorted(shapes.items())),
            'transform_command_signature_records': len(entries),
            'complete_transform_wrapper_records': sum(e['supported_complete_wrapper'] for e in entries),
            'records': entries}


def report(paths):
    cases = []
    for path in paths:
        path = Path(path)
        if not NAME.fullmatch(path.name):
            raise ValueError('explicit saved AL5 HTX trace required')
        source = read_bounded(path, 1, MAX_INPUT)
        decoded = decode(source)
        case = census(records(decoded))
        case.update(source_path=str(path.resolve()), source_name=path.name,
                    source_sha256=sha256(source), decoded_sha256=sha256(decoded))
        cases.append(case)
    if not cases:
        raise ValueError('at least one trace required')
    return {'schema_version': 1, 'generator_sha256': sha256(Path(__file__).read_bytes()),
            'scope': 'Every binary record in supplied saved AL5 containers checked for host-interface command words 0x8414/0x8415; hashes only, no raw payload export.',
            'limits': 'Absence applies only to supplied containers; object loading may precede recording. Complete wrapper framing does not prove command success, response pairing, CRC or transformed object contents.',
            'static_evidence': 'Docs/AL5/EFILIVE_HOST_IPC.json',
            'trace_count': len(cases), 'traces': cases,
            'object_transform_reproduced': False, 'physical_transport_verified': False,
            'write_protocol_verified': False, 'physical_recovery_verified': False,
            'ready_to_flash': False, 'live_write_enabled': False,
            'erase_scope': None, 'would_send': [], 'erase_packets': [], 'program_packets': []}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.resolve() in [p.resolve() for p in args.trace]:
        parser.error('output must not overwrite an input')
    result = report(args.trace)
    with args.output.open('x', encoding='utf8', newline='\n') as stream:
        stream.write(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'traces': result['trace_count'], 'ready_to_flash': False}))
