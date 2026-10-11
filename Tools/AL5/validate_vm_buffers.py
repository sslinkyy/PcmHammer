"""File-only CRC inspection of explicitly supplied post-transform VM buffers."""
import argparse
import json
from pathlib import Path
import re
from al5_segment import sha256
from checksum import crc16
from inspect_vm_objects import CODE_CAPACITY, DATA_CAPACITY


def inspect_buffers(code, data, expected_code_hash, expected_data_hash):
    for role, value, expected in [('code', code, expected_code_hash),
                                  ('data', data, expected_data_hash)]:
        if not re.fullmatch('[0-9a-fA-F]{64}', expected):
            raise ValueError(f'{role} expected SHA256 must contain 64 hex characters')
        if sha256(value) != expected.lower():
            raise ValueError(f'{role} source SHA256 mismatch')
    if not 64 <= len(code) <= CODE_CAPACITY or not 0 < len(data) <= DATA_CAPACITY:
        raise ValueError('supplied buffers outside bounded validator profile')
    crc = 0xB27D
    stages = []
    for role, value, start, end in [('code', code, 2, 48),
                                   ('code', code, 64, len(code)),
                                   ('data', data, 0, len(data))]:
        seed = crc
        crc = crc16(value[start:end], seed)
        stages.append({'buffer': role, 'offset': start, 'end_exclusive': end,
                       'seed': seed, 'crc16': crc,
                       'source_sha256': sha256(value[start:end])})
    stored = int.from_bytes(code[:2], 'little')
    return {'schema_version': 1, 'scope': 'Caller-supplied post-transform buffers only; no object decoder, callbacks, IPC, execution or transport.',
            'code_sha256': sha256(code), 'data_sha256': sha256(data),
            'code_bytes': len(code), 'data_bytes': len(data),
            'stages': stages, 'stored_crc16_le': stored, 'computed_crc16': crc,
            'supplied_buffer_crc_matches': stored == crc,
            'buffer_transform_provenance_verified': False,
            'object_contents_decoded': False, 'object_validation_verified': False,
            'date_compatibility_verified': False, 'physical_recovery_verified': False,
            'ready_to_flash': False, 'live_write_enabled': False,
            'erase_scope': None, 'would_send': [], 'erase_packets': [], 'program_packets': []}


def read_bounded(path, minimum, capacity):
    if not minimum <= path.stat().st_size <= capacity:
        raise ValueError('input file outside buffer capacity')
    with path.open('rb') as stream:
        value = stream.read(capacity + 1)
    if not minimum <= len(value) <= capacity:
        raise ValueError('input changed size or exceeded buffer capacity')
    return value


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--code', type=Path, required=True)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--expected-code-sha256', required=True)
    parser.add_argument('--expected-data-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.resolve() in (args.code.resolve(), args.data.resolve()):
        parser.error('output must not overwrite input')
    result = inspect_buffers(read_bounded(args.code, 64, CODE_CAPACITY),
                             read_bounded(args.data, 1, DATA_CAPACITY),
                             args.expected_code_sha256, args.expected_data_sha256)
    result['generator_sha256'] = sha256(Path(__file__).read_bytes())
    result['code_path'] = str(args.code.resolve())
    result['data_path'] = str(args.data.resolve())
    with args.output.open('x', encoding='utf8') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'supplied_buffer_crc_matches': result['supplied_buffer_crc_matches'],
                      'object_validation_verified': False, 'ready_to_flash': False}))
