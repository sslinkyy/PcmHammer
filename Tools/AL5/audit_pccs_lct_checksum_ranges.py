"""Audit two pinned PCCS LCT S2 images offline; never emit a flash image or packet.

Stored CRC and compensation locations are artifact-specific candidates. Their
equivalence to the help's KwCOND symbol names is not established by these bytes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

from checksum import crc16

VARIANTS = {
    'u2a': {'sha256': '84e8ef5e8f38dbf2814011a40190e9d38ecd041560d888133cba35c98178065d',
            'start': 0x8000, 'end_exclusive': 0x15FD8},
    'df9': {'sha256': '6af8a1afd0cffabe2ba66979283b03de1eb030101d7be174289d0800d4d4b411',
            'start': 0x8000, 'end_exclusive': 0x19040},
}


def parse_s2(data):
    """Require valid S2 count/checksum/address and unique bytes on every line."""
    memory = {}
    records = 0
    for ordinal, line in enumerate(data.splitlines(), 1):
        if not line.strip():
            continue
        if not re.fullmatch(rb'S2(?:[0-9A-Fa-f]{2})+', line):
            raise ValueError(f'line {ordinal}: expected exact ASCII S2 record')
        fields = bytes.fromhex(line[2:].decode('ascii'))
        if len(fields) < 5 or fields[0] != len(fields)-1:
            raise ValueError(f'line {ordinal}: invalid byte count or short address')
        if sum(fields) & 255 != 255:
            raise ValueError(f'line {ordinal}: S-record checksum mismatch')
        address = int.from_bytes(fields[1:4], 'big')
        payload = fields[4:-1]
        if address+len(payload) > 0x1000000:
            raise ValueError(f'line {ordinal}: data exceeds 24-bit address space')
        for offset, value in enumerate(payload):
            key = address+offset
            if key in memory:
                raise ValueError(f'line {ordinal}: overlapping address 0x{key:X}')
            memory[key] = value
        records += 1
    if not records or not memory:
        raise ValueError('no mapped S2 data')
    return memory, records


def mapped_ranges(memory):
    addresses = sorted(memory)
    if not addresses:
        return []
    ranges = []
    start = previous = addresses[0]
    for address in addresses[1:]:
        if address != previous+1:
            ranges.append({'start': start, 'end_exclusive': previous+1})
            start = address
        previous = address
    ranges.append({'start': start, 'end_exclusive': previous+1})
    return ranges


def inspect_range(memory, start, end):
    if (type(start) is not int or type(end) is not int or start < 0
            or end > 0x1000000 or end-start < 4 or (end-start) % 2):
        raise ValueError('expected bounded, even, checksum-bearing range')
    missing = next((a for a in range(start, end) if a not in memory), None)
    if missing is not None:
        raise ValueError(f'incomplete calibration range at 0x{missing:X}')
    segment = bytes(memory[a] for a in range(start, end))
    body = segment[:-4]
    crc = crc16(body)
    body_sum = sum(int.from_bytes(body[i:i+2], 'big') for i in range(0, len(body), 2)) & 0xFFFF
    compensation = (-body_sum-crc) & 0xFFFF
    return {
        'start': start, 'end_exclusive': end, 'bytes': len(segment),
        'sha256': hashlib.sha256(segment).hexdigest(),
        'body_end_exclusive': end-4,
        'candidate_crc_address': end-4, 'candidate_compensation_address': end-2,
        'stored_field_hex': segment[-4:].hex(),
        'computed_crc16': crc, 'computed_compensation': compensation,
        'crc_matches': int.from_bytes(segment[-4:-2], 'big') == crc,
        'compensation_matches': int.from_bytes(segment[-2:], 'big') == compensation,
        'whole_be16_sum': (body_sum+int.from_bytes(segment[-4:-2], 'big')
                           +int.from_bytes(segment[-2:], 'big')) & 0xFFFF,
        'candidate_readback_range': {'start': end-4, 'end_exclusive': end,
                                     'bytes': 4, 'physical_validation': False},
    }


def audit(data, variant):
    if variant not in VARIANTS:
        raise ValueError('unknown pinned variant')
    pin = VARIANTS[variant]
    digest = hashlib.sha256(data).hexdigest()
    if digest != pin['sha256']:
        raise ValueError('source pin changed; do not infer another calibration layout')
    memory, records = parse_s2(data)
    result = inspect_range(memory, pin['start'], pin['end_exclusive'])
    return {
        'schema': 'al5-pccs-lct-checksum-ranges-v1', 'variant': variant,
        'source_sha256': digest, 'source_bytes': len(data), 's2_records': records,
        'mapped_ranges': mapped_ranges(memory), 'calibration': result,
        'algorithm': {'crc_polynomial_reflected': 0xA001, 'seed': 0,
                      'crc_final_xor': 0, 'stored_words': 'BE16',
                      'compensation': '(-BE16_sum(body)-CRC16(body)) & 0xFFFF'},
        'symbol_bindings': {'KwCOND_Cal_CRC': None,
                            'KwCOND_Cal_Checksum_Location': None},
        'symbol_equivalence_proven': False, 'live_write_enabled': False,
        'ready_to_flash': False, 'would_send': [], 'controller_acceptance_proven': False,
        'scope': 'two pinned source artifacts; arithmetic and coverage only; no recovery proof',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--variant', choices=VARIANTS, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output already exists; refusing to overwrite')
    result = audit(args.input.read_bytes(), args.variant)
    result['source_path'] = str(args.input.resolve())
    with args.output.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'variant': args.variant, 'source_sha256': result['source_sha256'],
                      'crc_matches': result['calibration']['crc_matches'],
                      'compensation_matches': result['calibration']['compensation_matches'],
                      'ready_to_flash': False}))


if __name__ == '__main__':
    main()
