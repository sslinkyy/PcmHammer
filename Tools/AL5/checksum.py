"""Offline native AL5 checksum: reflected CRC16 plus BE16 sum compensation.

Validated on OS 15184109 / calibration 15183960. No vehicle I/O.
"""
import argparse
import json
from pathlib import Path
from al5_segment import LENGTH, CHECKSUM, START, validate, word_sum, sha256


def crc16(data, seed=0):
    crc = seed
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA001 if crc & 1 else 0)
    return crc


def native_field(data):
    if len(data) != LENGTH:
        raise ValueError('native checksum requires exactly 57304 bytes')
    body = data[:CHECKSUM-START]
    first = crc16(body)
    second = (-word_sum(body)-first) & 0xFFFF
    return first.to_bytes(2, 'big') + second.to_bytes(2, 'big')


def checksum_valid(data):
    return len(data) == LENGTH and data[-4:] == native_field(data)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--output', type=Path, help='new offline corrected BIN; does not authorize flashing')
    args = parser.parse_args()
    data = args.input.read_bytes()
    errors = validate(data)
    if errors:
        parser.error('; '.join(errors))
    field = native_field(data)
    print(json.dumps({'sha256': sha256(data), 'stored': data[-4:].hex().upper(),
                      'computed': field.hex().upper(), 'checksum_valid': checksum_valid(data),
                      'be16_sum': f'0x{word_sum(data):04X}', 'ready_to_flash': False}, indent=2))
    if args.output:
        if args.output.resolve() == args.input.resolve():
            parser.error('output must not overwrite input')
        with args.output.open('xb') as stream:
            stream.write(data[:-4] + field)
    else:
        raise SystemExit(0 if checksum_valid(data) else 1)
