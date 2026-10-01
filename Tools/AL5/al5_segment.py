"""Offline AL5 segment primitives. No adapter, serial or vehicle dependencies."""
import hashlib
import struct

START = 0x8000
END = 0x15FD8
LENGTH = END - START
CHECKSUM = 0x15FD4
ANCHORS = {
    0x8024: bytes.fromhex('00e7b058'),
    0xA996: bytes.fromhex('11f70c68073e05a0040002d9'),
    0x158A8: bytes.fromhex('00110009'),
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def occurrences(data, needle):
    return [i + START for i in range(0, len(data) - len(needle) + 1, 2)
            if data[i:i + len(needle)] == needle]


def word_sum(data):
    if len(data) % 2:
        raise ValueError('BE16 sum requires an even byte length')
    return sum(struct.unpack('>' + 'H' * (len(data) // 2), data)) & 0xFFFF


def validate(data):
    errors = []
    if len(data) != LENGTH:
        return [f'length {len(data)}; expected {LENGTH}']
    for address, expected in ANCHORS.items():
        if data[address - START:address - START + len(expected)] != expected:
            errors.append(f'anchor mismatch at 0x{address:05X}')
    return errors


def diff_ranges(before, after):
    if len(before) != LENGTH or len(after) != LENGTH:
        raise ValueError('diff requires two exact calibration segments')
    result = []
    i = 0
    while i < LENGTH:
        if before[i] == after[i]:
            i += 1
            continue
        start = i
        while i < LENGTH and before[i] != after[i]:
            i += 1
        result.append({'start': f'0x{START + start:05X}',
                       'end_inclusive': f'0x{START + i - 1:05X}',
                       'length': i - start, 'before': before[start:i].hex(),
                       'after': after[start:i].hex()})
    return result
