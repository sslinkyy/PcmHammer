"""Validate AL5 checksum using existing reference BINs and local COZ exports."""
import argparse
import json
import struct
import zlib
from pathlib import Path
from al5_segment import LENGTH, START, sha256, word_sum
from checksum import native_field, checksum_valid, crc16


def segments(data):
    # Locate candidates by the independently known ID offset, then require full
    # native checksum agreement. This is not a general EFILive container parser.
    anchor = bytes.fromhex('00e7b058')
    position = data.find(anchor)
    while position >= 0:
        start = position - 0x24
        if start >= 0 and start + LENGTH <= len(data):
            yield start, data[start:start+LENGTH]
        position = data.find(anchor, position+1)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stock', required=True, type=Path)
    p.add_argument('--ppei', required=True, type=Path)
    p.add_argument('--coz-directory', required=True, type=Path)
    p.add_argument('--firmware-high', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    records = []
    for label, path in [('stock', args.stock), ('ppei', args.ppei)]:
        data = path.read_bytes()
        records.append({'source': label, 'sha256': sha256(data), 'stored': data[-4:].hex().upper(),
                        'computed': native_field(data).hex().upper(), 'valid': checksum_valid(data),
                        'be16_sum': word_sum(data)})
    high = args.firmware_high.read_bytes()
    table = struct.unpack('>256H', high[0xAA610-0x20000:0xAA810-0x20000])
    generated = [crc16(bytes([n])) for n in range(256)]
    table_matches = list(table) == generated
    containers = []
    for path in sorted(args.coz_directory.glob('AL5*.coz')):
        raw = path.read_bytes()
        found = []
        for offset in range(len(raw)-2):
            if raw[offset] != 0x78 or ((raw[offset]<<8)|raw[offset+1]) % 31:
                continue
            try:
                decompressed = zlib.decompressobj().decompress(raw[offset:], 4*1024*1024)
            except zlib.error:
                continue
            for segment_offset, data in segments(decompressed):
                found.append({'zlib_offset': offset, 'segment_offset': segment_offset,
                              'sha256': sha256(data), 'stored': data[-4:].hex().upper(),
                              'computed': native_field(data).hex().upper(),
                              'valid': checksum_valid(data), 'be16_sum': word_sum(data)})
        containers.append({'source': path.name, 'source_sha256': sha256(raw), 'segments': found})
    result = {'references': records, 'firmware_crc_table_matches_all_256_entries': table_matches,
              'firmware_high_sha256': sha256(high), 'coz': containers,
              'note': 'COZ search tests standard zlib streams and ID-offset candidates only; '
                      'no matching segment does not mean the container is corrupt.'}
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print('References:', records)
    print('All 256 firmware CRC table entries match:', table_matches)
    print('COZ:', len(containers), 'valid additional segments:',
          sum(s['valid'] for c in containers for s in c['segments']))
    raise SystemExit(0 if all(r['valid'] for r in records) and table_matches else 1)
