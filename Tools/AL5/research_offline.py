"""Reproducible local sequence search and checksum hypothesis tests; no vehicle I/O."""
import argparse
import json
import struct
import zlib
from pathlib import Path
from al5_segment import START, LENGTH, sha256, validate, word_sum, occurrences


def mapping_candidates(data, export):
    result = []
    for c in export['calibrations']:
        ident = c['id']
        if ident not in {f'D{i}' for i in list(range(5010, 5014)) + list(range(5015, 5019)) +
                         list(range(5020, 5024)) + list(range(5035, 5039)) + list(range(5064, 5070))}:
            continue
        columns = []
        for col in range(c['column_count']):
            expected = [row[col] for row in c['cells']]
            counts = [round(v * 128) for v in expected]
            needle = struct.pack('>' + 'H' * len(counts), *counts)
            matches = occurrences(data, needle)
            columns.append({'column': c['columns'][col], 'column_index': col,
                            'expected': expected, 'raw_counts': counts,
                            'matches': [f'0x{a:05X}' for a in matches],
                            'max_abs_error': max(abs(v - n/128) for v, n in zip(expected, counts)),
                            'confidence': 'exact_unique_sequence' if len(matches) == 1 else 'ambiguous_sequence'})
        result.append({'id': ident, 'description': c['api_description'],
                       'rows': c['rows'], 'units': c['api_default_units'], 'columns': columns})
    return result


def checksum_hypotheses(data):
    if len(data) != LENGTH or validate(data):
        raise ValueError('checksum experiments require an anchored full segment')
    words = struct.unpack('>' + 'H' * (len(data)//2), data)
    body = data[:-4]
    high, low = words[-2:]
    results = {'sha256': sha256(data), 'native_field': data[-4:].hex().upper(),
               'be16_sum': word_sum(data), 'be16_payload_sum': word_sum(body),
               'field_word_sum': (high+low) & 0xFFFF,
               'crc32_payload': f'{zlib.crc32(body):08X}',
               'crc32_matches_native': zlib.crc32(body) == int.from_bytes(data[-4:], 'big'),
               'fletcher_tests': []}
    longs = struct.unpack('>' + 'I' * (len(body)//4), body)
    results['negative_be32_sum'] = f'{(-sum(longs)) & 0xFFFFFFFF:08X}'
    results['negative_alternating_be16_sums'] = [(-sum(words[:-2:2])) & 0xFFFF,
                                                (-sum(words[1:-2:2])) & 0xFFFF]
    results['alternating_sums_match'] = results['negative_alternating_be16_sums'] == [high, low]
    results['reflected_crc16_tests'] = []
    for polynomial in (0xA001, 0x8408):
        for seed in (0, 0xFFFF):
            crc = seed
            for byte in body:
                crc ^= byte
                for _ in range(8):
                    crc = (crc >> 1) ^ (polynomial if crc & 1 else 0)
            results['reflected_crc16_tests'].append({'polynomial': f'0x{polynomial:04X}',
                'seed': seed, 'value': f'{crc:04X}', 'matches_first_native_word': crc == high})
    for modulus in (65535, 65536):
        for start_offset in (0, 0x20, 0x24, 0x28):
            subset = words[start_offset//2:]
            s1 = s2 = 0
            for w in subset:
                s1 = (s1+w) % modulus
                s2 = (s2+s1) % modulus
            a = b = 0
            for w in subset[:-2]:
                a = (a+w) % modulus
                b = (b+a) % modulus
            check1 = (-a-b) % modulus
            check2 = b % modulus
            results['fletcher_tests'].append({'modulus': modulus, 'start_offset': start_offset,
                'whole_residues': [s1, s2], 'predicted_compensation_words': [check1, check2],
                'matches_native': [check1, check2] == [high, low]})
    return results


def object_inventory(directory):
    result = []
    for p in sorted(directory.glob('AL5*')):
        if p.suffix.lower() not in ('.obj', '.bix', '.pmm'):
            continue
        data = p.read_bytes()
        import re
        strings = [m.group().decode('ascii') for m in re.finditer(rb'[ -~]{8,}', data)]
        result.append({'filename': p.name, 'length': len(data), 'sha256': sha256(data),
                       'prefix_16': data[:16].hex(), 'ascii_strings': strings[:25]})
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('stock', 'ppei', 'export', 'objects', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    args = p.parse_args()
    stock, ppei = args.stock.read_bytes(), args.ppei.read_bytes()
    result = {'stock': checksum_hypotheses(stock), 'ppei': checksum_hypotheses(ppei),
              'mapping_candidates': mapping_candidates(stock, json.loads(args.export.read_text())),
              'objects': object_inventory(args.objects)}
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('Saved offline evidence to', args.output)
    for name in ('stock', 'ppei'):
        print(name, 'Fletcher matches:', [t for t in result[name]['fletcher_tests'] if t['matches_native']])
    for entry in result['mapping_candidates']:
        print(entry['id'], [len(c['matches']) for c in entry['columns']])
