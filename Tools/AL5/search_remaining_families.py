"""Inventory remaining WOT record families offline; do not assign ambiguous modes."""
import argparse
import json
import struct
from pathlib import Path
from al5_segment import occurrences, sha256, validate


def record(entry, column):
    values = [row[column] for row in entry['cells']]
    raw = [round(v*128) for v in values]
    if max(abs(v-n/128) for v, n in zip(values, raw)) >= .001:
        raise ValueError('speed scaling does not reproduce native values')
    return struct.pack('>H', len(raw))+struct.pack('>'+str(len(raw))+'H', *raw)


def inventory(stock, export):
    if validate(stock):
        raise ValueError('invalid stock anchors')
    native = {c['id']: c for c in export['calibrations']}
    results = []
    for col in range(4):
        ids = ['D5035', 'D5036', 'D5037', 'D5038']
        needle = b''.join(record(native[i], col) for i in ids)
        starts = occurrences(stock, needle)
        results.append({'family': 'WOT downshift', 'native_column': col,
            'label': native[ids[0]]['columns'][col], 'ids': ids,
            'layout': 'four consecutive header/BE16 speed records',
            'header_addresses': [f'0x{a:05X}' for a in starts],
            'status': 'unique family candidate' if len(starts) == 1 else 'ambiguous or absent'})
    for apply, release in [('D5064', 'D5067'), ('D5065', 'D5068'), ('D5066', 'D5069')]:
        for interleaved in (False, True):
            positions = ([(i, c) for c in range(4) for i in (apply, release)] if interleaved else
                         [(i, c) for i in (apply, release) for c in range(4)])
            needle = b''.join(record(native[i], c) for i, c in positions)
            starts = occurrences(stock, needle)
            results.append({'family': 'WOT TCC', 'ids': [apply, release],
                'label': native[apply]['api_description'],
                'layout': 'interleaved apply/release' if interleaved else 'apply gears then release gears',
                'record_order': [{'id': i, 'column': c} for i, c in positions],
                'header_addresses': [f'0x{a:05X}' for a in starts],
                'status': 'unique family candidate' if len(starts) == 1 else 'ambiguous or absent'})
    return results


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('stock', 'export', 'output'):
        p.add_argument('--'+name, required=True, type=Path)
    args = p.parse_args()
    stock, export_bytes = args.stock.read_bytes(), args.export.read_bytes()
    result = {'stock_sha256': sha256(stock), 'native_export_sha256': sha256(export_bytes),
        'confidence': 'search candidates only; identity and neighboring record context require review',
        'native_export_encoding': 'cp1252',
        'families': inventory(stock, json.loads(export_bytes.decode('cp1252')))}
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    for f in result['families']:
        print(f['label'], f['layout'], f['header_addresses'], f['status'])
