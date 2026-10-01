"""Search exact complete AL5 table sequences and extend XDF only on unique matches."""
import argparse
import copy
import json
import struct
import xml.etree.ElementTree as ET
from pathlib import Path
from al5_segment import START, validate, sha256, occurrences

SCALES = {'D5030': (128, True, 'X/128'),
          'D5031': (655.36, False, 'X*100/65536'),
          'D5032': (655.36, False, 'X*100/65536'),
          'D5033': (655.36, False, 'X*100/65536'),
          'D5034': (655.36, False, 'X*100/65536'),
          'D5070': (327.68, False, 'X*200/65536'),
          'D5071': (327.68, False, 'X*200/65536'),
          'D5072': (64, False, 'X/64')}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'stock', 'export', 'output', 'manifest'):
        p.add_argument('--'+name, required=True, type=Path)
    args = p.parse_args()
    stock = args.stock.read_bytes()
    if validate(stock):
        raise ValueError('invalid stock segment anchors')
    native = {c['id']: c for c in json.loads(args.export.read_text())['calibrations']}
    root = ET.parse(args.source).getroot()
    template = next(t for t in root.findall('XDFTABLE') if t.findtext('title').startswith('D5100 '))
    uid = max(int(t.get('uniqueid'), 0) for t in root if t.get('uniqueid'))+1
    manifest = {'stock_sha256': sha256(stock), 'source_xdf_sha256': sha256(args.source.read_bytes()),
                'native_export_sha256': sha256(args.export.read_bytes()),
                'method': 'unique complete BE16 column-major sequence with preceding dimension header',
                'confidence': 'exact structural mapping, not marker-differential verified',
                'added': [], 'deferred': []}
    for ident, (factor, signed, math) in SCALES.items():
        c = native[ident]
        rows, cols = c['row_count'], c['column_count']
        numbers = [c['cells'][r][col] for col in range(cols) for r in range(rows)]
        counts = [round(n*factor) for n in numbers]
        needle = struct.pack('>'+str(len(counts))+('h' if signed else 'H'), *counts)
        candidates = occurrences(stock, needle)
        matches = [a for a in candidates if (
            stock[a-START-4:a-START] == struct.pack('>2H', rows, cols) if cols > 1 else
            stock[a-START-2:a-START] == struct.pack('>H', rows))]
        print(ident, 'sequence matches', [hex(a) for a in candidates], 'header matches', [hex(a) for a in matches])
        if len(matches) != 1:
            manifest['deferred'].append({'id': ident, 'sequence_matches': [f'0x{a:05X}' for a in candidates],
                'header_matches': [f'0x{a:05X}' for a in matches], 'reason': 'not uniquely structurally resolved'})
            continue
        address = matches[0]
        max_error = max(abs(n-raw/factor) for n, raw in zip(numbers, counts))
        if max_error >= .001:
            raise ValueError('native values exceed tolerance')
        for col in range(cols):
            item = copy.deepcopy(template)
            item.set('uniqueid', f'0x{uid:X}')
            uid += 1
            item.find('title').text = f'{ident} {c["api_description"]} - Native Column {col}: {c["columns"][col]}'
            item.find('description').text = (
                'Exact structural mapping: unique complete native table sequence and matching dimension header. '
                'BE16 column-major storage; exported as separate column vectors to preserve orientation. '
                'Not marker-differential verified. Axis labels use the native export; links/semantics '
                'beyond those labels remain unvalidated. Keep stock for first test.')
            item.find('CATEGORYMEM').set('category', '9' if ident.startswith('D507') else '4')
            item.find("XDFAXIS[@id='x']/LABEL").set('value', str(c['columns'][col]))
            y = item.find("XDFAXIS[@id='y']")
            y.find('indexcount').text = str(rows)
            for label in list(y.findall('LABEL')):
                y.remove(label)
            for r, label in enumerate(c['rows']):
                ET.SubElement(y, 'LABEL', index=str(r), value=str(label))
            z = item.find("XDFAXIS[@id='z']")
            embedded = z.find('EMBEDDEDDATA')
            embedded.set('mmedrowcount', str(rows))
            embedded.set('mmedaddress', f'0x{address+col*rows*2:X}')
            embedded.set('mmedtypeflags', '0x01' if signed else '0x00')
            z.find('MATH').set('equation', math)
            z.find('units').text = 'deg C' if ident == 'D5030' else c['api_default_units']
            z.find('min').text = str(c['limits']['hard_min'])
            z.find('max').text = str(c['limits']['hard_max'])
            root.append(item)
            manifest['added'].append({'id': ident, 'column': col, 'address': f'0x{address+col*rows*2:05X}',
                                      'cells': rows, 'math': math, 'max_abs_error': max_error})
    root.find('XDFHEADER/deftitle').text = 'AL5 15184109 / 15183960 - iMob Racing Structural Extended v0.6'
    ET.indent(root, space='  ')
    ET.ElementTree(root).write(args.output, encoding='utf-8', xml_declaration=True)
    args.manifest.write_text(json.dumps(manifest, indent=2)+'\n')
    print('Added', len(manifest['added']), 'vectors')
