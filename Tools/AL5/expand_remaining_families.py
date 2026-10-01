"""Add uniquely matched complete WOT downshift and TCC families to an existing XDF."""
import argparse
import copy
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from al5_segment import sha256
from search_remaining_families import inventory


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'stock', 'export', 'output', 'manifest'):
        p.add_argument('--'+name, required=True, type=Path)
    args = p.parse_args()
    stock, export_bytes = args.stock.read_bytes(), args.export.read_bytes()
    export = json.loads(export_bytes.decode('cp1252'))
    native = {c['id']: c for c in export['calibrations']}
    families = inventory(stock, export)
    root = ET.parse(args.source).getroot()
    template = next(t for t in root.findall('XDFTABLE') if t.findtext('title').startswith('D5020 '))
    uid = max(int(t.get('uniqueid'), 0) for t in root if t.get('uniqueid'))+1
    manifest = {'stock_sha256': sha256(stock), 'native_export_sha256': sha256(export_bytes),
        'source_xdf_sha256': sha256(args.source.read_bytes()),
        'confidence': 'unique complete header/BE16 record-family match; not marker-differential verified',
        'added': [], 'deferred': []}
    for family in families:
        if family['status'] != 'unique family candidate':
            manifest['deferred'].append(family)
            continue
        start = int(family['header_addresses'][0], 0)
        positions = ([(i, family['native_column']) for i in family['ids']]
                     if family['family'] == 'WOT downshift' else
                     [(r['id'], r['column']) for r in family['record_order']])
        for index, (ident, col) in enumerate(positions):
            c = native[ident]
            if c['row_count'] != 2:
                raise ValueError('unexpected record dimensions')
            address = start+index*6+2
            item = copy.deepcopy(template)
            item.set('uniqueid', f'0x{uid:X}')
            uid += 1
            item.find('title').text = f'{ident} {c["api_description"]} - Native Column {col}: {c["columns"][col]}'
            item.find('description').text = (
                'Exact structural mapping: unique complete native record-family sequence, '
                'two-cell BE16 /128 speed records with 0x0002 headers and 0x06 stride. '
                'Labels follow this native definition, not neighboring RPM pattern labels. '
                'No marker-differential proof or controller operating-mode validation. Keep stock for first test.')
            item.find('CATEGORYMEM').set('category', '9' if family['family'] == 'WOT TCC' else '4')
            item.find("XDFAXIS[@id='x']/LABEL").set('value', str(c['columns'][col]))
            y = item.find("XDFAXIS[@id='y']")
            for label in y.findall('LABEL'):
                label.set('value', str(c['rows'][int(label.get('index'))]))
            z = item.find("XDFAXIS[@id='z']")
            z.find('EMBEDDEDDATA').set('mmedaddress', f'0x{address:X}')
            z.find('EMBEDDEDDATA').set('mmedtypeflags', '0x00')
            z.find('MATH').set('equation', 'X/128')
            z.find('units').text = 'km/h'
            z.find('min').text = '0'
            z.find('max').text = '511.9921875'
            root.append(item)
            manifest['added'].append({'id': ident, 'column': col, 'address': f'0x{address:05X}',
                'family_header': f'0x{start:05X}', 'layout': family['layout'], 'cells': 2})
    root.find('XDFHEADER/deftitle').text = 'AL5 15184109 / 15183960 - iMob Racing Structural WOT/TCC v0.7'
    ET.indent(root, space='  ')
    ET.ElementTree(root).write(args.output, encoding='utf-8', xml_declaration=True)
    args.manifest.write_text(json.dumps(manifest, indent=2)+'\n')
    print('Added', len(manifest['added']), 'vectors')
