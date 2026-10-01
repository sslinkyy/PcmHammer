"""Extend the preserved v0.3 XDF using unique whole TCC record-family matches."""
import argparse
import copy
import json
import struct
import xml.etree.ElementTree as ET
from pathlib import Path
from al5_segment import START, sha256, validate, occurrences

ORDER = ['D5010', 'D5011', 'D5012', 'D5013', 'D5015', 'D5016', 'D5017', 'D5018']


def expand(source, stock, export):
    if validate(stock):
        raise ValueError('stock segment anchor validation failed')
    native = {c['id']: c for c in export['calibrations']}
    root = ET.parse(source).getroot()
    template = next(t for t in root.findall('XDFTABLE') if t.findtext('title').startswith('D5100 '))
    uid = max(int(t.get('uniqueid'), 0) for t in root if t.get('uniqueid')) + 1
    manifest = {'stock_sha256': sha256(stock), 'source_xdf_sha256': sha256(Path(source).read_bytes()),
                'method': 'whole record-family exact search, 0x24 stride and 0x0011 vector headers',
                'confidence': 'exact structural mapping; not marker-differential verified',
                'added': [], 'deferred': []}
    for col in range(8):
        order = ORDER if col < 4 else ['D5010', 'D5015']
        needles = [struct.pack('>17H', *(round(row[col]*128) for row in native[ident]['cells']))
                   for ident in order]
        starts = occurrences(stock, needles[0])
        starts = [a for a in starts if all(
            stock[a-START + i*0x24:a-START + i*0x24+34] == needle and
            stock[a-START + i*0x24-2:a-START + i*0x24] == b'\x00\x11'
            for i, needle in enumerate(needles))]
        if len(starts) != 1:
            manifest['deferred'].append({'pattern': chr(65+col),
                'reason': 'whole family not unique; differential evidence required',
                'family_matches': [f'0x{a:05X}' for a in starts]})
            continue
        for i, ident in enumerate(order):
            address = starts[0] + i*0x24
            entry = native[ident]
            item = copy.deepcopy(template)
            item.set('uniqueid', f'0x{uid:X}')
            uid += 1
            item.find('title').text = f'{ident} {entry["api_description"]} - Pattern {chr(65+col)}'
            item.find('description').text = (
                'Exact structural mapping: unique complete native record-family sequence, '
                '0x24-byte stride, 0x0011 headers, BE16 /128 km/h. '
                'Not marker-differential verified. Pattern letters follow the native export; '
                'mode semantics have not been established. Keep stock for first test.')
            item.find('CATEGORYMEM').set('category', '9')
            x = item.find("XDFAXIS[@id='x']/LABEL")
            x.set('value', 'Speed')
            y = item.find("XDFAXIS[@id='y']")
            for label in y.findall('LABEL'):
                label.set('value', f'{entry["rows"][int(label.get("index"))]}%')
            z = item.find("XDFAXIS[@id='z']")
            z.find('EMBEDDEDDATA').set('mmedtypeflags', '0x00')
            z.find('EMBEDDEDDATA').set('mmedaddress', f'0x{address:X}')
            z.find('units').text = 'km/h'
            z.find('MATH').set('equation', 'X/128')
            z.find('min').text = '0'
            z.find('max').text = '511.9921875'
            root.append(item)
            raw = list(struct.unpack('>17H', needles[i]))
            expected = [r[col] for r in entry['cells']]
            error = max(abs(v-n/128) for v, n in zip(expected, raw))
            if error >= .001:
                raise ValueError('native value error exceeds tolerance')
            manifest['added'].append({'id': ident, 'pattern': chr(65+col),
                'address': f'0x{address:05X}', 'cells': 17, 'max_abs_error': error})
    header = root.find('XDFHEADER')
    header.find('deftitle').text = 'AL5 15184109 / 15183960 - iMob Racing Structural TCC v0.4'
    warning = root.find('XDFCONSTANT/description')
    warning.text = ('For 57,304-byte calibration segments only. Offline inspection and development. '
                    'Native four-byte checksum and AL5 write protocol are unresolved. '
                    'No edited BIN is flash-ready. The user has no FlashScan. '
                    'New TCC entries use exact structural mapping, not marker differentials.')
    return ET.ElementTree(root), manifest


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'stock', 'export', 'output', 'manifest'):
        p.add_argument('--' + name, required=True, type=Path)
    args = p.parse_args()
    tree, manifest = expand(args.source, args.stock.read_bytes(), json.loads(args.export.read_text()))
    ET.indent(tree, space='  ')
    tree.write(args.output, encoding='utf-8', xml_declaration=True)
    args.manifest.write_text(json.dumps(manifest, indent=2) + '\n')
    print('Added', len(manifest['added']), 'vectors;', 'deferred:', manifest['deferred'])
