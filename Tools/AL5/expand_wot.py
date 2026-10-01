"""Map WOT upshift speed records anchored to the preserved WOT RPM families."""
import argparse
import copy
import json
import struct
import xml.etree.ElementTree as ET
from pathlib import Path
from al5_segment import START, sha256, validate


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'stock', 'export', 'output', 'manifest'):
        p.add_argument('--'+name, required=True, type=Path)
    args = p.parse_args()
    stock = args.stock.read_bytes()
    if validate(stock):
        raise ValueError('invalid stock anchors')
    native = {c['id']: c for c in json.loads(args.export.read_text())['calibrations']}
    root = ET.parse(args.source).getroot()
    uid = max(int(t.get('uniqueid'), 0) for t in root if t.get('uniqueid'))+1
    manifest = {'method': 'four 0x06-byte speed records 0x30 bytes before existing verified RPM family',
                'confidence': 'exact structural mapping, not marker-differential verified',
                'stock_sha256': sha256(stock), 'source_xdf_sha256': sha256(args.source.read_bytes()), 'added': []}
    for col, pattern in enumerate('ABCD'):
        template = next(t for t in root.findall('XDFTABLE') if t.findtext('title') ==
                        f'D5025 WOT 1->2 Shift RPM - Pattern {pattern}')
        rpm_address = int(template.find("XDFAXIS[@id='z']/EMBEDDEDDATA").get('mmedaddress'), 0)
        for i in range(4):
            ident = f'D{5020+i}'
            address = rpm_address-0x30+i*6
            offset = address-START
            expected = [row[col] for row in native[ident]['cells']]
            counts = [round(v*128) for v in expected]
            if stock[offset-2:offset] != b'\x00\x02' or stock[offset:offset+4] != struct.pack('>2H', *counts):
                raise ValueError(f'{ident} {pattern}: structural/value validation failed')
            item = copy.deepcopy(template)
            item.set('uniqueid', f'0x{uid:X}')
            uid += 1
            item.find('title').text = f'{ident} {native[ident]["api_description"]} - Pattern {pattern}'
            item.find('description').text = (
                'Exact structural mapping: native two-cell BE16 /128 speed sequence, '
                '0x0002 header, 0x06 record stride, and fixed position 0x30 bytes before '
                'the preserved WOT RPM family. Not marker-differential verified. Keep stock for first test.')
            z = item.find("XDFAXIS[@id='z']")
            z.find('EMBEDDEDDATA').set('mmedaddress', f'0x{address:X}')
            z.find('MATH').set('equation', 'X/128')
            z.find('units').text = 'km/h'
            z.find('max').text = '511.9921875'
            root.append(item)
            manifest['added'].append({'id': ident, 'pattern': pattern, 'address': f'0x{address:05X}',
                                      'raw_counts': counts, 'expected': expected, 'max_abs_error': 0.0})
    root.find('XDFHEADER/deftitle').text = 'AL5 15184109 / 15183960 - iMob Racing Structural TCC and WOT v0.5'
    root.find('XDFCONSTANT/description').text = (
        'For 57,304-byte calibration segments only. Offline inspection and development. '
        'Native CRC16 and BE16 compensation are implemented in Tools/AL5/checksum.py '
        'and reproduce stock/PPEI fields; additional native edited-segment validation is pending. '
        'The AL5 write protocol is unresolved and live writing is disabled. '
        'No edited BIN is flash-ready. New TCC/WOT entries use structural confidence, '
        'not marker differentials. The user has no FlashScan.')
    ET.indent(root, space='  ')
    ET.ElementTree(root).write(args.output, encoding='utf-8', xml_declaration=True)
    args.manifest.write_text(json.dumps(manifest, indent=2)+'\n')
    print('Added', len(manifest['added']), 'WOT upshift speed vectors')
