"""Add firmware-selected raw vectors to a research XDF without assigning native IDs."""
import argparse
import copy
import json
import struct
import xml.etree.ElementTree as ET
from pathlib import Path
from al5_segment import START, sha256, validate

FAMILIES = {
    0x13950: 'mode 1, flag1226 clear or enable11ACC clear',
    0x13A08: 'mode 1, flag1226 set and enable11ACC set',
    0x13AC0: 'mode 2',
    0x13B78: 'other mode, flag1226 clear or enable11ACD clear',
    0x13C30: 'other mode, flag1226 set and enable11ACD set',
}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'stock', 'evidence', 'output', 'manifest'):
        p.add_argument('--'+name, type=Path, required=True)
    args = p.parse_args()
    stock = args.stock.read_bytes()
    evidence_bytes = args.evidence.read_bytes()
    evidence = json.loads(evidence_bytes)
    if validate(stock) or evidence['stock_sha256'] != sha256(stock) or not evidence['all_match']:
        raise ValueError('stock or selection evidence validation failed')
    seen = {int(c['table_header'], 0) for c in evidence['cases'] if c['match']}
    root = ET.parse(args.source).getroot()
    template = next(t for t in root.findall('XDFTABLE') if t.findtext('title').startswith('D5010 '))
    uid = max(int(t.get('uniqueid'), 0) for t in root if t.get('uniqueid'))+1
    manifest = {'source_xdf_sha256': sha256(args.source.read_bytes()), 'stock_sha256': sha256(stock),
        'selection_evidence_sha256': sha256(evidence_bytes),
        'confidence': 'firmware-selected raw locations; native IDs, physical mode and gear names unassigned',
        'added': []}
    for base, condition in FAMILIES.items():
        for column in range(5):
            header = base+column*36
            address = header+2
            if header not in seen or stock[header-START:address-START] != b'\x00\x11':
                raise ValueError('vector lacks verified selection/header evidence')
            raw = list(struct.unpack_from('>17H', stock, address-START))
            item = copy.deepcopy(template)
            item.set('uniqueid', f'0x{uid:X}')
            uid += 1
            item.find('title').text = f'RESEARCH raw throttle candidate 0x{base:05X} - Selector index {column}'
            item.find('description').text = (
                f'Firmware selection: {condition}; signed selector byte A5+0x2286={column}. '
                '17 BE16 raw words, 0x0011 header and 0x24 stride verified offline. '
                'No native calibration ID, actual gear name, physical operating mode, '
                'row-axis unit or percentage conversion is assigned. Inspection only; keep stock.')
            item.find('CATEGORYMEM').set('category', '10')
            item.find("XDFAXIS[@id='x']/LABEL").set('value', f'Selector index {column}')
            y = item.find("XDFAXIS[@id='y']")
            y.find('unittype').text = '0'
            for label in y.findall('LABEL'):
                label.set('value', f'Raw row {label.get("index")}')
            z = item.find("XDFAXIS[@id='z']")
            z.find('EMBEDDEDDATA').set('mmedaddress', f'0x{address:X}')
            z.find('EMBEDDEDDATA').set('mmedtypeflags', '0x00')
            z.find('MATH').set('equation', 'X')
            z.find('units').text = 'raw counts'
            if z.find('decimalpl') is not None:
                z.find('decimalpl').text = '0'
            z.find('min').text = '0'
            z.find('max').text = '65535'
            root.append(item)
            manifest['added'].append({'family_header': f'0x{base:05X}', 'condition': condition,
                'selector_index': column, 'data_address': f'0x{address:05X}', 'raw_counts': raw})
    root.find('XDFHEADER/deftitle').text = 'AL5 15184109 / 15183960 - iMob Racing Research Supplement v0.8'
    warning = root.find('XDFCONSTANT/description')
    warning.text += (' v0.8 adds unassigned raw research vectors only. Native ID coverage remains '
                     '105/127; the named definition baseline remains v0.7. Live writing remains disabled.')
    ET.indent(root, space='  ')
    ET.ElementTree(root).write(args.output, encoding='utf-8', xml_declaration=True)
    args.manifest.write_text(json.dumps(manifest, indent=2)+'\n')
    print('Added', len(manifest['added']), 'unassigned raw vectors')
