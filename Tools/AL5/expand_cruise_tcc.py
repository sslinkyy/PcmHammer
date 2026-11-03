"""Add traced cruise TCC banks to XDF v0.12 and audit local stock values.

BINs are read only. Each five-column bank uses the established per-gear vector
presentation so 0x0011 count headers between columns are never editable cells.
"""
import argparse
import copy
import json
import struct
import xml.etree.ElementTree as ET
from pathlib import Path
from al5_segment import START, sha256, validate
from audit_xdf import audit, decode, equation

STOCK_SHA = '140b70ea90cb57c20aaab2d9641d2b7caaa6bf312c89bd9369b27b8bce5fcbe6'
BANKS = ((0x13A08, 'Tow/Haul', 'D5074', 'mode 1', '0x11ACC'),
         (0x13C30, 'Normal', 'D5073', 'other than mode 1 or 2', '0x11ACD'))


def build(source, stock, evidence_dir):
    if validate(stock) or sha256(stock) != STOCK_SHA:
        raise ValueError('stock segment identity/anchors do not match the traced calibration')
    evidence = {}
    for name, key in (('TCC_ALTERNATE_FLAG_PRODUCERS_20261102.json', 'all_replay_cases_pass'),
                      ('TCC_THROTTLE_AXES_20261102.json', 'all_match'),
                      ('TCC_THROTTLE_EFFECT_20261103.json', 'all_match'),
                      ('TCC_RELEASE_ARBITRATION_20261102.json', 'all_match')):
        raw = (evidence_dir / name).read_bytes()
        if not json.loads(raw)[key]:
            raise ValueError('required trace evidence failed: ' + name)
        evidence[name] = sha256(raw)
    root = ET.fromstring(source)
    originals = [ET.tostring(item) for item in root if item.tag in ('XDFTABLE', 'XDFCONSTANT')]
    if len(originals) != 298:
        raise ValueError('expected the complete v0.12 baseline')
    uid = max(int(t.get('uniqueid'), 0) for t in root if t.get('uniqueid')) + 1
    category_index = max(int(c.get('index'), 0) for c in root.findall('XDFHEADER/CATEGORY')) + 1
    ET.SubElement(root.find('XDFHEADER'), 'CATEGORY',
                  index=hex(category_index), name='TCC / Cruise Throttle Release')
    records = []
    for base, mode, native_id, selector, enable in BANKS:
        for gear in range(5):
            template = next(t for t in root.findall('XDFTABLE')
                            if t.findtext('title').startswith(native_id + ' ')
                            and f'Native Column {gear}:' in t.findtext('title'))
            item = copy.deepcopy(template)
            item.set('uniqueid', hex(uid))
            uid += 1
            gear_label = template.find("XDFAXIS[@id='x']/LABEL").get('value')
            item.find('title').text = f'TCC Throttle Release, {mode}, Cruise Active - {gear_label}'
            item.find('description').text = (
                f'Offline firmware-traced cruise-conditioned alternate to {native_id}; '
                f'family header 0x{base:05X}, {selector}, enable byte {enable}. '
                'Cruise flag A5+0x1226 requires active cruise and the allowed speed window '
                'around the normalized cruise set-speed reference (stock approximately +/-10 km/h). '
                'Rows: filtered vehicle speed, km/h; units corroborated by the shared native '
                'axis and speed producer. Column uses selected gear state, not measured achieved gear. '
                'Unsigned BE16; percent=raw*100/65536; 0x0011 count header; 0x24 record stride. '
                'Maximum throttle parameter for the release path; downstream model, acceleration '
                'gate and overrides apply. Stock raw 65535=99.99847412109375%. '
                'Firmware/replay evidence, not native marker proof of this alternate bank. '
                'See TCC_CRUISE_THROTTLE_RELEASE_TRACE.md. TunerPro GUI validation pending.')
            item.find('CATEGORYMEM').set('category', str(category_index + 1))
            y = item.find("XDFAXIS[@id='y']")
            if [int(l.get('value')) for l in y.findall('LABEL')] != list(range(0, 257, 16)):
                raise ValueError('unexpected native speed labels')
            ET.SubElement(y, 'units').text = 'km/h'
            address = base + gear * 36 + 2
            z = item.find("XDFAXIS[@id='z']")
            z.find('EMBEDDEDDATA').set('mmedaddress', hex(address))
            z.find('EMBEDDEDDATA').set('mmedtypeflags', '0x00')
            z.find('MATH').set('equation', 'X*100/65536')
            z.find('max').text = str(65535 * 100 / 65536)
            z.find('decimalpl').text = '3'
            offset = address - START
            if stock[offset-2:offset] != b'\x00\x11':
                raise ValueError('invalid vector count header')
            raw_values = list(struct.unpack_from('>17H', stock, offset))
            displayed = decode(item, stock)
            if raw_values != [65535] * 17 or displayed != [65535 * 100 / 65536] * 17:
                raise ValueError('unexpected cruise-bank stock values/scaling')
            if [equation(z.find('MATH').get('equation'), v) for v in (0, 32768, 65535)] != [0, 50, 65535*100/65536]:
                raise ValueError('incorrect endpoint/midpoint conversion')
            root.append(item)
            records.append({'bank_header': hex(base), 'mode': mode, 'gear': gear_label,
                            'data_address': hex(address), 'segment_offset': offset,
                            'stock_raw': raw_values, 'stock_percent': displayed})
    # Header metadata may change; all pre-existing calibration definitions must remain identical.
    if [ET.tostring(i) for i in root if i.tag in ('XDFTABLE', 'XDFCONSTANT')][:298] != originals:
        raise ValueError('pre-existing definition changed')
    root.find('XDFHEADER/deftitle').text = 'AL5 15184109 / 15183960 - iMob Racing Cruise TCC v0.13'
    root.find('XDFHEADER/description').text += (
        ' v0.13 adds two traced cruise TCC banks as ten per-gear vectors. '
        'See TCC_CRUISE_THROTTLE_RELEASE_TRACE.md for confidence and operating conditions.')
    ET.indent(root, space='  ')
    return root, {'source_xdf_sha256': sha256(source), 'stock_sha256': sha256(stock),
                  'evidence_sha256': evidence, 'previous_items_preserved': 298,
                  'added_banks': 2, 'added_vectors': 10, 'compared_stock_cells': 170,
                  'speed_labels_kmh': list(range(0, 257, 16)),
                  'scaling': 'unsigned BE16 * 100 / 65536', 'added': records,
                  'gui_validation': 'pending', 'all_stock_values_match': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'stock', 'ppei', 'export', 'evidence-dir', 'output', 'manifest', 'audit'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    outputs = [args.output, args.manifest, args.audit]
    if len({p.resolve() for p in outputs}) != 3 or any(p.exists() for p in outputs):
        raise ValueError('select three distinct, absent output paths')
    stock, ppei = args.stock.read_bytes(), args.ppei.read_bytes()
    root, manifest = build(args.source.read_bytes(), stock, args.evidence_dir)
    with args.output.open('xb') as output:
        ET.ElementTree(root).write(output, encoding='utf-8', xml_declaration=True)
    report = audit(args.output, stock, ppei, args.export)
    if report['status'] != 'pass' or not report['coverage']['numeric_coverage_complete']:
        raise ValueError('full XDF audit failed')
    manifest['xdf_sha256'] = sha256(args.output.read_bytes())
    manifest['inputs'] = {name: str(getattr(args, name)) for name in ('source', 'stock', 'ppei', 'export')}
    for path, value in ((args.manifest, manifest), (args.audit, report)):
        with path.open('x', encoding='utf-8', newline='\n') as output:
            output.write(json.dumps(value, indent=2) + '\n')
    if args.stock.read_bytes() != stock or args.ppei.read_bytes() != ppei:
        raise ValueError('source BIN changed during validation')
    print(json.dumps({'status': report['status'], 'items': len(report['items']),
                      'native_cells': report['coverage']['compared_unique_numeric_cell_count'],
                      'added_stock_cells': manifest['compared_stock_cells'],
                      'stock_percent': manifest['added'][0]['stock_percent'][0],
                      'bins_unchanged': True}))
