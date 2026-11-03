"""Expand the verified v0.13 XDF with two traced shift-stage RPM constants.

Only absent XDF/report output paths are written. Source BINs remain read only.
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
FIELDS = (
    ('D5057', 0x145E0, 900, 'Set',
     'With a clear inhibit latch, RPM strictly below this threshold sets the inhibit.'),
    ('D5058', 0x145E2, 1050, 'Clear',
     'With the inhibit latch set, RPM reaching or exceeding this threshold clears it.'),
)


def build(source, stock, evidence_dir):
    baseline = json.loads((evidence_dir/'CRUISE_TCC_MAPPING_v0_13.json').read_bytes())
    if sha256(source) != baseline['xdf_sha256']:
        raise ValueError('source is not the verified v0.13 XDF')
    if validate(stock) or sha256(stock) != STOCK_SHA:
        raise ValueError('stock identity or segment anchors differ')
    evidence = {}
    for name in ('TCC_RPM_SELECTOR_20261103.json', 'TCC_ALTERNATE_RPM_EFFECT_20261103.json'):
        raw = (evidence_dir/name).read_bytes()
        if not json.loads(raw)['all_match']:
            raise ValueError('trace evidence failed: '+name)
        evidence[name] = sha256(raw)
    root = ET.fromstring(source)
    prior = [ET.tostring(i) for i in root if i.tag in ('XDFCONSTANT', 'XDFTABLE')]
    if len(prior) != 308:
        raise ValueError('expected 308 baseline entries')
    uid = max(int(i.get('uniqueid'), 0) for i in root if i.get('uniqueid'))+1
    category = max(int(c.get('index'), 0) for c in root.findall('XDFHEADER/CATEGORY'))+1
    ET.SubElement(root.find('XDFHEADER'), 'CATEGORY',
                  index=hex(category), name='TCC / Shift-Stage RPM Inhibit')
    added = []
    for template_id, address, expected, action, behavior in FIELDS:
        template = next(i for i in root.findall('XDFCONSTANT')
                        if i.findtext('title').startswith(template_id+' '))
        item = copy.deepcopy(template)
        item.set('uniqueid', hex(uid))
        uid += 1
        item.find('title').text = f'TCC Low-RPM Lockup Inhibit {action} - Active Shift Stage'
        item.find('description').text = (
            'Firmware-traced alternate RPM threshold, selected when A5+0x2D1D=1 '
            '(active shift-control stage). Exact OEM fill/torque/inertia phase name remains '
            'unresolved. Other selector states use D5057/D5058. '+behavior+' '
            'The inhibit latch is shared across both pairs. Low-RPM inhibition feeds '
            'the release/off request path; clearing it allows other lockup logic to proceed. '
            'State-7 enforcement depends on calibration byte 0x145B6 (stock 1). '
            'Unsigned BE16, RPM=raw/8. No EFILive ID is assigned to this alternate field. '
            'Evidence: TCC_ALTERNATE_RPM_TRACE.md; extracted-code selection/hysteresis '
            'and release-chain replay, not alternate-field native marker proof. '
            'TunerPro GUI validation for these two entries remains pending.')
        item.find('CATEGORYMEM').set('category', str(category+1))
        embedded = item.find('EMBEDDEDDATA')
        embedded.set('mmedaddress', hex(address))
        embedded.set('mmedtypeflags', '0x00')
        embedded.set('mmedelementsizebits', '16')
        item.find('units').text = 'rpm'
        item.find('decimalpl').text = '3'
        item.find('MATH').set('equation', 'X/8')
        item.find('rangelow').text = '0'
        item.find('rangehigh').text = '8191.875'
        raw = struct.unpack_from('>H', stock, address-START)[0]
        values = decode(item, stock)
        if raw != expected*8 or values != [expected]:
            raise ValueError('stock RPM mismatch')
        if [equation('X/8', v) for v in (0, 1, 65535)] != [0, .125, 8191.875]:
            raise ValueError('RPM scaling mismatch')
        root.append(item)
        added.append({'title': item.findtext('title'), 'native_address': hex(address),
                      'segment_offset': address-START, 'raw_hex': f'{raw:04X}',
                      'stock_raw': raw, 'stock_rpm': values[0],
                      'stock_display': f'{values[0]:.3f}', 'units': 'rpm',
                      'behavior': behavior})
    if prior != [ET.tostring(i) for i in root if i.tag in ('XDFCONSTANT','XDFTABLE')][:308]:
        raise ValueError('baseline entry changed')
    root.find('XDFHEADER/deftitle').text = 'AL5 15184109 / 15183960 - iMob Racing Extended TCC v0.14'
    root.find('XDFHEADER/description').text += (
        ' v0.14 adds the alternate shift-stage RPM inhibit set/clear constants. '
        'See TCC_ALTERNATE_RPM_TRACE.md for exact conditions and limits.')
    ET.indent(root, space='  ')
    return root, {'source_xdf_sha256': sha256(source), 'stock_sha256': sha256(stock),
                  'evidence_sha256': evidence, 'previous_items_preserved': 308,
                  'added': added, 'scaling': 'unsigned BE16 /8 RPM',
                  'all_stock_values_match': True, 'gui_validation': 'pending for the two new RPM constants'}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source','stock','ppei','export','evidence-dir','output','manifest','audit'):
        p.add_argument('--'+name, type=Path, required=True)
    args = p.parse_args()
    outputs = [args.output, args.manifest, args.audit]
    if len({x.resolve() for x in outputs}) != 3 or any(x.exists() for x in outputs):
        raise ValueError('select distinct absent output paths')
    stock, ppei = args.stock.read_bytes(), args.ppei.read_bytes()
    root, manifest = build(args.source.read_bytes(), stock, args.evidence_dir)
    with args.output.open('xb') as f:
        ET.ElementTree(root).write(f, encoding='utf-8', xml_declaration=True)
    report = audit(args.output, stock, ppei, args.export)
    if report['status'] != 'pass' or not report['coverage']['numeric_coverage_complete']:
        raise ValueError('full audit failed')
    manifest['xdf_sha256'] = sha256(args.output.read_bytes())
    manifest['inputs'] = {n: str(getattr(args,n)) for n in ('source','stock','ppei','export')}
    for path, obj in ((args.manifest, manifest), (args.audit, report)):
        with path.open('x', encoding='utf-8', newline='\n') as f:
            f.write(json.dumps(obj, indent=2)+'\n')
    if args.stock.read_bytes() != stock or args.ppei.read_bytes() != ppei:
        raise ValueError('source BIN changed')
    print(json.dumps({'status':report['status'],'items':len(report['items']),
                      'native_numeric_cells':report['coverage']['compared_unique_numeric_cell_count'],
                      'added_stock_rpm':[i['stock_rpm'] for i in manifest['added']],
                      'bins_unchanged':True}))
