"""Validate isolated EFILive markers against stock, then extend the named v0.7 XDF."""
import argparse
import copy
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from al5_segment import START, LENGTH, validate, sha256
from audit_xdf import equation

# Width and scaling are checked against BOTH native stock values and marker
# readbacks. H0105's unchanged high word remains structurally inferred.
SCALARS = {
    'D5042': (0x9CFC, 16, True, 'X/4'),
    'D5043': (0x9CFE, 16, True, 'X/4'),
    'D5044': (0x9D00, 16, True, 'X/4'),
    'D5045': (0x9D02, 16, True, 'X/4'),
    'D5055': (0x1378C, 16, True, 'X/128'),
    'D5056': (0x1378E, 16, True, 'X/128'),
    'D5057': (0x1375C, 16, False, 'X/8'),
    'D5058': (0x1375E, 16, False, 'X/8'),
    'D5061': (0x14B14, 16, False, 'X*0.0001220704'),
    'D5062': (0xB03C, 16, True, 'X/4'),
    'D5063': (0xB03E, 16, True, 'X/4'),
    'D5183': (0x803C, 8, False, 'X'),
    'H0103': (0x14B16, 16, False, 'X/8192'),
    'H0105': (0x152E4, 32, False, 'X*0.6213709992'),
    'H0136': (0x15640, 16, False, 'X/32'),
    'H0137': (0x14B18, 16, False, 'X*0.0097089219'),
}
THROTTLE = {'D5073': 0x13B7A, 'D5074': 0x13952, 'D5075': 0x13AC2}
TCC_G = {'D5010': 0x133F2, 'D5015': 0x13416}


def layout(ident, col, row):
    if ident in SCALARS:
        return SCALARS[ident]
    if ident in THROTTLE:
        return THROTTLE[ident]+36*col+2*row, 16, False, 'X*100/65536'
    if ident in TCC_G and col == 6:
        return TCC_G[ident]+2*row, 16, False, 'X/128'
    if ident in ('D5035', 'D5036', 'D5037', 'D5038') and col in (0, 3):
        return {0: 0x12570, 3: 0x12840}[col]+6*(int(ident[1:])-5035)+2*row, 16, False, 'X/128'
    raise ValueError('unsupported marker identity/column')


def check_evidence(report, cases, stock, native):
    if validate(stock):
        raise ValueError('invalid stock segment')
    for key in ('completed', 'secondary_closed'):
        if report.get(key) is not True:
            raise ValueError('incomplete marker pass: '+key)
    for key in ('vehicle_io', 'gui_descriptor_modified', 'secondary_saved', 'flash_ready', 'checksum_finalized'):
        if report.get(key) is not False:
            raise ValueError('unsafe or incompatible report flag: '+key)
    if report.get('error') or report.get('close_error'):
        raise ValueError('report contains an error')
    if (report.get('controller'), report.get('operating_system'), report.get('transmission')) != ('AL5', 15184109, 15183960):
        raise ValueError('wrong controller context')
    if report.get('tool') != 'AL5-targeted-differential-mapper-0.6':
        raise ValueError('unexpected mapper version')
    for key in ('gui_raw_unchanged', 'raw_coherency_and_restore', 'secondary_baseline_equals_gui'):
        if report.get('validation', {}).get(key) is not True:
            raise ValueError('baseline validation missing: '+key)
    expected = {(c['id'], c['column'], c['row']): c for c in cases}
    if len(expected) != 83 or len(report['cases']) != len(expected):
        raise ValueError('missing or duplicate marker cases')
    seen = set()
    verified = []
    for record in report['cases']:
        marker = record['marker']
        key = (marker['id'], marker['column'], marker['row'])
        if key not in expected or key in seen or record.get('restored') is not True:
            raise ValueError('unexpected, duplicate or unrestored marker')
        seen.add(key)
        source = expected[key]
        if abs(marker['before']-source['expected']) > .001 or marker['requested'] != source['target']:
            raise ValueError('marker differs from prepared manifest')
        ident, col, row = key
        if abs(native[ident]['cells'][row][col]-marker['before']) > .001:
            raise ValueError('marker differs from native reference')
        address, bits, signed, math = layout(*key)
        width = bits//8
        offset = address-START
        old = stock[offset:offset+width]
        new = bytearray(old)
        changes = record['changed_bytes']
        if not changes or record['changed_byte_count'] != len(changes):
            raise ValueError('empty/inconsistent changed bytes')
        byte_seen = set()
        for b in changes:
            a = b['address']
            if a in byte_seen or not address <= a < address+width:
                raise ValueError('coupled/out-of-field or duplicate changed byte')
            byte_seen.add(a)
            if b['before'] != stock[a-START] or not 0 <= b['after'] <= 255 or b['before'] == b['after']:
                raise ValueError('changed byte disagrees with stock')
            new[a-address] = b['after']
        for raw, value in ((old, marker['before']), (new, marker['readback'])):
            decoded = equation(math, int.from_bytes(raw, 'big', signed=signed))
            if abs(decoded-value) >= .001:
                raise ValueError('encoding disagrees with native/readback for '+ident)
        # Verify all reported context bytes, not just the inferred field.
        covered = set()
        for diff in record['diff_ranges']:
            start, end = diff['context_start'], diff['context_end']
            if not START <= start <= end < START+LENGTH:
                raise ValueError('context outside segment')
            before = bytes.fromhex(diff['before_hex'])
            after = bytes.fromhex(diff['after_hex'])
            if len(before) != end-start+1 or len(after) != len(before) or before != stock[start-START:end-START+1]:
                raise ValueError('context mismatch')
            wanted = bytearray(before)
            for b in changes:
                if start <= b['address'] <= end:
                    wanted[b['address']-start] = b['after']
                    covered.add(b['address'])
            if after != wanted:
                raise ValueError('unreported context changes')
        if covered != byte_seen:
            raise ValueError('context does not cover changes')
        verified.append({'id': ident, 'column': col, 'row': row,
                         'address': f'0x{address:05X}', 'bits': bits, 'equation': math})
    return verified


def expand(source, stock, native, report, manifest):
    verified = check_evidence(report, manifest['cases'], stock, native)
    root = ET.parse(source).getroot()
    scalar_template = next(t for t in root.findall('XDFCONSTANT') if t.findtext('title').startswith('D1205 '))
    vector_template = next(t for t in root.findall('XDFTABLE') if t.findtext('title').startswith('D5010 '))
    uid = max(int(t.get('uniqueid'), 0) for t in root if t.get('uniqueid'))+1
    additions = []
    fields = [(id, 0, 1) for id in SCALARS]
    fields += [(id, col, 17) for id in THROTTLE for col in range(5)]
    fields += [(id, 6, 17) for id in TCC_G]
    fields += [(id, col, 2) for id in ('D5035', 'D5036', 'D5037', 'D5038') for col in (0, 3)]
    for ident, col, rows in fields:
        c = native[ident]
        address, bits, signed, math = layout(ident, col, 0)
        # All vector headers and every stock cell must agree independently.
        if rows > 1 and stock[address-START-2:address-START] != rows.to_bytes(2, 'big'):
            raise ValueError('vector header mismatch')
        for row in range(rows):
            a, b, s, eq = layout(ident, col, row)
            raw = int.from_bytes(stock[a-START:a-START+b//8], 'big', signed=s)
            if abs(equation(eq, raw)-c['cells'][row][col]) >= .001:
                raise ValueError('full stock vector mismatch')
        item = copy.deepcopy(scalar_template if rows == 1 else vector_template)
        item.set('uniqueid', f'0x{uid:X}')
        uid += 1
        item.find('title').text = f'{ident} {c["api_description"]}' + (f' - Native Column {col}: {c["columns"][col]}' if rows > 1 else '')
        item.find('description').text = (
            'Isolated EFILive v6 marker evidence: named scalar or vector row samples changed '
            'only this field; each case restored the full raw baseline. All stock cells '
            'decode against the native export. Vector rows 0/8/16 are marker-tested for '
            '17-cell vectors; both rows are marker-tested for two-cell vectors. Other '
            'vector cells have structural confidence. GUI display validation pending. Keep stock.')
        if ident == 'H0105':
            item.find('description').text += (
                ' IMPORTANT: marker proves only the low word at 0x152E6. Unsigned BE32 '
                'width starting 0x152E4 is inferred from native hard maximum / unit scale '
                'and zero high word. A high-word marker is still required before editing.')
        if ident == 'D5183':
            item.find('description').text += ' Locked counter: diagnostic inspection only; do not edit.'
        if ident.startswith('H') or ident == 'D5061':
            category = '2'
        elif ident == 'D5183':
            category = '1'
        elif ident in ('D5062','D5063'):
            category = '5'
        elif ident in ('D5035','D5036','D5037','D5038'):
            category = '4'
        else:
            category = '9'
        item.find('CATEGORYMEM').set('category', category)
        container = item if rows == 1 else item.find("XDFAXIS[@id='z']")
        embedded = container.find('EMBEDDEDDATA')
        embedded.set('mmedaddress', f'0x{address:X}')
        embedded.set('mmedelementsizebits', str(bits))
        embedded.set('mmedtypeflags', '0x01' if signed else '0x00')
        container.find('MATH').set('equation', math)
        container.find('units').text = c['api_default_units']
        container.find('decimalpl').text = '4' if ident.startswith('H') or ident=='D5061' else '3' if ident in THROTTLE else '0'
        if rows == 1:
            container.find('rangelow').text = str(c['limits']['hard_min'])
            container.find('rangehigh').text = str(c['limits']['hard_max'])
        else:
            embedded.set('mmedrowcount', str(rows))
            container.find('min').text = str(c['limits']['hard_min'])
            container.find('max').text = str(c['limits']['hard_max'])
            item.find("XDFAXIS[@id='x']/LABEL").set('value', str(c['columns'][col]))
            y = item.find("XDFAXIS[@id='y']")
            y.find('indexcount').text = str(rows)
            for label in list(y.findall('LABEL')):
                y.remove(label)
            for row, label in enumerate(c['rows']):
                ET.SubElement(y, 'LABEL', index=str(row), value=str(label))
        root.append(item)
        additions.append({'id': ident, 'column': col, 'address': f'0x{address:05X}', 'bits': bits, 'cells': rows, 'equation': math})
    root.find('XDFHEADER/deftitle').text = 'AL5 15184109 / 15183960 - iMob Racing Marker Extended v0.9'
    root.find('XDFCONSTANT/description').text += ' v0.9 adds isolated marker mappings; H0105 high-word width remains inferred. No edited BIN is flash-ready.'
    ET.indent(root, space='  ')
    return root, {'verified_cases': verified, 'added': additions,
                  'H0105_width_status': 'BE32 structurally inferred; only low word marker verified'}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source','stock','export','report','cases','output','manifest'):
        p.add_argument('--'+name, required=True, type=Path)
    args = p.parse_args()
    native = {c['id']: c for c in json.loads(args.export.read_bytes().decode('cp1252'))['calibrations']}
    case_manifest = json.loads(args.cases.read_text())
    if case_manifest['reference_sha256'] != sha256(args.export.read_bytes()):
        raise ValueError('native reference differs from prepared case manifest')
    root, result = expand(args.source, args.stock.read_bytes(), native,
                          json.loads(args.report.read_text()), case_manifest)
    result.update({name+'_sha256': sha256(getattr(args, name).read_bytes())
                   for name in ('source','stock','export','report','cases')})
    ET.ElementTree(root).write(args.output, encoding='utf-8', xml_declaration=True)
    args.manifest.write_text(json.dumps(result, indent=2)+'\n')
    print('Verified cases:',len(result['verified_cases']),'Added items:',len(result['added']))
