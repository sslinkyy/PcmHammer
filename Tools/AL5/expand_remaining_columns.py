"""Verify isolated E-H markers before extending the existing XDF."""
import argparse
import copy
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from al5_segment import START, validate, sha256
from checksum import checksum_valid
from verify_enum_checksum_pass import reconstruct

BASES = {'D5000': (0x11BC8, 0x11C10, 0x11C58, 0x11CA0),
         'D5005': (0x11BEC, 0x11C34, 0x11C7C, 0x11CC4)}


def verify(report, prepared, stock, native):
    if validate(stock) or not checksum_valid(stock):
        raise ValueError('invalid stock segment')
    if report.get('tool') != 'AL5-remaining-columns-mapper-0.9':
        raise ValueError('wrong report version')
    if (report.get('controller'), report.get('operating_system'), report.get('transmission')) != ('AL5', 15184109, 15183960):
        raise ValueError('wrong controller context')
    for key in ('completed', 'secondary_closed'):
        if report.get(key) is not True: raise ValueError('incomplete report')
    for key in ('vehicle_io', 'gui_descriptor_modified', 'secondary_saved', 'checksum_finalized', 'flash_ready'):
        if report.get(key) is not False: raise ValueError('invalid safety flag')
    for key in ('gui_raw_unchanged', 'raw_coherency_and_restore', 'secondary_baseline_equals_gui'):
        if report.get('validation', {}).get(key) is not True: raise ValueError('missing baseline check')
    if report.get('error') or report.get('close_error') or len(report['cases']) != 24 or len(prepared['cases']) != 24:
        raise ValueError('failed or incomplete cases')
    seen = set()
    for record, case in zip(report['cases'], prepared['cases']):
        marker = record['marker']
        ident, col, row = case['id'], case['column'], case['row']
        if ident not in BASES or col not in range(4, 8) or row not in (0, 8, 16):
            raise ValueError('unexpected prepared coordinate')
        seen.add((ident, col, row))
        for key in ('id', 'column', 'row', 'label'):
            if marker[key] != case[key]: raise ValueError('marker identity mismatch')
        wanted = native[ident]['cells'][row][col]
        if marker['before'] != wanted or case['expected'] != wanted or marker['requested'] != 200 or case['target'] != 200 or marker['readback'] != 200:
            raise ValueError('marker value mismatch')
        address = BASES[ident][col-4] + 2*row
        marked = reconstruct(stock, record['changed_bytes'], {address, address+1})
        if record.get('restored') is not True or record['changed_byte_count'] != len(record['changed_bytes']) or not record['changed_bytes']:
            raise ValueError('unrestored or empty marker')
        if int.from_bytes(marked[address-START:address-START+2], 'big') != 25600:
            raise ValueError('marker encoding mismatch')
        covered = set()
        for context in record['diff_ranges']:
            a, b = context['context_start'], context['context_end']
            if not START <= a <= b < START+len(stock): raise ValueError('invalid context bounds')
            if bytes.fromhex(context['before_hex']) != stock[a-START:b-START+1] or bytes.fromhex(context['after_hex']) != marked[a-START:b-START+1]:
                raise ValueError('context mismatch')
            covered.update(range(a, b+1))
        if not {c['address'] for c in record['changed_bytes']} <= covered:
            raise ValueError('missing marker context')
    if len(seen) != 24: raise ValueError('duplicate marker coordinates')
    vectors = []
    for ident, bases in BASES.items():
        for col, base in enumerate(bases, 4):
            offset = base-START
            if stock[offset-2:offset] != b'\x00\x11': raise ValueError('vector header mismatch')
            values = [int.from_bytes(stock[offset+2*r:offset+2*r+2], 'big')/128 for r in range(17)]
            if any(abs(value-native[ident]['cells'][r][col]) >= .001 for r, value in enumerate(values)):
                raise ValueError('full vector mismatch')
            vectors.append({'id': ident, 'column': col, 'pattern': chr(65+col), 'address': hex(base),
                            'bits': 16, 'rows': 17, 'equation': 'X/128', 'stock_values': values,
                            'marker_rows': [0, 8, 16]})
    return {'vectors': vectors, 'marker_cases': 24, 'stock_compared_cells': 136,
            'confidence': 'Three isolated marker rows per vector; every stock cell matches native export.',
            'limits': 'Runtime selection and new-vector GUI validation remain unproven.', 'flash_ready': False}


def expand(source, evidence):
    root = ET.parse(source).getroot()
    uid = max(int(item.get('uniqueid'), 0) for item in root if item.tag in ('XDFCONSTANT', 'XDFTABLE'))
    for vector in evidence['vectors']:
        ident = vector['id']
        template = next(item for item in root.findall('XDFTABLE') if item.findtext('title', '').startswith(ident+' ') and 'Pattern A' in item.findtext('title'))
        item = copy.deepcopy(template)
        uid += 1
        item.set('uniqueid', hex(uid))
        item.find('title').text = template.findtext('title').split(' - Pattern')[0] + f" - Native Column {vector['column']}: Pattern {vector['pattern']}"
        item.find('description').text = ('Isolated EFILive markers confirm rows 0, 8 and 16 and full restoration. '
            'All 17 stock cells match the native export; contiguous BE16 /128 encoding and 0011 header verified. '
            'Native throttle labels retained. Pattern runtime selection and GUI validation pending. Keep stock.')
        item.find("XDFAXIS[@id='x']/LABEL").set('value', 'Pattern '+vector['pattern'])
        item.find("XDFAXIS[@id='z']/EMBEDDEDDATA").set('mmedaddress', vector['address'])
        item.find("XDFAXIS[@id='z']/max").text = '511.9921875'
        root.append(item)
    root.find('XDFHEADER/deftitle').text = 'AL5 15184109 / 15183960 - iMob Racing Marker Extended v0.12'
    root.find('XDFCONSTANT/description').text = (
        'For 57,304-byte calibration segments only. Offline inspection and development. '
        'v0.12 represents 127/127 native IDs and matches all 2517 numeric stock cells to the native export. '
        'Confidence varies: full stock decoding is not marker proof of every cell or runtime/GUI validation. '
        'The native checksum formula matches stock, PPEI and three independently EFILive-finalized edits. '
        'Physical programming and recovery remain unproven. AL5 live writing is blocked; no edited BIN is flash-ready.')
    ET.indent(root, space='  ')
    return root


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'report', 'prepared', 'stock', 'export', 'output', 'manifest'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    native = {c['id']: c for c in json.loads(args.export.read_bytes().decode('cp1252'))['calibrations']}
    evidence = verify(json.loads(args.report.read_text(encoding='utf8')), json.loads(args.prepared.read_text(encoding='utf8')), args.stock.read_bytes(), native)
    evidence.update({name+'_sha256': sha256(getattr(args, name).read_bytes()) for name in ('source', 'report', 'prepared', 'stock', 'export')})
    ET.ElementTree(expand(args.source, evidence)).write(args.output, encoding='utf-8', xml_declaration=True)
    args.manifest.write_text(json.dumps(evidence, indent=2)+'\n', encoding='utf8')
    print('Verified 24 isolated markers and 136 stock cells; appended eight vectors.')
