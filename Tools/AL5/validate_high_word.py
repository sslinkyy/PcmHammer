"""Validate the offline H0105 high-word marker and update XDF confidence only."""
import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from al5_segment import START, sha256
from expand_marker_mappings import SCALARS, check_evidence

CASE = {'id':'H0105', 'column':0, 'row':0, 'expected':2485.4839968,
        'target':100000, 'columns':1, 'rows':1}


def verify(report, stock, native):
    check_evidence(report, [CASE], stock, native,
                   expected_tool='AL5-high-word-differential-mapper-0.6.1', expected_count=1)
    address, bits, signed, equation = SCALARS['H0105']
    if abs(native['H0105']['limits']['hard_max']-0xFFFFFFFF*0.6213709992) >= .001:
        raise ValueError('native unsigned 32-bit maximum mismatch')
    marker = report['cases'][0]['marker']
    changes = report['cases'][0]['changed_bytes']
    before = stock[address-START:address-START+4]
    after = bytearray(before)
    for b in changes:
        after[b['address']-address] = b['after']
    if before[:2] == after[:2] or int.from_bytes(after[:2],'big') == 0:
        raise ValueError('marker does not establish a nonzero high word')
    if abs(marker['readback']-marker['requested']) >= 0.6213709992:
        raise ValueError('marker readback differs by more than one raw count')
    return {'id':'H0105', 'address':f'0x{address:05X}', 'bits':bits,
            'equation':equation, 'units':'count/km', 'before_hex':before.hex().upper(),
            'after_hex':after.hex().upper(), 'before_raw':int.from_bytes(before,'big'),
            'after_raw':int.from_bytes(after,'big'), 'requested':marker['requested'],
            'readback':marker['readback'], 'high_word_changed':True,
            'confidence':'high-word and low-word marker evidence plus native unsigned BE32 maximum',
            'limit':'most significant byte remained zero; GUI display not yet checked',
            'checksum_finalized':False, 'flash_ready':False}


def update_xdf(source, evidence):
    root = ET.parse(source).getroot()
    item = next(t for t in root.findall('XDFCONSTANT') if t.findtext('title').startswith('H0105 '))
    embedded = item.find('EMBEDDEDDATA')
    if (int(embedded.get('mmedaddress'),0), int(embedded.get('mmedelementsizebits')),
            item.find('MATH').get('equation')) != (0x152E4,32,'X*0.6213709992'):
        raise ValueError('source XDF differs from validated encoding')
    item.find('description').text = (
        'Offline EFILive isolated marker evidence: the original low-word case and '
        'a separate high-word case confirm H0105 at 0x152E4. Stock 00000FA0 changed '
        'to 000274A6 for requested 100000 count/km, readback 99999.7203852528. '
        'Unsigned BE32 interpretation is corroborated by the native hard maximum '
        'and nonzero high word. The most significant byte remained zero. '
        'Each case restored the full raw baseline and left the GUI image unchanged. '
        'Unit factor follows the native export. TunerPro GUI display validation '
        'pending. Keep stock for the first vehicle test; no edited BIN is flash-ready.')
    warning = root.find('XDFCONSTANT/description')
    warning.text = warning.text.replace('v0.9 adds isolated marker mappings; H0105 high-word width remains inferred.',
                                       'v0.9.1 adds H0105 high-word marker validation; all v0.9 encodings are preserved.')
    root.find('XDFHEADER/deftitle').text = 'AL5 15184109 / 15183960 - iMob Racing Marker Extended v0.9.1'
    ET.indent(root, space='  ')
    return root


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source','stock','export','report','output','manifest'):
        p.add_argument('--'+name, required=True, type=Path)
    args = p.parse_args()
    native = {c['id']:c for c in json.loads(args.export.read_bytes().decode('cp1252'))['calibrations']}
    result = verify(json.loads(args.report.read_text()), args.stock.read_bytes(), native)
    result.update({name+'_sha256':sha256(getattr(args,name).read_bytes())
                   for name in ('source','stock','export','report')})
    root = update_xdf(args.source,result)
    ET.ElementTree(root).write(args.output,encoding='utf-8',xml_declaration=True)
    args.manifest.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
