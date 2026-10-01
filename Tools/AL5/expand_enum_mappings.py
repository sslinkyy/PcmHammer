"""Add marker/firmware-confirmed AL5 adaptive-enable bytes; preserve prior encodings."""
import argparse
import copy
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from al5_segment import START, sha256
from verify_enum_checksum_pass import verify

FIELDS={'D5053':(0xF6AC,0x730BC),'D5054':(0xCCF2,0x72FFA)}


def expand(source, stock, native, report, references, high):
    checked=verify(report,stock)
    if not checked['all_checksums_match']:
        raise ValueError('independent native checksum verification failed')
    if references['high_sha256']!=sha256(high):
        raise ValueError('firmware reference hash mismatch')
    root=ET.parse(source).getroot()
    template=next(t for t in root.findall('XDFCONSTANT') if t.findtext('title').startswith('D5233 '))
    uid=max(int(t.get('uniqueid'),0) for t in root if t.get('uniqueid'))+1
    added=[]
    for record in checked['enum_candidates']:
        id=record['id'];address,pc=FIELDS[id]
        if record['changed_bytes']!=[{'address':address,'before':1,'after':0}]:
            raise ValueError('enum evidence does not establish isolated 1 to 0 byte')
        instruction=bytes.fromhex('4a39')+address.to_bytes(4,'big')
        if high[pc-0x20000:pc-0x20000+6]!=instruction:
            raise ValueError('native TST.B reference mismatch')
        if native[id]['cells']!=[['Enable']] or stock[address-START]!=1:
            raise ValueError('native/stock enable baseline mismatch')
        item=copy.deepcopy(template);item.set('uniqueid',f'0x{uid:X}');uid+=1
        item.find('title').text=f'{id} {native[id]["api_description"]} (0=Disable, 1=Enable)'
        item.find('description').text=(
            'Isolated EFILive text marker confirmed Enable=1 and Disable=0 at this byte; '
            'exact readback and full raw restoration passed. Saved firmware uses a full '
            f'byte zero/nonzero test at 0x{pc:05X}; no bit-field encoding is assumed. '
            'Only values 0 and 1 have native label evidence. Keep enabled/stock for '
            'the first vehicle test. TunerPro GUI validation of this new entry is pending.')
        item.find('CATEGORYMEM').set('category','5')
        item.find('EMBEDDEDDATA').set('mmedaddress',f'0x{address:X}')
        root.append(item)
        added.append({'id':id,'address':f'0x{address:05X}','bits':8,
                      'labels':{'0':'Disable','1':'Enable'},'consumer':f'0x{pc:05X}',
                      'confidence':'isolated text marker plus full-byte firmware consumer'})
    # Resolve the native unit-description templates visibly leaked in the GUI.
    for id,title in {'H0105':'ECM Pulses Per Kilometer','H0136':'Tire Revolutions Per Kilometer'}.items():
        item=next(t for t in root.findall('XDFCONSTANT') if t.findtext('title').startswith(id+' '))
        item.find('title').text=id+' '+title
    root.find('XDFHEADER/deftitle').text='AL5 15184109 / 15183960 - iMob Racing Marker Extended v0.10'
    root.find('XDFCONSTANT/description').text=(
        'For 57,304-byte calibration segments only. Offline inspection and development. '
        'CRC16 plus BE16 compensation reproduces stock, PPEI and three independently '
        'EFILive-finalized edited payloads. This validates the offline formula for these '
        'examples, not physical programming or recovery. The AL5 write protocol remains '
        'incomplete and live writing is blocked. No edited BIN is flash-ready. '
        'v0.10 adds D5053/D5054 byte enums; 126/127 native IDs are represented, '
        'including partial/research entries. D5197 remains absent.')
    checksum=next(t for t in root.findall('XDFCONSTANT') if t.findtext('title').startswith('Segment checksum field'))
    checksum.find('description').text=(
        'Native four-byte field: payload reflected CRC16 (poly A001, init 0) and '
        'BE16 sum-compensation word. Offline synthesis matches five independent '
        'native examples. TunerPro does not automatically update this field. '
        'Do not edit it manually; live programming remains blocked.')
    ET.indent(root,space='  ')
    return root,{'added':added,'native_checksum_variants':checked['checksum_variants'],
                'flash_ready':False,'gui_validation':'new enum entries pending'}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','stock','export','report','references','high','output','manifest'):
        p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    native={c['id']:c for c in json.loads(a.export.read_bytes().decode('cp1252'))['calibrations']}
    root,result=expand(a.source,a.stock.read_bytes(),native,json.loads(a.report.read_text()),
                       json.loads(a.references.read_text()),a.high.read_bytes())
    result.update({name+'_sha256':sha256(getattr(a,name).read_bytes())
                   for name in ('source','stock','export','report','references','high')})
    ET.ElementTree(root).write(a.output,encoding='utf-8',xml_declaration=True)
    a.manifest.write_text(json.dumps(result,indent=2)+'\n')
    print('Added two independently marker/firmware mapped byte enums')
