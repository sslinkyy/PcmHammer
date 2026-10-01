"""Verify final enum markers, relabel the existing raw byte, and identify PPEI's option."""
import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from al5_segment import START, validate, sha256
from checksum import checksum_valid
from verify_enum_checksum_pass import reconstruct

ADDRESS=0x10A24
OPTIONS={0:'All Enabled',32:'Torque Limit Req Disabled',64:'RPM Limit Req Disabled',
         96:'Torque and RPM Limit Req Disabled'}


def verify(report,stock,ppei):
    if validate(stock) or validate(ppei) or not checksum_valid(stock) or not checksum_valid(ppei):
        raise ValueError('invalid reference segments')
    if report.get('tool')!='AL5-D5197-text-differential-mapper-0.8':
        raise ValueError('wrong report version')
    if (report.get('controller'),report.get('operating_system'),report.get('transmission')) != ('AL5',15184109,15183960):
        raise ValueError('wrong controller context')
    for key in ('completed','secondary_closed'):
        if report.get(key) is not True:raise ValueError('incomplete report')
    for key in ('vehicle_io','gui_descriptor_modified','secondary_saved','checksum_finalized','flash_ready'):
        if report.get(key) is not False:raise ValueError('invalid safety flag')
    for key in ('gui_raw_unchanged','raw_coherency_and_restore','secondary_baseline_equals_gui'):
        if report.get('validation',{}).get(key) is not True:raise ValueError('missing baseline check')
    if report.get('error') or report.get('close_error') or len(report['cases'])!=3:
        raise ValueError('failed or incomplete cases')
    if stock[ADDRESS-START]!=0:raise ValueError('stock enum byte mismatch')
    for record,raw in zip(report['cases'],(32,64,96)):
        m=record['marker'];label=OPTIONS[raw]
        if (m['id'],m['column'],m['row'],m['before'],m['requested'],m['readback']) != ('D5197',0,0,OPTIONS[0],label,label):
            raise ValueError('text marker/readback mismatch')
        if record.get('restored') is not True or record.get('changed_byte_count')!=1:
            raise ValueError('unrestored or unexpected changes')
        if record['changed_bytes']!=[{'address':ADDRESS,'before':0,'after':raw}]:
            raise ValueError('marker is not the isolated named byte')
        marked=reconstruct(stock,record['changed_bytes'],{ADDRESS})
        covered=False
        for d in record['diff_ranges']:
            a,b=d['context_start'],d['context_end']
            if not START<=a<=ADDRESS<=b<START+len(stock):raise ValueError('invalid marker context')
            if bytes.fromhex(d['before_hex'])!=stock[a-START:b-START+1] or bytes.fromhex(d['after_hex'])!=marked[a-START:b-START+1]:
                raise ValueError('context mismatch')
            covered=True
        if not covered:raise ValueError('missing byte context')
    ppei_value=ppei[ADDRESS-START]
    if ppei_value not in OPTIONS:raise ValueError('PPEI has an unvalidated enum value')
    return {'id':'D5197','address':'0x10A24','bits':8,'options':OPTIONS,
            'confidence':'three isolated text markers, exact readback and full raw restoration',
            'stock_raw':0,'stock_option':OPTIONS[0],'ppei_raw':ppei_value,'ppei_option':OPTIONS[ppei_value],
            'note':'Two observed disable masks 0x20/0x40; other bits are unassigned. Keep stock for first test.',
            'flash_ready':False}


def expand(source,evidence):
    root=ET.parse(source).getroot()
    item=next(t for t in root.findall('XDFCONSTANT')
              if t.find('EMBEDDEDDATA').get('mmedaddress')=='0x10A24')
    item.find('title').text='D5197 CAN Torque Messages (raw hex: 00/20/40/60)'
    item.find('description').text=(
        'Isolated EFILive text markers confirm 00=All Enabled; 20=Torque Limit Req Disabled; '
        '40=RPM Limit Req Disabled; 60=Torque and RPM Limit Req Disabled. Exact readbacks '
        'and raw restores passed. Only these four byte values are validated; other bits '
        'are unassigned. This raw constant has no dropdown/discrete-value enforcement. '
        'Keep 00 stock for the first vehicle test. PPEI 40 means RPM Limit Req Disabled. '
        'This identifies the old unknown byte without proving a flare mechanism. GUI check pending.')
    item.find('CATEGORYMEM').set('category','8')
    item.find('rangehigh').text='96'
    root.find('XDFHEADER/deftitle').text='AL5 15184109 / 15183960 - iMob Racing Marker Extended v0.11'
    warning=root.find('XDFCONSTANT/description')
    warning.text=warning.text.replace('v0.10 adds D5053/D5054 byte enums; 126/127 native IDs are represented,',
        'v0.11 identifies D5197 and represents 127/127 native IDs,').replace('D5197 remains absent.',
        '136 numeric cells in D5000/D5005 Patterns E-H still need mapping; ID coverage is not full cell validation.')
    ET.indent(root,space='  ')
    return root


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','stock','ppei','report','output','manifest'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    evidence=verify(json.loads(a.report.read_text()),a.stock.read_bytes(),a.ppei.read_bytes())
    root=expand(a.source,evidence)
    evidence.update({name+'_sha256':sha256(getattr(a,name).read_bytes()) for name in ('source','stock','ppei','report')})
    ET.ElementTree(root).write(a.output,encoding='utf-8',xml_declaration=True)
    a.manifest.write_text(json.dumps(evidence,indent=2)+'\n')
    print('D5197 mapped; PPEI option:',evidence['ppei_option'])
