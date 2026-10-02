"""Saved host-request census for the statically inspected AL5 loader; no transport."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct
from al5_segment import sha256
from decode_trace_containers import decode, records, NAME


def analyze(path):
    path=Path(path)
    match=NAME.fullmatch(path.name)
    if not match or (match[4] or match[5]).upper()!='W':raise ValueError('AL5 W trace required')
    source=path.read_bytes();counts=Counter();subtypes=Counter()
    for record in records(decode(source)):
        payload=record['payload']
        if record['kind']!=0x42 or record['channel']!=1 or len(payload)<14 or payload[:2]!=b'\x01\x54':continue
        length=struct.unpack_from('<H',payload,10)[0]
        if len(payload)!=length+14:continue
        message=payload[12:12+length]
        if len(message)<4 or message[0] not in (0x6C,0x6D,0x8C) or message[1] not in (0x18,0xFE) or message[2] not in (0xF0,0xF1):continue
        counts[message[:4].hex()]+=1
        if message[3]==0x36 and len(message)>4:subtypes[hex(message[4])]+=1
    return {'source_name':path.name,'source_sha256':sha256(source),
            'host_request_header_service_counts':dict(sorted(counts.items())),
            'mode36_subtype_counts':dict(sorted(subtypes.items())),
            'loader_erase_subtype_observed':bool(subtypes['0xee']),
            'loader_word_program_subtype_observed':bool(subtypes['0x0']),
            'loader_finalize_subtype_observed':bool(subtypes['0xff']),
            'capture_complete_verified':False,'operation_outcome':None}


def report(paths):
    root=Path(__file__).resolve().parents[2]
    static=(root/'Docs/AL5/CAPTURED_LOADER_STATIC.json').read_bytes()
    cases=[analyze(p) for p in paths]
    if not cases:raise ValueError('no saved W traces supplied')
    return {'scope':'Static loader behavior and saved host-wrapper request census, including destination 0x18 and global 0xFE. No hardware or uploaded-code execution.',
            'static_evidence':'Docs/AL5/CAPTURED_LOADER_STATIC.json','static_evidence_sha256':sha256(static),
            'payload_sha256':json.loads(static)['payload_sha256'],
            'static_dispatch':{'service':'0x36','subtypes':{
                '0xee':{'target':'0xff934a','effect':'Flash-ID check then erase calls with bases 0x8000 and 0x10000; bypasses block byte-sum branch.'},
                '0x00':{'target':'0xff9130','effect':'Parse length/address/data and check byte-sum before word-program routine 0xff93ea.'},
                '0xdb':{'target':'0xff9130','effect':'Same byte-sum branch but takes delay branch instead of word programming.'},
                '0xff':{'target':'0xff91d6','effect':'Use pointers at 0x20046; BE16 sum check then program word 0x4afc at 0x1fffe.'}}},
            'static_flash_id_gate':{'manufacturer_word':'0x0001','device_word':'0x2258','physical_chip_identity_verified':False},
            'static_erase_bases':['0x8000','0x10000'],'physical_erase_geometry_verified':False,
            'traces':cases,'trace_count':len(cases),
            'destructive_requests_observed':any(c['loader_erase_subtype_observed'] or c['loader_word_program_subtype_observed'] or c['loader_finalize_subtype_observed'] for c in cases),
            'limits':'Only supported host wrapper shapes examined; interface checksums, missing traffic, loader execution, physical geometry and flash completion remain unverified. No destructive request observed is not proof none occurred.',
            'loader_executed':False,'calibration_programming_verified':False,'physical_recovery_verified':False,
            'ready_to_flash':False,'live_write_enabled':False,'would_send':[]}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--trace',type=Path,action='append',required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();result=report(args.trace)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'trace_count':result['trace_count'],'destructive_requests_observed':result['destructive_requests_observed'],'would_send':[]}))
