"""Offline saved AL5 HTX decoding; emit redacted metadata, never executable packets."""
import argparse
from collections import Counter
import json
import math
from pathlib import Path
import struct
import zlib
from al5_segment import sha256
from inspect_trace_containers import MAX_INPUT, NAME

MAX_DECODED=16*1024*1024
HEADER_BYTES=1024
RECORD_BYTES=18
SIGNATURE=bytes.fromhex('0100020001000500')


def decode(data):
    if not 0<len(data)<=MAX_INPUT:raise ValueError('encoded input exceeds policy')
    transformed=bytes(((((b-0x87)&255)<<3)|(((b-0x87)&255)>>5))&255 ^ 0xA5 for b in data)
    try:
        stream=zlib.decompressobj()
        result=stream.decompress(transformed,MAX_DECODED+1)
    except zlib.error as error:
        raise ValueError('invalid transformed zlib stream') from error
    if len(result)>MAX_DECODED or not stream.eof or stream.unused_data:
        raise ValueError('oversized, incomplete or trailing container data')
    if len(result)<HEADER_BYTES or result[:8]!=SIGNATURE:
        raise ValueError('unsupported decoded trace header')
    return result


def records(decoded):
    offset=HEADER_BYTES
    while offset<len(decoded):
        if len(decoded)-offset<RECORD_BYTES:raise ValueError('truncated record header')
        date,channel,category,subtype,kind,length=struct.unpack_from('<dBHHBI',decoded,offset)
        end=offset+RECORD_BYTES+length
        if not math.isfinite(date) or not 0<=date<100000 or end>len(decoded) or kind not in (0x54,0x42):
            raise ValueError('invalid or unsupported trace record')
        yield {'offset':offset,'date':date,'channel':channel,'category':category,
               'subtype':subtype,'kind':kind,'payload':decoded[offset+RECORD_BYTES:end]}
        offset=end


def vehicle_message(record):
    """Observed USB wrapper shapes; direction labels are inferred, not bus verification."""
    payload=record['payload']
    if record['kind']!=0x42 or len(payload)<14:return None
    length=struct.unpack_from('<H',payload,10)[0]
    direction=record['channel']
    if direction==1 and payload[:2]==b'\x01\x54' and len(payload)==length+14:
        label='host_tx_candidate'
    elif direction==2 and payload[:2]==b'\x01\x52' and len(payload)==length+15:
        label='device_rx_candidate'
    else:return None
    message=payload[12:12+length]
    if len(message)<4 or message[:3] not in (bytes.fromhex('6c18f0'),bytes.fromhex('6d18f0'),bytes.fromhex('6cf018')):return None
    return label,message


def summarize(path):
    path=Path(path)
    match=NAME.fullmatch(path.name)
    if not match or not 0<path.stat().st_size<=MAX_INPUT:raise ValueError('explicit bounded AL5 trace required')
    source=path.read_bytes()
    decoded=decode(source)
    parsed=list(records(decoded))
    if not parsed:raise ValueError('empty trace records')
    counters=Counter();sequence=[]
    for record in parsed:
        observed=vehicle_message(record)
        if observed:
            direction,message=observed
            counters[(direction,message[:4].hex())]+=1
            sequence.append({'record_offset':hex(record['offset']),
                             'elapsed_ms':round((record['date']-parsed[0]['date'])*86400000,3),
                             'direction_inference':direction,'header_and_service':message[:4].hex(),
                             'message_bytes':len(message),'message_sha256':sha256(message)})
    return {'source_name':path.name,'source_sha256':sha256(source),
            'encoded_bytes':len(source),'decoded_bytes':len(decoded),'decoded_sha256':sha256(decoded),
            'record_count':len(parsed),'record_payload_kinds':dict(Counter(chr(r['kind']) for r in parsed)),
            'records_consume_decoded_file':True,
            'observed_al5_message_count':len(sequence),
            'service_counts':[{'direction_inference':direction,'header_and_service':service,'count':count}
                              for (direction,service),count in sorted(counters.items())],
            'redacted_message_sequence':sequence,
            'container_decoding_verified_for_saved_file':True,
            'vehicle_wrapper_checksum_verified':False,'operation_outcome':None,
            'erase_program_protocol_verified':False}


def report(paths):
    cases=[summarize(p) for p in paths]
    if not cases:raise ValueError('no traces supplied')
    return {'schema_version':1,
            'scope':'Saved container transform, complete zlib decoding, bounded record framing and redacted candidate AL5 message metadata only.',
            'limits':'Direction labels inferred from wrapper shapes. Interface checksums, dropped messages, full packet semantics, erase/program completion and recovery unverified. Container headers, text, tune data, keys and loader payloads omitted.',
            'transform':'Subtract 0x87 modulo 256, rotate left 3 bits, XOR 0xA5; then standard zlib.',
            'static_evidence':'Docs/AL5/TRACE_STREAM_STATIC.json',
            'static_evidence_sha256':sha256((Path(__file__).resolve().parents[2]/'Docs/AL5/TRACE_STREAM_STATIC.json').read_bytes()),
            'traces':cases,'trace_count':len(cases),'saved_container_format_decoded':True,
            'programming_transport_verified':False,'flash_outcomes_verified':False,
            'live_write_enabled':False,'ready_to_flash':False,'would_send':[]}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--trace',type=Path,action='append',required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    result=report(args.trace)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'trace_count':result['trace_count'],'saved_container_format_decoded':True,'would_send':[]}))
