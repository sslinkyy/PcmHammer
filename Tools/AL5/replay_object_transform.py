"""Replay saved transform replies against an exact installed AL5 object; no I/O."""
import argparse
import json
from pathlib import Path
from al5_segment import sha256
from decode_trace_containers import decode, records, NAME
from inspect_trace_containers import MAX_INPUT
from inspect_vm_objects import inspect_bytes, CODE_CAPACITY, DATA_CAPACITY
from validate_vm_buffers import read_bounded, inspect_buffers
from audit_trace_wrappers import framed_message


def local_transform(value):
    if not len(value) <= 4096 or len(value)%4:
        raise ValueError('VM transform requires a bounded word-aligned chunk')
    output=bytearray()
    for offset in range(0,len(value),4):
        word=int.from_bytes(value[offset:offset+4],'little')
        for _ in range(13):
            word=(((word^0x958E3535)*2|1) if word&0x80000000 else word*2)&0xFFFFFFFF
        output.extend((word^0x35358E95^(offset//4)).to_bytes(4,'little'))
    return bytes(output)


def reconstruct(parsed, obj, name):
    info=inspect_bytes(obj,name)
    exchanges=[]
    for ordinal,record in enumerate(parsed):
        payload=record['payload']
        if record['kind']!=0x42 or len(payload)<4 or payload[:2] not in (b'\x01\x54',b'\x01\x52'):
            continue
        command=int.from_bytes(payload[2:4],'little')
        if command not in (0x8414,0x8415):continue
        framed=framed_message(record)
        if framed is None:raise ValueError('malformed transform wrapper')
        exchanges.append((ordinal,record['offset'],command,framed[0],framed[1]))
    cursor=0
    stages=[]
    def pair(command, expected, section):
        nonlocal cursor
        if cursor+2>len(exchanges):raise ValueError('missing transform exchange')
        tx,rx=exchanges[cursor:cursor+2]
        cursor+=2
        if tx[2:4]!=(command,'host_tx_candidate') or rx[2:4]!=(command,'device_rx_candidate'):
            raise ValueError('ambiguous, repeated or reordered transform exchange')
        if tx[4]!=expected:raise ValueError('request does not match pinned object section')
        stages.append({'section':section,'command_le16':command,
                       'tx_record_ordinal':tx[0],'rx_record_ordinal':rx[0],
                       'tx_record_offset':tx[1],'rx_record_offset':rx[1],
                       'tx_data_sha256':sha256(tx[4]),'rx_data_sha256':sha256(rx[4]),
                       'tx_bytes':len(tx[4]),'rx_bytes':len(rx[4]),
                       'pairing':'strict supplied-record order and exact source-byte match; not wire correlation'})
        return rx[4]
    transformed=[]
    for section,selector,start,end in [('code',12,42,info['code_section_bytes']),
                                       ('data',13,info['data_offset'],len(obj))]:
        if cursor>=len(exchanges):raise ValueError('missing section initialization')
        initial=exchanges[cursor][4]
        if len(initial)!=34 or initial[:2]!=bytes((selector,0)):
            raise ValueError('unsupported section initialization')
        reply=pair(0x8414,initial,section)
        if len(reply)!=1:raise ValueError('unsupported initialization reply length')
        chunks=[]
        for offset in range(start,end,4096):
            expected=obj[offset:min(offset+4096,end)]
            reply=pair(0x8415,expected,section)
            if len(reply)!=len(expected):raise ValueError('transform reply length differs from request')
            chunks.append(local_transform(reply))
        transformed.append(b''.join(chunks))
    if cursor!=len(exchanges):raise ValueError('extra transform exchanges; source association unresolved')
    code=obj[:42]+transformed[0]
    data=transformed[1]
    return code, data, stages


def replay(parsed, obj, name):
    code, data, stages = reconstruct(parsed, obj, name)
    result=inspect_buffers(code,data,sha256(code),sha256(data))
    result.update(object_source_name=name,object_source_sha256=sha256(obj),
                  captured_transform_replay_verified=True,
                  independent_device_transform_reproduced=False,
                  captured_source_association='Exact transmitted bytes for both sections, strict selector/chunk sequence.',
                  exchange_stages=stages)
    return result


def report(trace_path,object_path,expected_trace_hash,expected_object_hash):
    trace_path,object_path=Path(trace_path),Path(object_path)
    if not NAME.fullmatch(trace_path.name):raise ValueError('explicit AL5 trace required')
    source=read_bounded(trace_path,1,MAX_INPUT)
    obj=read_bounded(object_path,16,CODE_CAPACITY+DATA_CAPACITY)
    if sha256(source)!=expected_trace_hash or sha256(obj)!=expected_object_hash:
        raise ValueError('caller-supplied trace or object SHA256 mismatch')
    result=replay(records(decode(source)),obj,object_path.name)
    result.update(trace_source_path=str(trace_path.resolve()),trace_source_sha256=sha256(source),
                  object_source_path=str(object_path.resolve()),
                  generator_sha256=sha256(Path(__file__).read_bytes()),
                  static_evidence='Docs/AL5/EFILIVE_HOST_IPC.json',
                  limits='Reuses recorded device replies. Does not decode arbitrary objects, validate wrapper CRC or device statuses, verify date compatibility, execute VM code, or prove programming/recovery.')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace',type=Path,required=True)
    parser.add_argument('--object',type=Path,required=True)
    parser.add_argument('--expected-trace-sha256',required=True)
    parser.add_argument('--expected-object-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.resolve() in (args.trace.resolve(),args.object.resolve()):parser.error('output must not overwrite input')
    result=report(args.trace,args.object,args.expected_trace_sha256,args.expected_object_sha256)
    with args.output.open('x',encoding='utf8',newline='\n') as stream:stream.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'supplied_buffer_crc_matches':result['supplied_buffer_crc_matches'],'ready_to_flash':False}))
