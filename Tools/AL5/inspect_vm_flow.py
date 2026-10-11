"""Structural AL5 VM listing and static control-flow candidates; never executes VM."""
import argparse
import json
from pathlib import Path
import struct
from al5_segment import sha256
from inspect_vm_objects import CODE_CAPACITY, DATA_CAPACITY
from decode_trace_containers import decode, records, NAME
from inspect_trace_containers import MAX_INPUT
from replay_object_transform import reconstruct
from validate_vm_buffers import inspect_buffers, read_bounded

TAGS = {0xA0:4, 0xA1:4, 0xB1:4, 0xB2:4, 0xB4:6}
BRANCH_MASKS = {0x40:(1,True),0x41:(2,True),0x42:(6,True),0x43:(4,True),
                0x44:(4,False),0x45:(8,True),0x46:(12,True),0x47:(32,True),
                0x48:(32,False),0x49:(16,True),0x4B:(128,True),0x4C:(129,True)}


def descriptor(data, offset):
    if offset+4>len(data):raise ValueError('truncated descriptor')
    tag,word=struct.unpack_from('<HH',data,offset)
    length=TAGS.get(tag)
    result={'offset':offset,'tag':tag}
    if tag==0xB0:
        signed=struct.unpack_from('<h',data,offset+2)[0]
        if signed<0 or offset+6>len(data):raise ValueError('invalid variable descriptor length')
        length=6+((signed+1)&0xFFFE)
        result.update(payload_bytes=signed,capacity_word=struct.unpack_from('<H',data,offset+4)[0])
    elif length is None:raise ValueError('unsupported descriptor tag')
    if offset+length>len(data):raise ValueError('truncated descriptor extent')
    result['extent_bytes']=length
    if tag==0xB0:result['payload_sha256']=sha256(data[offset+6:offset+6+result['payload_bytes']])
    else:result['value']=int.from_bytes(data[offset+2:offset+length],'little')
    return result,offset+length


def listing(data):
    if not 0<len(data)<=DATA_CAPACITY:raise ValueError('instruction buffer outside VM capacity')
    nodes=[];offset=0
    while offset+2<=len(data):
        start=offset;opcode=struct.unpack_from('<H',data,offset)[0]
        if opcode>0x9F:break
        offset+=2;args=[]
        while offset+2<=len(data):
            tag=struct.unpack_from('<H',data,offset)[0]
            if tag not in TAGS and tag!=0xB0:break
            arg,offset=descriptor(data,offset);args.append(arg)
        node={'offset':start,'end_exclusive':offset,'opcode':opcode,'operands':args,
              'source_sha256':sha256(data[start:offset]),'effects_fully_modeled':False}
        if opcode in BRANCH_MASKS or opcode in (0x50,0x51):
            if len(args)!=1 or args[0]['tag']!=0xA1:raise ValueError('unsupported branch target representation')
            value=args[0]['value'];node['target_offset']=value if value<0x8000 else value-0x10000
            if opcode in BRANCH_MASKS:
                mask,nonzero=BRANCH_MASKS[opcode]
                node['branch_condition']={'flags_mask':mask,'branch_if_nonzero':nonzero}
        if opcode in (0x01,0x52,0x64,0x77,0x7E) and args:
            raise ValueError('unexpected descriptor after native early-route opcode')
        nodes.append(node)
    return nodes,offset


def analyze_buffers(code,data,header_words):
    if not 64<=len(code)<=CODE_CAPACITY or len(header_words)!=8:
        raise ValueError('unsupported code buffer/header profile')
    nodes,covered=listing(data);by_offset={n['offset']:n for n in nodes}
    roots={'initial_entry':header_words[5],'host_error_entry':header_words[6]}
    for offset in roots.values():
        if offset not in by_offset:raise ValueError('entry is not a structural instruction boundary')
    edges=[];invalid=[]
    for node in nodes:
        start,op,end=node['offset'],node['opcode'],node['end_exclusive']
        if 'target_offset' in node:
            target=node['target_offset']
            if target not in by_offset:invalid.append({'source':start,'target':target})
            else:edges.append({'source':start,'target':target,'kind':'call' if op==0x51 else 'branch'})
        if op not in (0x50,0x52,0x81) and end in by_offset:
            edges.append({'source':start,'target':end,'kind':'call_continuation_candidate' if op==0x51 else 'fallthrough_candidate'})
    outgoing={}
    for edge in edges:outgoing.setdefault(edge['source'],[]).append(edge['target'])
    reachable={}
    for role,entry in roots.items():
        seen=set();pending=[entry]
        while pending:
            offset=pending.pop()
            if offset in seen:continue
            seen.add(offset);pending.extend(outgoing.get(offset,[]))
        reachable[role]=sorted(seen)
    literals=[]
    for node in nodes:
        for arg in node['operands']:
            if arg['tag'] in (0xB1,0xB2,0xB4) and arg['value'] in (0x36EE,0x3600,0x36DB,0x36FE,0x36FF,0x8000,0x1FFFD,512):
                literals.append({'instruction_offset':node['offset'],'operand_offset':arg['offset'],
                                 'value':arg['value'],'instruction_opcode':node['opcode'],
                                 'operands':node['operands'],'packet_semantics_verified':False})
    arities={}
    for node in nodes:arities.setdefault(str(node['opcode']),set()).add(len(node['operands']))
    return {'code_sha256':sha256(code),'instruction_buffer_sha256':sha256(data),
            'entries':roots,'instruction_count':len(nodes),'structural_instructions':nodes,
            'structurally_examined_bytes':covered,'instruction_buffer_bytes':len(data),
            'uninterpreted_tail':{'offset':covered,'bytes':len(data)-covered,'sha256':sha256(data[covered:])},
            'observed_descriptor_counts':{k:sorted(v) for k,v in arities.items()},
            'descriptor_count_provenance':'Grouping of supported descriptors in the reconstructed stream; full native opcode arities not established.',
            'control_flow_candidates':edges,'invalid_direct_targets':invalid,
            'context_insensitive_reachability_candidates':reachable,'programming_literal_references':literals,
            'complete_vm_semantics_verified':False,'dynamic_return_targets_resolved':False,
            'stop_opcode':{'opcode':0x81,'semantics':'Native handler sets run-stop byte and returns descriptor word as status; no ordinary fallthrough edge.'},
            'host_error_redirects':'Native callback failures can redirect to host_error_entry; not modeled as ordinary instruction edges.',
            'write_protocol_verified':False,'physical_recovery_verified':False,
            'live_write_enabled':False,'ready_to_flash':False,'erase_scope':None,
            'would_send':[],'erase_packets':[],'program_packets':[]}


def report(trace,object_path,trace_hash,object_hash):
    trace,object_path=Path(trace),Path(object_path)
    if not NAME.fullmatch(trace.name):raise ValueError('explicit saved AL5 trace required')
    source=read_bounded(trace,1,MAX_INPUT);obj=read_bounded(object_path,16,CODE_CAPACITY+DATA_CAPACITY)
    if sha256(source)!=trace_hash or sha256(obj)!=object_hash:raise ValueError('trace/object SHA256 mismatch')
    code,data,stages=reconstruct(records(decode(source)),obj,object_path.name)
    validation=inspect_buffers(code,data,sha256(code),sha256(data))
    if not validation['supplied_buffer_crc_matches']:raise ValueError('reconstructed VM buffer CRC mismatch')
    result=analyze_buffers(code,data,struct.unpack_from('<8H',obj))
    result.update(schema_version=1,trace_path=str(trace.resolve()),trace_sha256=sha256(source),
                  object_path=str(object_path.resolve()),object_sha256=sha256(obj),
                  generator_sha256=sha256(Path(__file__).read_bytes()),
                  reconstruction_generator_sha256=sha256(Path(__file__).with_name('replay_object_transform.py').read_bytes()),
                  reconstruction_stages=stages,crc16=validation['computed_crc16'],
                  static_evidence='Docs/AL5/EFILIVE_VM_DISPATCH.json',
                  static_evidence_sha256=sha256((Path(__file__).resolve().parents[2]/'Docs/AL5/EFILIVE_VM_DISPATCH.json').read_bytes()),
                  scope='File-only structural instruction grouping and static direct branch/call candidates from captured-reply reconstruction. No VM execution, host callbacks, IPC, adapter or controller access.',
                  limits='Full operand arities, helper side effects, flags/dataflow, external callbacks and dynamic returns remain incomplete. Possible fallthrough and call continuations do not prove execution, retries, preservation or recovery. Tail is retained as unknown.')
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
    print(json.dumps({'structural_instructions':result['instruction_count'],'ready_to_flash':False}))
