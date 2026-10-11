"""File-only AL5 retry audit and isolated stored-counter models; no VM execution."""
import argparse
import json
from pathlib import Path
import struct
from al5_segment import sha256
from inspect_vm_flow import report as flow_report
from replay_object_transform import reconstruct
from decode_trace_containers import decode, records
from inspect_trace_containers import MAX_INPUT
from inspect_vm_objects import CODE_CAPACITY, DATA_CAPACITY
from validate_vm_buffers import read_bounded

DLL_SHA256='132832f80d7e5b642033fafc35df4ff3c0f3b19371081d23eacf696c4019ac00'
MAX_REPORT_BYTES=16*1024*1024


def decrement_stored(value,width,flags=0,step=1):
    """Native12 subset: modular subtract, truncate destination, update only20."""
    if width not in (8,16,32) or not 0<=value<1<<width or not 0<=flags<=0xFFFF or not 0<=step<=0xFFFFFFFF:
        raise ValueError('unsupported scalar/counter profile')
    stored=(value-step)&((1<<width)-1)
    return {'stored_value':stored,'flags':(flags&~0x20)|(0x20 if stored==0 else 0),
            'opcode47_branch':stored==0,'opcode48_branch':stored!=0}


def counter_path(initial,width):
    if not 1<=initial<=20:raise ValueError('counter path outside selected saved profile')
    steps=[];value=initial
    for _ in range(initial):
        effect=decrement_stored(value,width)
        steps.append({'before':value,**effect});value=effect['stored_value']
    return steps


def selected_profile(flow,code,data):
    if sha256(code)!=flow['code_sha256'] or sha256(data)!=flow['instruction_buffer_sha256']:
        raise ValueError('reconstructed buffers do not match supplied flow')
    nodes={n['offset']:n for n in flow['structural_instructions']}
    def expect(offset,opcode,operands):
        node=nodes.get(offset)
        if node is None or node['opcode']!=opcode or [(a['tag'],a.get('value')) for a in node['operands']]!=operands:
            raise ValueError(f'unsupported saved retry instruction at0x{offset:x}')
        return node
    refs=lambda *pairs:list(pairs)
    expected={
        0x1BBC:(0x20,refs((0xB1,3),(0xA0,0x217A))),
        0x1CD4:(0x20,refs((0xB1,1),(0xA0,0x2476))),
        0x1CE8:(0x51,refs((0xA1,0x188))),0x1CEE:(0x4C,refs((0xA1,0x1DC8))),
        0x1D0C:(0x43,refs((0xA1,0x1DCE))),0x1D1C:(0x43,refs((0xA1,0x1D78))),
        0x1DC8:(0x51,refs((0xA1,0x28E))),0x1DD4:(0x12,refs((0xB1,1),(0xA0,0x217A))),
        0x1DDE:(0x48,refs((0xA1,0x1CCA))),0x1DE4:(0x82,refs((0xB1,0x80))),
        0x0194:(0x20,refs((0xB1,8),(0xA0,0x247A))),
        0x0214:(0x12,refs((0xB1,1),(0xA0,0x247A))),0x021E:(0x47,refs((0xA1,0x22A))),
        0x022A:(0x12,refs((0xB1,1),(0xA0,0x2476))),0x0234:(0x47,refs((0xA1,0x26C))),
        0x0278:(0x20,refs((0xB1,3),(0xA0,0x2476))),
        0x029C:(0x51,refs((0xA1,0x102))),
        0x0102:(0x20,refs((0xA0,0x24AE),(0xA0,0x24B2))),
        0x010C:(0x61,refs((0xA0,0x10CC),(0xA0,0x2472),(0xA0,0x2484))),
        0x011A:(0x4B,refs((0xA1,0x130))),0x0120:(0x12,refs((0xB1,1),(0xA0,0x24B2))),
        0x012A:(0x48,refs((0xA1,0x10C))),0x013A:(0x64,[]),0x013C:(0x83,refs((0xB1,0x81))),
        0x1D02:(0x30,refs((0xA0,0x24CA),(0xB1,0x77))),
        0x1D12:(0x30,refs((0xA0,0x24CA),(0xB1,0x73))),
        0x1D22:(0x20,refs((0xB2,0x600),(0xA0,0xFF07))),
        0x1D2C:(0x11,refs((0xA0,0x24CA),(0xA0,0xFF07))),
        0x1D98:(0x20,refs((0xB1,3),(0xA0,0x217A))),
        0x1DB6:(0x12,refs((0xA0,0x2204),(0xA0,0x21FE))),0x1DC0:(0x48,refs((0xA1,0x1BBC))),
        0x2C54:(0x4B,refs((0xA1,0x2A00))),0x2AD2:(0x81,refs((0xA0,0x70)))}
    for offset,(opcode,operands) in expected.items():expect(offset,opcode,operands)
    pools=[]
    for ref,tag in [(0x217A,0xB2),(0x2476,0xB1),(0x247A,0xB1),(0x24AE,0xB1),(0x24B2,0xB1),(0x2484,0xB2),(0x2488,0xB4),(0x21FE,0xB4)]:
        if ref+6>len(code) or struct.unpack_from('<H',code,ref)[0]!=tag:raise ValueError('unsupported pool descriptor')
        width={0xB1:8,0xB2:16,0xB4:32}[tag]
        value=int.from_bytes(code[ref+2:ref+2+width//8],'little')
        pools.append({'reference':ref,'tag':tag,'width_bits':width,'initial_stored_value':value,
                      'source_sha256':sha256(code[ref:ref+2+width//8])})
    values={p['reference']:p['initial_stored_value'] for p in pools}
    if values[0x24AE]!=20 or values[0x2484]!=250 or values[0x2488]!=250:raise ValueError('unsupported drain count/timeout')
    helper=nodes.get(0x28E)
    if not helper or helper['opcode']!=0x60 or len(helper['operands'])!=1:raise ValueError('unsupported helper')
    arg=helper['operands'][0]
    payload=data[arg['offset']+6:arg['offset']+6+arg.get('payload_bytes',0)]
    if arg['tag']!=0xB0 or payload!=bytes.fromhex('6c fe f0 28 00'):raise ValueError('unsupported helper payload')
    return {'matched_instruction_count':len(expected)+1,'matched_instruction_offsets':sorted([*expected,0x28E]),
            'pool_descriptors':pools,'helper028e_inline_bytes':payload.hex(' '),
            'helper028e_payload_sha256':sha256(payload),'packet_semantics_verified':False}


def audit(flow,code,data):
    profile=selected_profile(flow,code,data)
    return {'schema_version':1,'profile':profile,
            'flag20':{'after_opcode12':'Stored width-truncated destination equals zero; not borrow.',
                      'opcode47':'branch when20 set','opcode48':'branch when20 clear',
                      'global_numeric_meaning_assumed':False},
            'isolated_counter_models':{
                'programming_attempts':{'pool_reference':0x217A,'width_bits':16,'initial':3,'steps':counter_path(3,16)},
                'mismatched_receives':{'pool_reference':0x247A,'width_bits':8,'initial':8,'steps':counter_path(8,8)},
                'helper_drain_receives':{'pool_reference':0x24B2,'width_bits':8,'initial':20,'steps':counter_path(20,8)}},
            'programming_branches':[
                {'source':0x1CEE,'condition':'flags &0x81 !=0','target':0x1DC8,'action':'Call028E then backoff and decrement outer counter.'},
                {'source':0x1D0C,'condition':'extracted response byte==0x77','target':0x1DCE,'action':'Backoff and decrement; no helper028E call on this branch.'},
                {'source':0x1D1C,'condition':'extracted response byte==0x73','target':0x1D78,'action':'Progress branch resets outer counter to3 and updates positions/remaining bytes.'},
                {'source':0x1D22,'condition':'other extracted response byte','target':0x1DCE,'action':'Assign status0x600+response, then backoff/decrement.'},
                {'source':0x1DDE,'condition':'stored outer counter nonzero immediately after12','target':0x1CCA,'action':'Repeat exchange for same built block; per-exchange send budget is assigned1.'},
                {'source':0x1DE4,'condition':'stored outer counter became zero','target':0x1DEA,'action':'Set80 and return; caller2C54 branches to2A00.'}],
            'common_exchange':{'entry':0x188,'send_call':0x44,'receive':0x19E,
                'mismatch_decrement':0x214,'mismatch_zero_branch':0x21E,'send_budget_decrement':0x22A,
                'send_budget_zero_branch':0x234,'failure_flag_set':0x26C,
                'reset_on_return':{'send_budget':3,'timeout_value':250,'entry':0x278},
                'limits':'Programming assigns budget1 before entry: failure consumes it and returns80 without the inner resend path. Up to8 mismatched candidate responses are counted for each entry. Actual callback results and wire correlation remain unknown.'},
            'helper028e':{'entry':0x28E,'drain_call':0x29C,'drain_entry':0x102,
                'drain_timeout_value':250,'maximum_counted_receives':20,'break_on_flag80_at':0x11A,
                'callback_selector0a_at':0x13A,'clear_flags_mask':0x81,'clear_at':0x13C,
                'limits':'Inline bytes are passed to opcode60; no claim that controller received them or that they recover flash. Drain/cleanup can clear observed failure flags before the caller decrements its outer counter. External callback effects remain unknown.'},
            'remaining_byte_loop':{'decrement':0x1DB6,'branch':0x1DC0,'target':0x1BBC,
                'condition':'stored remaining-byte value nonzero, not unsigned borrow; valid block sizing is required.'},
            'recovery_assessment':'Traced response retry/drain and error cleanup, not interrupted erase/program restoration. Durable marker/storage preservation and power-interruption recovery remain unverified.',
            'scope':'Static saved-profile matching and isolated integer counter modeling. No VM, callbacks, IPC or adapter/controller execution.',
            'complete_vm_semantics_verified':False,'write_protocol_verified':False,
            'physical_recovery_verified':False,'automatic_retry_allowed':False,
            'live_write_enabled':False,'ready_to_flash':False,'erase_scope':None,
            'would_send':[],'erase_packets':[],'program_packets':[]}


def report(flow_path,flow_hash,flag_path,flag_hash,helper_path,helper_hash):
    inputs=[]
    for path,expected in [(flow_path,flow_hash),(flag_path,flag_hash),(helper_path,helper_hash)]:
        blob=read_bounded(Path(path),1,MAX_REPORT_BYTES)
        if sha256(blob)!=expected:raise ValueError('evidence SHA256 mismatch')
        inputs.append((json.loads(blob),{'path':str(Path(path).resolve()),'sha256':sha256(blob)}))
    flow,flags,helpers=[item[0] for item in inputs]
    for native in (flags,helpers):
        if native['source']['sha256']!=DLL_SHA256:raise ValueError('unsupported native source')
    current=flow_report(flow['trace_path'],flow['object_path'],flow['trace_sha256'],flow['object_sha256'])
    if current['structural_instructions']!=flow['structural_instructions']:raise ValueError('flow listing does not match reconstructed source')
    source=read_bounded(Path(flow['trace_path']),1,MAX_INPUT)
    obj=read_bounded(Path(flow['object_path']),16,CODE_CAPACITY+DATA_CAPACITY)
    if sha256(source)!=flow['trace_sha256'] or sha256(obj)!=flow['object_sha256']:raise ValueError('source changed during reconstruction')
    code,data,_=reconstruct(records(decode(source)),obj,Path(flow['object_path']).name)
    result=audit(flow,code,data)
    result.update(evidence_inputs=[item[1] for item in inputs],generator_sha256=sha256(Path(__file__).read_bytes()),
                  instruction_buffer_sha256=sha256(data),code_sha256=sha256(code),
                  trace_sha256=flow['trace_sha256'],object_sha256=flow['object_sha256'],native_source_sha256=DLL_SHA256,
                  flag20_arithmetic_predicate_statically_verified=True,
                  limits='Only the selected source/profile and counter arithmetic are modeled; no whole-VM execution, wall-clock timing, complete callback side effects or physical success/recovery proof.')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('flow','flag-evidence','helper-evidence'):
        parser.add_argument('--'+name,type=Path,required=True)
        parser.add_argument('--expected-'+name+'-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=report(args.flow,args.expected_flow_sha256,args.flag_evidence,args.expected_flag_evidence_sha256,
                  args.helper_evidence,args.expected_helper_evidence_sha256)
    with args.output.open('x',encoding='utf8',newline='\n') as stream:stream.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'ready_to_flash':False,'matched_instruction_count':result['profile']['matched_instruction_count']}))
