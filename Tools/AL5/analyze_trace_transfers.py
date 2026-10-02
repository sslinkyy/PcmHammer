"""Compare saved AL5 transfer candidates to the offline boot contract; no execution."""
import argparse
from collections import Counter
import json
from pathlib import Path
from al5_segment import sha256
from decode_trace_containers import decode, records, vehicle_message, NAME


def transfer_contract(message):
    if len(message)<12 or message[:4]!=bytes.fromhex('6d18f036'):
        raise ValueError('bounded AL5 Mode 0x36 candidate required')
    length=int.from_bytes(message[5:7],'big')
    address=int.from_bytes(message[7:10],'big')
    payload=message[10:-2]
    checksum=int.from_bytes(message[-2:],'big')
    return {'subtype':hex(message[4]),'declared_payload_bytes':length,
            'actual_payload_bytes':len(payload),'address':hex(address),
            'end_exclusive':hex(address+length),'payload_sha256':sha256(payload),
            'length_matches':length==len(payload),
            'within_offline_handler_bounds':address%2==0 and 0xFF9000<=address<=0xFFA7FF and address+length<=0xFFA7FF,
            'byte_sum_matches':sum(message[4:-2])&0xFFFF==checksum,
            'requests_execution_in_offline_handler':message[4]==0x80,
            'payload_executed':False,'erase_program_verified':False}


def analyze(path):
    path=Path(path)
    match=NAME.fullmatch(path.name)
    if not match:raise ValueError('explicit AL5 trace required')
    source=path.read_bytes()
    messages=[]
    for record in records(decode(source)):
        candidate=vehicle_message(record)
        if candidate:messages.append((record['offset'],*candidate))
    transfers=[]
    for index,(offset,direction,message) in enumerate(messages):
        if direction!='host_tx_candidate' or message[:4]!=bytes.fromhex('6d18f036'):continue
        contract=transfer_contract(message)
        later=messages[index+1:]
        contract.update({'record_offset':hex(offset),
                         'prior_7444_response_candidates':sum(d=='device_rx_candidate' and m==bytes.fromhex('6cf0187444') for _,d,m in messages[:index]),
                         'subsequent_service_counts':[{'direction_inference':d,'header_and_service':s,'count':n} for (d,s),n in sorted(Counter((d,m[:4].hex()) for _,d,m in later).items())],
                         'subsequent_76_response_candidates':sum(d=='device_rx_candidate' and m[3]==0x76 for _,d,m in later)})
        transfers.append(contract)
    return {'source_name':path.name,'source_sha256':sha256(source),
            'filename_mode':(match[4] or match[5]).upper(),'transfers':transfers,
            'calibration_write_completion_verified':False,'operation_outcome':None}


def report(paths):
    traces=[analyze(p) for p in paths]
    contracts=[t for trace in traces for t in trace['transfers']]
    if not contracts:raise ValueError('no captured transfer candidates found')
    return {'scope':'Saved RAM-transfer candidates compared to existing offline firmware contract. No payload execution, packet builder, transport or hardware.',
            'limits':'Wrapper direction/checksums and capture completeness remain unverified. Matching the RAM-transfer contract does not establish live boot reachability, flash semantics or recovery.',
            'boot_contract_evidence':'Docs/AL5/RAM_TRANSFER_EMULATION.json',
            'boot_contract_evidence_sha256':sha256((Path(__file__).resolve().parents[2]/'Docs/AL5/RAM_TRANSFER_EMULATION.json').read_bytes()),
            'traces':traces,'trace_count':len(traces),'transfer_count':len(contracts),
            'all_captured_contracts_match':all(t['length_matches'] and t['within_offline_handler_bounds'] and t['byte_sum_matches'] for t in contracts),
            'loader_execution_verified':False,'calibration_programming_verified':False,
            'physical_recovery_verified':False,'ready_to_flash':False,'live_write_enabled':False,'would_send':[]}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--trace',type=Path,action='append',required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    result=report(args.trace)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'trace_count':result['trace_count'],'transfer_count':result['transfer_count'],'all_captured_contracts_match':result['all_captured_contracts_match']}))
