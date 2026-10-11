"""Supplied-file VM receive callback outcome models; no callbacks or transport."""
import argparse
import json
from pathlib import Path
from al5_segment import sha256
from validate_vm_buffers import read_bounded

MAX_REPORT_BYTES=16*1024*1024
MAX_PAYLOAD_BYTES=0xC000


def integer(value,minimum,maximum):
    if type(value) is not int or not minimum<=value<=maximum:raise ValueError('integer outside callback profile')
    return value


def receive_outcome(event):
    if event.get('classification_profile')!='mode1_selector1':raise ValueError('unsupported supplied classification profile')
    raw=integer(event['callback_return'],-0x80000000,0xFFFFFFFF)
    capacity=integer(event['destination_capacity'],0,0x7FFF)
    before=integer(event['flags_before'],0,0xFFFF)
    status=event.get('exception_status')
    if status is not None:integer(status,0,0xFFFFFFFF)
    encoded=event['payload_hex']
    if not isinstance(encoded,str) or len(encoded)>MAX_PAYLOAD_BYTES*3:raise ValueError('payload text outside host limit')
    try:payload=bytes.fromhex(encoded)
    except ValueError as error:raise ValueError('malformed payload hex') from error
    if len(payload)>MAX_PAYLOAD_BYTES:raise ValueError('payload outside host limit')
    low16=raw&0xFFFF;signed=low16 if low16<0x8000 else low16-0x10000
    base=before&~0x81
    result={'supplied_callback_return':raw,'native_signed_low16':signed,'supplied_exception_status':status,
            'destination_capacity':capacity,'supplied_payload_bytes':len(payload),'supplied_payload_sha256':sha256(payload),
            'classification_profile':'caller-supplied mode1/selector1; no live state verification',
            'copied_bytes':0,'length_scalar_value':0,'modeled_flags':None,'negative_response_code':None,
            'vm_failure_branch_0x1cee':None,'controller_acknowledgment_verified':False,
            'physical_recovery_verified':False,'automatic_retry_allowed':False,'ready_to_flash':False}
    if signed<=0:
        if payload:raise ValueError('nonpositive return cannot establish newly copied payload')
        if status is not None and status&0xFFFF:
            result.update(modeled_flags=base|0x80,vm_failure_branch_0x1cee=True,
                          status='supplied nonpositive result and nonzero status select VM error flag80')
        else:
            result['status']='unknown: missing/zero status and native prior-buffer reads are not modeled'
        return result
    if len(payload)!=signed:raise ValueError('supplied payload must exactly match positive callback length')
    copied=min(signed,capacity)
    result.update(copied_bytes=copied,length_scalar_value=signed,
                  copied_payload_sha256=sha256(payload[:copied]),
                  destination_truncated=copied<signed,
                  separate_length_exceeds_copied_bytes=signed>copied)
    if copied<4:
        result['status']='unknown: native response-signature read lies outside supplied copied extent'
        return result
    negative=payload[3]==0x7F
    flags=base|(1 if negative else 0)
    result.update(modeled_flags=flags,vm_failure_branch_0x1cee=bool(flags&0x81),
                  negative_response_code=payload[copied-1] if negative else None,
                  status='supplied bytes select negative-response flag01' if negative else 'supplied bytes do not select negative-response flag01; no programming success claim')
    return result


def replay(document):
    if not isinstance(document,dict) or document.get('schema_version')!=1 or not isinstance(document.get('cases'),list) or not document['cases']:
        raise ValueError('explicit nonempty supplied cases required')
    results=[];identities=set()
    for event in document['cases']:
        if not isinstance(event,dict) or not isinstance(event.get('id'),str) or not event['id'] or event['id'] in identities:
            raise ValueError('unique nonempty case identity required')
        identities.add(event['id']);results.append({'id':event['id'],**receive_outcome(event)})
    return {'schema_version':1,'scope':'Isolated supplied-file receive result modeling; never invokes VM, host callbacks, IPC or an adapter.',
            'cases':results,'limits':'Only signed-low16 result, selected status/flag and bounded copied-payload branches modeled. Prior-buffer contents, zero-length status initialization, transport/command correlation and controller programming/recovery remain unverified.',
            'live_write_enabled':False,'ready_to_flash':False,'automatic_retry_allowed':False,
            'controller_acknowledgment_verified':False,'physical_recovery_verified':False,
            'erase_scope':None,'would_send':[],'erase_packets':[],'program_packets':[]}


def report(events_path,expected_hash):
    blob=read_bounded(Path(events_path),1,MAX_REPORT_BYTES)
    if sha256(blob)!=expected_hash:raise ValueError('events SHA256 mismatch')
    result=replay(json.loads(blob))
    evidence=[]
    root=Path(__file__).resolve().parents[2]
    for name in ['VM_CALLBACK_OUTCOMES_STATIC.json','VM_CALLBACK10_STATIC.json','VM_RETRY_FAILURE_AUDIT.json']:
        path=root/'Docs/AL5'/name
        evidence.append({'path':str(path),'sha256':sha256(path.read_bytes())})
    result.update(events_path=str(Path(events_path).resolve()),events_sha256=sha256(blob),
                  generator_sha256=sha256(Path(__file__).read_bytes()),evidence=evidence)
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--events',type=Path,required=True)
    parser.add_argument('--expected-events-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=report(args.events,args.expected_events_sha256)
    encoded=json.dumps(result,indent=2)+'\n'
    if len(encoded.encode())>MAX_REPORT_BYTES:raise ValueError('expanded report outside16MiB resource budget')
    with args.output.open('x',encoding='utf8',newline='\n') as stream:stream.write(encoded)
    print(json.dumps({'case_count':len(result['cases']),'ready_to_flash':False}))
