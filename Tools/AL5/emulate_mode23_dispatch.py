"""Pinned native Mode 23 descriptor callbacks, without receive queue or transport."""
import argparse
import hashlib
import json
from pathlib import Path
from emulate_mode23_coverage import Probe, HIGH_HASH


def analyze(high):
    if hashlib.sha256(high).hexdigest()!=HIGH_HASH:
        raise ValueError('Firmware identity changed')
    descriptor=high[0x99a12-0x20000:0x99a18-0x20000].hex()
    if descriptor!='9000000bfda0':raise ValueError('Mode 23 descriptor changed')
    records=[]
    for state in (0,1,2,3,255):
        for lock in (0,0x20):
            for argument in (0,1):
                p=Probe(high)
                p.ranges.append((0xb1970,0xb1b24))
                request=0xff8eb6
                p.u.mem_write(request,bytes.fromhex('086d18f02301fffc01'))
                p.u.mem_write(0xff8eff,b'\0')
                p.u.mem_write(0xff8f2a,bytes([state]))
                p.u.mem_write(0xff9dbe,bytes([lock]))
                p.u.mem_write(0xffa269,b'\xcc'*6)
                p.call(0xb1970,[0x99a12,argument])
                body=p.u.mem_read(0xffa269,6).hex()
                pending=p.u.mem_read(0xff8f3f,1).hex()
                reached=argument==1 or state==0
                assert body==('fffcbfd0e1f2' if reached else 'cccccccccccc')
                assert pending==('10' if reached else '00')
                assert not p.negative
                records.append(dict(state=state,lock_flags=lock,call_argument=argument,
                                    handler_result_staged=reached,response_body=body,pending_flag=pending))
    return dict(firmware_sha256=HIGH_HASH,
                code_sha256={hex(a):hashlib.sha256(high[a-0x20000:b-0x20000]).hexdigest()
                             for a,b in ((0xa4a38,0xa4c9e),(0xb1970,0xb1b24))},
                descriptor=descriptor,cases=records,
                limits=['Dispatcher traced statically; only descriptor processor and Mode 23 helpers executed.',
                        'Receive queue, physical addressing acceptance and response scheduling not executed.',
                        'Synthetic state and target data; no live security or transport operation.'],
                live_read_enabled=False,live_write_enabled=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--high',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    report=analyze(args.high.read_bytes())
    args.output.write_bytes((json.dumps(report,indent=2)+'\n').encode())
    print('PASS',len(report['cases']),'native descriptor/state/lock cases; no transport')
