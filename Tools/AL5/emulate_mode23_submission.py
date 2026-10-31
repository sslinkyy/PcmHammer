"""Offline transmit submission with an inert MMIO page, never a physical device."""
import argparse
import hashlib
import json
from pathlib import Path
from emulate_mode23_boundary import Boundary
from emulate_mode23_coverage import HIGH_HASH

EXTRA=((0x70a44,0x70aa6),(0x70e58,0x70e94),(0x70ea4,0x70ecc))


class Submission(Boundary):
    def __init__(self, high):
        super().__init__(high)
        from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
        self.ranges.extend(EXTRA)
        self.u.mem_map(0xffffe000,0x1000)
        self.register_writes=[]
        self.register_reads=[]
        self.u.hook_add(UC_HOOK_MEM_WRITE,self.write_register,begin=0xffffe000,end=0xffffefff)
        self.u.hook_add(UC_HOOK_MEM_READ,self.read_register,begin=0xffffe000,end=0xffffefff)

    def write_register(self,u,access,address,size,value,user):
        if size!=1 or address not in (0xffffe800,0xffffe801):
            raise ValueError('Unexpected synthetic MMIO write')
        self.register_writes.append((hex(address),value))

    def read_register(self,u,access,address,size,value,user):
        self.register_reads.append((hex(address),size))


def analyze(high):
    records=[]
    for status in (0,0xff):
        p=Submission(high)
        p.request(0x1fffc)
        staged=p.format()
        payload=bytes.fromhex(staged['tx'])
        p.u.mem_write(0xffffe802,bytes([status]))
        p.call(0x70a44,[])
        expected=[]
        for i,value in enumerate(payload):
            command=0x14 if i==0 else 0x0c if i==len(payload)-1 else 0x04
            expected.extend([('0xffffe800',command),('0xffffe801',value)])
        assert p.register_writes==expected
        assert p.register_reads==[]
        assert p.snapshot()['tx_count']==0 and p.snapshot()['pending']=='00'
        assert bytes(p.u.mem_read(0xff96de,len(payload)))==payload
        records.append(dict(case='submission_ignores_synthetic_status',synthetic_status=status,
                            register_writes=p.register_writes,register_reads=p.register_reads,
                            tx_count_after=0,staging_bytes_retained=True,
                            hardware_completion_observed=False))
    # Software buffer discard does not clear the pending response body or RX record.
    p=Submission(high)
    p.request(0x15fd8)
    p.u.mem_write(0xff96de,bytes.fromhex('6cf01863fffcbfd0e1f2'))
    p.u.mem_write(0xff96e9,b'\x0a')
    p.u.mem_write(0xff8eb7,bytes.fromhex('086d18f02301fffc01'))
    before=p.snapshot()
    p.call(0x70ea4,[])
    assert p.snapshot()['pending']==before['pending']=='10'
    assert p.snapshot()['body']==before['body']
    assert p.u.mem_read(0xff96de,11)==b'\0'*11
    assert p.u.mem_read(0xff8eb7,9)==bytes.fromhex('086d18f02301fffc01')
    assert not p.register_reads and not p.register_writes
    records.append(dict(case='software_discard_is_not_session_invalidation',pending_preserved=True,
                        response_body_preserved=True,receive_record_preserved=True,tx_count_after=0))
    return dict(firmware_sha256=HIGH_HASH,
                code_sha256={hex(a):hashlib.sha256(high[a-0x20000:b-0x20000]).hexdigest() for a,b in EXTRA},
                cases=records,session_boundary_proven=False,live_read_enabled=False,live_write_enabled=False,
                limits=['MMIO mapped to inert emulator RAM; writes recorded, not delivered to hardware.',
                        'Synthetic status bytes are not a model of peripheral semantics.',
                        'No interrupt, arbitration, acknowledgement, completion or adapter queue modeled.',
                        'No timing bound or physical drain/invalidation guarantee established.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--high',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    report=analyze(args.high.read_bytes())
    args.output.write_bytes((json.dumps(report,indent=2)+'\n').encode())
    print('PASS',len(report['cases']),'native submission/discard cases; no hardware completion established')
