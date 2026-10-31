"""Run pinned Mode 23 range helpers and handler in isolated, read-only firmware memory."""
import argparse
import hashlib
import json
from pathlib import Path

HIGH_HASH='492040d9460d53b77dda606b9a89f4254e0680f239093001663f6ed5cf51ba75'
RANGES=((0xbfda0,0xbfe48),(0xc00e8,0xc018e),(0xc2f88,0xc2fce),(0xc2fd0,0xc2ff6))


class Probe:
    def __init__(self,high):
        if hashlib.sha256(high).hexdigest()!=HIGH_HASH:raise ValueError('Firmware identity changed')
        from unicorn import Uc,UC_ARCH_M68K,UC_MODE_BIG_ENDIAN,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
        from unicorn.m68k_const import UC_CPU_M68K_M68020
        self.u=Uc(UC_ARCH_M68K,UC_MODE_BIG_ENDIAN);self.u.ctl_set_cpu_model(UC_CPU_M68K_M68020)
        self.u.mem_map(0,0x100000);self.u.mem_write(0x20000,high)
        self.u.mem_write(0x8000,bytes((n*17+3)&255 for n in range(0x18000)))
        self.u.mem_write(0xc2390,bytes.fromhex('4e75')) # negative formatter intercepted, never real transport
        self.u.mem_protect(0,0x100000,UC_PROT_READ|UC_PROT_EXEC)
        self.u.mem_map(0xff8000,0x8000);self.u.mem_map(0x200000,0x10000);self.u.mem_map(0x300000,0x1000)
        self.ranges=list(RANGES)
        self.u.hook_add(UC_HOOK_CODE,self.hook);self.negative=[]

    def hook(self,u,pc,size,user):
        from unicorn.m68k_const import UC_M68K_REG_A7
        if pc==0x300000:u.emu_stop();return
        if pc==0xc2390:
            sp=u.reg_read(UC_M68K_REG_A7);self.negative.append(int.from_bytes(u.mem_read(sp+8,4),'big'));return
        if not any(a<=pc<b for a,b in self.ranges):raise ValueError('Execution left selected handler/helpers: '+hex(pc))

    def call(self,pc,args):
        from unicorn.m68k_const import UC_M68K_REG_A7,UC_M68K_REG_A5,UC_M68K_REG_D0
        self.u.reg_write(UC_M68K_REG_A5,0xff8000);self.u.reg_write(UC_M68K_REG_A7,0x208800)
        self.u.mem_write(0x208800,b''.join(x.to_bytes(4,'big') for x in [0x300000,*args]))
        self.u.emu_start(pc,0x300002,count=2000)
        from unicorn.m68k_const import UC_M68K_REG_PC
        if self.u.reg_read(UC_M68K_REG_PC)!=0x300000:raise ValueError('Instruction budget exhausted')
        return self.u.reg_read(UC_M68K_REG_D0)&255

    def permission(self,address):return self.call(0xc00e8,[address,4])==1

    def handler(self,address,length=8,count=1):
        self.negative=[];self.u.mem_write(0xffa269,b'\xcc'*6);self.u.mem_write(0xff8f3f,b'\0')
        self.u.mem_write(0x208000,bytes([length])+bytes.fromhex('6d18f023')+address.to_bytes(3,'big')+bytes([count]))
        self.call(0xbfda0,[0x208000])
        return dict(address=address,negative_reasons=list(self.negative),response_body=self.u.mem_read(0xffa269,6).hex(),pending_flag=self.u.mem_read(0xff8f3f,1).hex())


def analyze(high):
    probe=Probe(high)
    rejected=[a for a in range(0x15fd8,0x20000,4) if not probe.permission(a)]
    boundary={hex(a):probe.permission(a) for a in (0x15fd8,0x1fffc,0xffffc,0xffffd,0x100000,0x3fd7,0x3fd8,0xc4c64,0xff8000,0xffb7fc,0xffb7fd)}
    samples=[probe.handler(a) for a in (0x8000,0x18000,0x15fd8,0x1fffc,0x3fd8,0x100000)]
    malformed=[probe.handler(0x1fffc,length=7),probe.handler(0x1fffc,count=2)]
    assert not rejected and boundary['0xffffc'] and not boundary['0xffffd']
    assert samples[0]['response_body']==samples[1]['response_body'] # deliberate alias-data fixture
    for sample in samples[:4]:
        address=sample['address']
        expected=(address&0xffff).to_bytes(2,'big')+bytes(((address-0x8000+n)*17+3)&255 for n in range(4))
        assert sample['response_body']==expected.hex() and sample['pending_flag']=='10' and not sample['negative_reasons']
    assert all(x['negative_reasons']==[0x31] and x['pending_flag']=='00' and x['response_body']=='cccccccccccc' for x in samples[4:])
    assert all(x['negative_reasons']==[0x12] for x in malformed)
    return dict(firmware_sha256=HIGH_HASH,table_address='0xc591e',table_hex=high[0xc591e-0x20000:0xc5930-0x20000].hex(),
                code_sha256={hex(a):hashlib.sha256(high[a-0x20000:b-0x20000]).hexdigest() for a,b in RANGES},
                supplemental_dwords_checked=10250,rejected_addresses=rejected,boundary_permissions=boundary,
                handler_samples=samples,malformed_requests=malformed,
                limits=['Synthetic data; isolated handler invocation bypasses dispatcher, security and scheduling.',
                        'Negative formatter intercepted; pending response not transmitted.',
                        'No physical readability or full-address response identity established.'],
                live_read_enabled=False,live_write_enabled=False)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--high',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();r=analyze(a.high.read_bytes());a.output.write_bytes((json.dumps(r,indent=2)+'\n').encode());print(json.dumps(r))
