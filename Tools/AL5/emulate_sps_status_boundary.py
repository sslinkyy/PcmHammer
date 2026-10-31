"""Pinned SPS native status paths with scripted inert MMIO; no physical bit semantics inferred."""
import json,hashlib,argparse
from pathlib import Path
from emulate_mode23_coverage import Probe

RANGES=((0x70AA8,0x70C9C),(0x70CE0,0x70E32),(0x70A44,0x70AA6),(0x70E58,0x70E94))
STUBS=(0x2377C,0x23570,0x58584,0xC0328,0x23428)
class StatusProbe(Probe):
 def __init__(self,module,status,data=0,flags=0):
  super().__init__(module,source='sps_os')
  from unicorn import UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_PROT_READ,UC_PROT_EXEC
  self.ranges.extend(RANGES);self.status=[status,0];self.callbacks=[];self.writes=[]
  self.u.mem_protect(0,0x100000,7)
  for a in STUBS:self.u.mem_write(a,bytes.fromhex('4e75'))
  self.u.mem_protect(0,0x100000,UC_PROT_READ|UC_PROT_EXEC)
  self.u.mem_map(0xFFFFE000,0x1000);self.u.mem_write(0xFFFFE803,bytes([data]))
  self.u.mem_write(0xFF8F3F,b'\x10');self.u.mem_write(0xFFA269,bytes.fromhex('fffc12345678'))
  self.u.mem_write(0xFF8F58,bytes([flags]));self.u.mem_write(0xFF96EC,b'\x0a')
  self.u.hook_add(UC_HOOK_MEM_READ,self.read,begin=0xFFFFE802,end=0xFFFFE802)
  self.u.hook_add(UC_HOOK_MEM_WRITE,self.write,begin=0xFFFFE000,end=0xFFFFEFFF)
 def hook(self,u,pc,size,user):
  if pc in STUBS:
   from unicorn.m68k_const import UC_M68K_REG_A7
   sp=u.reg_read(UC_M68K_REG_A7);self.callbacks.append(dict(address=hex(pc),stack_argument=u.mem_read(sp+4,4).hex()));return
  super().hook(u,pc,size,user)
 def read(self,u,access,address,size,value,user):
  if size!=1:raise ValueError('Unexpected status access width')
  u.mem_write(address,bytes([self.status.pop(0) if self.status else 0]))
 def write(self,u,access,address,size,value,user):
  if size!=1 or address not in (0xFFFFE800,0xFFFFE801):raise ValueError('Unexpected MMIO access')
  self.writes.append((hex(address),value))
 def state(self):
  return dict(mode23_pending=self.u.mem_read(0xFF8F3F,1).hex(),mode23_body=self.u.mem_read(0xFFA269,6).hex(),
    link_state=self.u.mem_read(0xFF80E2,5).hex(),software_flags=self.u.mem_read(0xFF96EE,1).hex(),
    callbacks=self.callbacks,register_writes=self.writes)

def analyze(module):
 cases=[]
 for status in (0,8,16,24,255):
  p=StatusProbe(module,status);p.call(0x70CE0,[]);r=p.state()
  assert r['mode23_pending']=='10' and r['mode23_body']=='fffc12345678'
  cases.append(dict(entry='0x70ce0',status=status,**r))
 for status,data,flag in [(0,0,0),(0x20,0x41,0),(0x20,0x41,1),(0xE0,0,0),(0xA0,0xC0,0)]:
  p=StatusProbe(module,status,data,flag);p.call(0x70AA8,[]);r=p.state()
  assert r['mode23_pending']=='10' and r['mode23_body']=='fffc12345678'
  cases.append(dict(entry='0x70aa8',status=status,data=data,flag=flag,**r))
 # Bind the distinct native branches, not only their unchanged response storage.
 assert cases[1]['register_writes']==[('0xffffe800',224),('0xffffe801',0),('0xffffe800',20),('0xffffe801',8),('0xffffe800',4),('0xffffe801',255),('0xffffe800',4),('0xffffe801',24),('0xffffe800',12),('0xffffe801',3)]
 assert any(x['address']=='0x23570' and x['stack_argument']=='00000041' for x in cases[6]['callbacks'])
 assert not any(x['address']=='0x23570' for x in cases[7]['callbacks'])
 assert any(x['address']=='0x23428' for x in cases[8]['callbacks'])
 return dict(sps_os_sha256=hashlib.sha256(module).hexdigest(),code_sha256={hex(a):hashlib.sha256(module[a-0x20000:b-0x20000]).hexdigest() for a,b in RANGES},
  cases=cases,session_boundary_proven=False,live_read_enabled=False,live_write_enabled=False,
  limits=['Scripted MMIO is inert memory, not a model of physical peripheral semantics or interrupt cadence.',
    'Receive accumulation/event callbacks are intercepted; their downstream queue behavior is not executed.',
    'Status paths do not invalidate the staged Mode 23 body/pending bit in these cases.',
    'No controller/adapter TX drain bound or external-session freshness established.'])
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--sps-os',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if a.output.exists():p.error('New output required')
 r=analyze(a.sps_os.read_bytes());a.output.open('x').write(json.dumps(r,indent=2));print('PASS',len(r['cases']),'native status cases; boundary remains unproven')
