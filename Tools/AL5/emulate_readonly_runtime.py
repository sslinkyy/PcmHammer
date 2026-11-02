"""Compiled AL5 runtime with scripted FIFO and guarded RAM. Never a vehicle/peripheral qualification."""
import argparse,hashlib,json
from collections import deque
from pathlib import Path
from emulate_readonly_core import request
from readonly_ram_layout import audit,FIXED
class Runtime:
 def __init__(self,code,receipt):
  if hashlib.sha256(code).hexdigest()!=receipt['code_sha256']:raise ValueError('Runtime identity mismatch')
  self.layout=audit(len(code));self.base=receipt['text_base'];self.end=self.base+len(code);self.symbols=receipt['symbols']
  if self.base!=0xFF9006 or receipt['entry']!=self.symbols['al5_ro_entry'] or any(not self.base<=self.symbols[n]<self.end for n in ('al5_ro_entry','al5_ro_init','al5_ro_step','al5_ro_read')):raise ValueError('Runtime symbol/layout mismatch')
  from unicorn import Uc,UC_ARCH_M68K,UC_MODE_BIG_ENDIAN,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_PROT_READ,UC_PROT_EXEC
  from unicorn.m68k_const import UC_CPU_M68K_M68020,UC_M68K_REG_SR
  self.u=Uc(UC_ARCH_M68K,UC_MODE_BIG_ENDIAN);self.u.ctl_set_cpu_model(UC_CPU_M68K_M68020);self.u.reg_write(UC_M68K_REG_SR,0x2700)
  self.u.mem_map(0,0x100000);self.flash=bytes((i*17+(i>>16))&255 for i in range(0x100000));self.u.mem_write(0,self.flash);self.u.mem_protect(0,0x100000,UC_PROT_READ)
  self.u.mem_map(0xFF8000,0x4000);self.u.mem_write(0xFF8000,b'\xa5'*0x4000);self.u.mem_write(self.base,code)
  self.u.mem_map(0xFFE000,0x1000);self.u.mem_map(0xFFF000,0x1000);self.u.mem_map(0x300000,0x1000)
  self.fifo=deque();self.tx=[];self.frames=[];self.current=[];self.command=None;self.watchdog=[];self.flash_reads=[];self.ram_writes=[];self.stack_low=0xFFA800;self.busy=0;self.entry_steps=None
  self.u.hook_add(UC_HOOK_CODE,self.instruction);self.u.hook_add(UC_HOOK_MEM_READ,self.read);self.u.hook_add(UC_HOOK_MEM_WRITE,self.write)
 def instruction(self,u,pc,size,_):
  if pc==0x300000:u.emu_stop();return
  if self.entry_steps is not None and pc==self.symbols['al5_ro_step']:
   self.entry_steps-=1
   if self.entry_steps<0:u.emu_stop();return
  if not (self.base<=pc and pc+size<=self.end):raise ValueError('PC escaped compiled runtime '+hex(pc))
 def read(self,u,access,address,size,value,_):
  if address<0x100000:self.flash_reads.extend(range(address,address+size));return
  if address==0xFFE800 and size==1:
   status=self.fifo[0][0] if self.fifo else self.busy;u.mem_write(address,bytes([status]));return
  if address==0xFFE801 and size==1:
   if not self.fifo:raise ValueError('Data read without scripted event')
   _,data=self.fifo.popleft();u.mem_write(address,bytes([data]));return
  if any(a<=address and address+size<=b for _,a,b in FIXED):return
  # GCC can read literal code/rodata; it may not read arbitrary resident RAM.
  if self.base<=address and address+size<=self.end:return
  raise ValueError('Unowned read '+hex(address))
 def write(self,u,access,address,size,value,_):
  if address==0xFFFA26 and size==2:
   if value not in (0x55,0xAA):raise ValueError('Unexpected watchdog value')
   self.watchdog.append(value);return
  if address==0xFFE800 and size==1:
   if value not in (0x14,0x04,0x0C):raise ValueError('Unexpected VPW command')
   self.command=value;self.tx.append(('command',value));return
  if address==0xFFE801 and size==1:
   if self.command is None:raise ValueError('Data without command')
   self.tx.append(('data',value))
   if self.command==0x14:
    if self.current:raise ValueError('Nested transmit frame')
    self.current=[value]
   elif self.command==0x04:
    if not self.current:raise ValueError('Missing transmit start')
    self.current.append(value)
   else:
    if not self.current:raise ValueError('Missing transmit start')
    self.current.append(value);self.frames.append(bytes(self.current));self.current=[]
   self.command=None;return
  for name,a,b in FIXED:
   if a<=address and address+size<=b:
    self.ram_writes.append((address,size))
    if name=='stack':self.stack_low=min(self.stack_low,address)
    return
  raise ValueError('Write outside owned RAM/exact IO '+hex(address))
 def call(self,name):
  from unicorn.m68k_const import UC_M68K_REG_A7,UC_M68K_REG_D0,UC_M68K_REG_PC
  self.u.mem_write(0xFFA7F8,(0x300000).to_bytes(4,'big'));self.u.reg_write(UC_M68K_REG_A7,0xFFA7F8)
  self.u.emu_start(self.symbols[name],0x300002,count=50000)
  if self.u.reg_read(UC_M68K_REG_PC)!=0x300000:raise ValueError('Call budget exhausted')
  return self.u.reg_read(UC_M68K_REG_D0)
 def feed(self,wire,end_class=0xE0,end_data=0):
  self.fifo.extend((0x20,v) for v in wire);self.fifo.append((end_class,end_data))
  results=[]
  for _ in range(len(wire)+1):results.append(self.call('al5_ro_step'))
  return results
 def drain(self):
  for _ in range(64):
   if self.u.mem_read(0xFFA303,1)==b'\0':return
   self.call('al5_ro_step')
  raise ValueError('Software transmit did not finish')
 def validate_watchdog(self):
  if self.watchdog!=[0x55,0xAA]*(len(self.watchdog)//2) or len(self.watchdog)%2:raise ValueError('Watchdog sequence invalid')

def peripheral_fault_cases(code,receipt):
 """Adversarial scripted statuses; these assertions describe software, not hardware."""
 cases=[];wire=bytes.fromhex('6d18f0b1')+request(0x8000,4)
 for status in range(32):
  r=Runtime(code,receipt);r.call('al5_ro_init');r.feed(wire);before=len(r.tx);r.busy=status
  result=r.call('al5_ro_step');allowed=(status&0x0B)==0
  assert (len(r.tx)>before)==allowed and result==(2 if allowed else 0)
  r.validate_watchdog()
 cases.append(dict(case='all_idle_class_status_bit_combinations',statuses=32,submission_mask='0x0b'))
 r=Runtime(code,receipt);r.call('al5_ro_init')
 # A stuck/repeating data source must overflow into discard, not escape RAM.
 r.fifo.extend([(0x20,0x6D)]*128)
 for _ in range(128):r.call('al5_ro_step')
 assert not r.tx and not r.flash_reads and r.u.mem_read(0xFFA302,1)==b'\x01'
 r.fifo.append((0xE0,0));r.call('al5_ro_step');r.feed(wire);r.drain();r.validate_watchdog()
 assert len(r.frames)==1
 cases.append(dict(case='repeated_data_overflow_then_explicit_end_recovery',repeated_events=128))
 r=Runtime(code,receipt);r.call('al5_ro_init');r.fifo.extend((0x20,b) for b in wire[:13])
 for _ in range(13):r.call('al5_ro_step')
 for _ in range(100):r.call('al5_ro_step')
 assert not r.tx and not r.flash_reads and int.from_bytes(r.u.mem_read(0xFFA300,2),'big')==13
 r.fifo.extend((0x20,b) for b in wire[13:]);r.fifo.append((0xE0,0))
 for _ in range(14):r.call('al5_ro_step')
 r.drain();assert len(r.frames)==1;r.validate_watchdog()
 cases.append(dict(case='idle_gap_retains_partial_frame',idle_polls=100,
                   limitation='No timeout or session boundary is inferred from idle polls.'))
 r=Runtime(code,receipt);r.call('al5_ro_init');r.feed(wire);r.call('al5_ro_step');assert r.current
 r.fifo.append((0xE0,0xC0));before=len(r.tx);r.call('al5_ro_step')
 assert len(r.tx)==before and r.u.mem_read(0xFFA303,1)==b'\x01'
 r.drain();assert len(r.frames)==1;r.validate_watchdog()
 cases.append(dict(case='receive_error_during_tx_does_not_prove_tx_abort',
                   limitation='Current software consumes RX error and continues TX; hardware TX error semantics remain unknown.'))
 r=Runtime(code,receipt);r.call('al5_ro_init');r.feed(wire);r.drain();r.busy=0x0B
 assert r.u.mem_read(0xFFA303,1)==b'\0'
 for _ in range(50):r.call('al5_ro_step')
 assert len(r.frames)==1
 cases.append(dict(case='last_submission_clears_software_pending_before_physical_completion',
                   limitation='No physical completion/acknowledgement event is modeled.'))
 # Inspect every unowned byte, not merely the minimum observed stack address.
 r=Runtime(code,receipt);r.fifo.extend((0x20,b) for b in wire);r.fifo.append((0xE0,0));r.entry_steps=100
 r.u.emu_start(receipt['entry'],0x1000000,count=1000000)
 memory=bytes(r.u.mem_read(0xFF8000,0x4000));checked=0
 for offset,value in enumerate(memory):
  address=0xFF8000+offset
  if r.base<=address<r.end or any(a<=address<b for _,a,b in FIXED):continue
  assert value==0xA5;checked+=1
 assert len(r.frames)==1
 cases.append(dict(case='all_unowned_ram_canaries_preserved',bytes_checked=checked,
                   limitation='Guest CPU accesses only; no asynchronous DMA or interrupt writer is simulated.'))
 r=Runtime(code,receipt);r.call('al5_ro_init');r.feed(wire);r.busy=8;before=len(r.tx)
 for _ in range(150):r.call('al5_ro_step')
 assert len(r.tx)==before and r.u.mem_read(0xFFA303,1)==b'\x01';r.validate_watchdog()
 cases.append(dict(case='persistent_status_bit3_defers_tx_without_native_control_write',polls=150,
                   limitation='No physical status-bit clearing or peripheral initialization is implemented.'))
 r=Runtime(code,receipt);r.call('al5_ro_init');unsupported=bytearray(wire);unsupported[7]=2
 import binascii
 crc=binascii.crc_hqx(unsupported[4:-2],0xFFFF);unsupported[-2:]=crc.to_bytes(2,'big')
 r.feed(bytes(unsupported));r.drain();assert not r.tx and not r.flash_reads
 cases.append(dict(case='unsupported_exit_operation_has_no_flash_or_tx_effect',
                   limitation='Rejecting an unsupported operation does not implement a safe exit.'))
 r=Runtime(code,receipt);r.call('al5_ro_init');r.feed(wire);r.drain();before=(len(r.tx),len(r.flash_reads),len(r.watchdog))
 for _ in range(150):r.call('al5_ro_step')
 assert (len(r.tx),len(r.flash_reads))==before[:2] and len(r.watchdog)==before[2]+300;r.validate_watchdog()
 cases.append(dict(case='post_reply_idle_keeps_polling_without_implicit_exit',polls=150,
                   limitation='Closing a host campaign does not stop or restore the controller runtime.'))
 return cases

def quiesce_cases(code,receipt):
 if 'al5_ro_request_quiesce' not in receipt['symbols']:raise ValueError('Quiesce validation requires the new runtime build')
 cases=[];wire=bytes.fromhex('6d18f0b1')+request(0x15FD8,32)
 r=Runtime(code,receipt);r.call('al5_ro_init');r.call('al5_ro_request_quiesce');assert r.call('al5_ro_step')==32
 r.call('al5_ro_request_quiesce');r.feed(wire)
 assert r.u.mem_read(0xFFA310,1)==b'\x02' and len(r.fifo)==27 and not r.tx and not r.flash_reads;r.validate_watchdog()
 cases.append(dict(case='local_quiesce_parks_then_rejects_all_further_work',physical_exit_proven=False))
 r=Runtime(code,receipt);r.call('al5_ro_init');r.fifo.extend((0x20,b) for b in wire[:13])
 for _ in range(13):r.call('al5_ro_step')
 r.call('al5_ro_request_quiesce')
 for _ in range(150):r.call('al5_ro_step')
 assert r.u.mem_read(0xFFA310,1)==b'\x01' and not r.tx and not r.flash_reads
 r.fifo.extend((0x20,b) for b in wire[13:]);r.fifo.append((0xE0,0))
 for _ in range(14):r.call('al5_ro_step')
 assert r.call('al5_ro_step')==32 and not r.tx and not r.flash_reads;r.validate_watchdog()
 cases.append(dict(case='quiesce_partial_rx_waits_for_end_not_idle_timeout',idle_polls=150))
 r=Runtime(code,receipt);r.call('al5_ro_init');r.feed(wire);r.call('al5_ro_step');r.call('al5_ro_request_quiesce');r.busy=8
 before=len(r.tx)
 for _ in range(150):r.call('al5_ro_step')
 assert len(r.tx)==before and r.u.mem_read(0xFFA310,1)==b'\x01'
 r.feed(bytes.fromhex('6d18f0b1')+request(0x18000,32,sequence=2));r.busy=0;r.drain()
 assert r.call('al5_ro_step')==32 and len(r.frames)==1 and r.flash_reads==list(range(0x15FD8,0x15FF8));r.validate_watchdog()
 cases.append(dict(case='quiesce_finishes_existing_software_reply_and_drops_new_requests',busy_polls=150,
                   limitation='Zero scripted status is only a software park criterion, not physical TX completion.'))
 r=Runtime(code,receipt);r.call('al5_ro_init');r.fifo.extend((0x20,b) for b in wire);r.fifo.append((0xE0,0));r.call('al5_ro_request_quiesce')
 for _ in range(27):r.call('al5_ro_step')
 assert r.call('al5_ro_step')==32 and not r.tx and not r.flash_reads;r.validate_watchdog()
 cases.append(dict(case='quiesce_consumes_queued_rx_without_invoking_reader'))
 r=Runtime(code,receipt);r.call('al5_ro_init');r.u.mem_write(0xFFA310,b'\x03')
 assert r.call('al5_ro_step')==16 and not r.tx and not r.flash_reads
 r=Runtime(code,receipt);r.call('al5_ro_init');r.feed(wire);r.u.mem_write(0xFFA310,b'\x02')
 assert r.call('al5_ro_step')==16 and not r.tx
 cases.append(dict(case='corrupt_lifecycle_or_parked_pending_owner_latches_fault',rejections=2))
 return cases

def analyze(code,receipt):
 cases=[];vectors=[]
 for address,count in [(0,1),(0x3FD8,4),(0xC4C66,2),(0x8000,32),(0x18000,32),(0xFFFFF,1)]:
  r=Runtime(code,receipt);r.call('al5_ro_init');wire=bytes.fromhex('6d18f0b1')+request(address,count);results=r.feed(wire);assert results[-1]==1
  r.drain();r.validate_watchdog();assert len(r.frames)==1 and r.frames[0][:4]==bytes.fromhex('6df018f1')
  body=r.frames[0][4:];assert body[20:-2]==r.flash[address:address+count] and r.flash_reads==list(range(address,address+count))
  vectors.append(dict(address=address,count=count,request_hex=wire[4:].hex(),reply_hex=body.hex(),vpw_request_hex=wire.hex(),vpw_reply_hex=r.frames[0].hex()))
  cases.append(dict(case='valid_frame',address=address,count=count,watchdog_pairs=len(r.watchdog)//2,stack_low=hex(r.stack_low),software_tx_bytes=len(r.frames[0])))
 bad=[bytes.fromhex('6c18f0b1')+request(0x8000,4),bytes.fromhex('6d10f0b1')+request(0x8000,4),bytes.fromhex('6d18f036')+request(0x8000,4),bytes.fromhex('6d18f0b1')+request(0x8000,4)[:-1],bytes(27)]
 corrupted=bytearray(bytes.fromhex('6d18f0b1')+request(0x8000,4));corrupted[-1]^=1;bad.append(bytes(corrupted))
 for wire in bad:
  r=Runtime(code,receipt);r.call('al5_ro_init');r.feed(wire);r.drain();assert not r.frames and not r.flash_reads;r.validate_watchdog()
 cases.append(dict(case='malformed_header_length_overflow_crc',rejections=len(bad)))
 for end_class,end_data in [(0xA0,0),(0xC0,0),(0xE0,0x40),(0xE0,0x80)]:
  r=Runtime(code,receipt);r.call('al5_ro_init');r.feed(bytes.fromhex('6d18f0b1')+request(0x8000,4),end_class,end_data);assert not r.frames and not r.flash_reads
 cases.append(dict(case='error_end_events',rejections=4))
 r=Runtime(code,receipt);r.call('al5_ro_init');r.feed(bytes.fromhex('6d18f0b1')+request(0x8000,4));r.busy=3
 before=len(r.tx)
 for _ in range(50):r.call('al5_ro_step')
 assert len(r.tx)==before;r.busy=0;r.drain();assert len(r.frames)==1;r.validate_watchdog();cases.append(dict(case='busy_tx_bounded_and_watchdog_progress',polls=50))
 r=Runtime(code,receipt);r.call('al5_ro_init');r.u.mem_write(0xFFA303,b'\x01');r.u.mem_write(0xFFA304,b'\xff\xff')
 assert r.call('al5_ro_step')==16 and r.u.mem_read(0xFFA303,1)==b'\x02';assert r.call('al5_ro_step')==16 and not r.tx and not r.flash_reads
 cases.append(dict(case='corrupt_state_latches_fault'))
 # Preserve state across frames and reject a second request while a reply is pending.
 r=Runtime(code,receipt);r.call('al5_ro_init');r.feed(bytes.fromhex('6d18f0b1')+request(0x8000,4));before=list(r.flash_reads)
 r.feed(bytes.fromhex('6d18f0b1')+request(0x18000,4,sequence=2));assert r.flash_reads==before;r.drain();assert len(r.frames)==1
 transcript=[dict(address=0x8000,count=4,request_hex=request(0x8000,4).hex(),reply_hex=r.frames[0][4:].hex(),vpw_request_hex=(bytes.fromhex('6d18f0b1')+request(0x8000,4)).hex(),vpw_reply_hex=r.frames[0].hex())]
 r.feed(bytes.fromhex('6d18f0b1')+request(0x18000,4,sequence=2));r.drain();assert len(r.frames)==2
 transcript.append(dict(address=0x18000,count=4,request_hex=request(0x18000,4,sequence=2).hex(),reply_hex=r.frames[1][4:].hex(),vpw_request_hex=(bytes.fromhex('6d18f0b1')+request(0x18000,4,sequence=2)).hex(),vpw_reply_hex=r.frames[1].hex()))
 assert r.frames[0]!=r.frames[1];r.validate_watchdog();cases.append(dict(case='persistent_state_busy_request_drop_and_next_bank',frames=2))
 r=Runtime(code,receipt);r.call('al5_ro_init');r.feed(bytes(27));assert not r.flash_reads;r.feed(bytes.fromhex('6d18f0b1')+request(0x8000,4));r.drain();assert len(r.frames)==1
 cases.append(dict(case='overflow_recovery_only_at_end_event'))
 # A malformed later request must not resend the retained previous reply buffer.
 r=Runtime(code,receipt);r.call('al5_ro_init');r.feed(bytes.fromhex('6d18f0b1')+request(0x8000,4));r.drain();before=list(r.flash_reads)
 corrupt=bytearray(bytes.fromhex('6d18f0b1')+request(0x18000,4,sequence=2));corrupt[-1]^=1;r.feed(bytes(corrupt));r.drain()
 assert len(r.frames)==1 and r.flash_reads==before
 cases.append(dict(case='bad_next_request_does_not_resubmit_retained_reply'))
 r=Runtime(code,receipt);r.entry_steps=25;r.u.emu_start(receipt['entry'],0x1000000,count=200000);r.validate_watchdog()
 from unicorn.m68k_const import UC_M68K_REG_SR,UC_M68K_REG_A7
 assert r.u.reg_read(UC_M68K_REG_SR)&0x700==0x700 and 0xFFA700<=r.u.reg_read(UC_M68K_REG_A7)<0xFFA800 and len(r.watchdog)==52
 cases.append(dict(case='actual_assembly_entry',steps=25,interrupt_mask=7,watchdog_pairs=26,stack_low=hex(r.stack_low)))
 r=Runtime(code,receipt);r.fifo.extend((0x20,v) for v in bytes.fromhex('6d18f0b1')+request(0x18000,32));r.fifo.append((0xE0,0));r.entry_steps=100
 r.u.emu_start(receipt['entry'],0x1000000,count=1000000);r.validate_watchdog()
 assert len(r.frames)==1 and r.frames[0][4:24]==b'ar\x01\0'+request(0x18000,32)[4:20] and r.flash_reads==list(range(0x18000,0x18020))
 assert r.u.reg_read(UC_M68K_REG_SR)&0x700==0x700
 cases.append(dict(case='assembly_entry_to_complete_scripted_vpw_reply',steps=100,software_tx_bytes=len(r.frames[0]),stack_low=hex(r.stack_low),watchdog_pairs=len(r.watchdog)//2))
 cases.extend(peripheral_fault_cases(code,receipt))
 cases.extend(quiesce_cases(code,receipt))
 return dict(schema='al5-offline-runtime-emulation-v1',code_sha256=receipt['code_sha256'],code_bytes=len(code),cases=cases,valid_cases=vectors,session_transcript=transcript,ram_layout=audit(len(code)),
  flash_writes=0,unowned_ram_writes=0,peripheral_writes='Only scripted VPW command/data and watchdog allowlist',
  live_upload_enabled=False,live_execution_enabled=False,live_write_enabled=False,hardware_qualified=False,
  limits=['Scripted FIFO classes/end flags are not a physical peripheral model or VPW length qualification.',
   'Watchdog order and polling progress do not establish its real deadline or other watchdog requirements.',
   'SR mask does not qualify exception/NMI/DMA behavior or exclusive ownership of resident RAM.',
   'Software submission is not physical transmit completion.'])
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build-dir',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if a.output.exists():p.error('New output required')
 r=analyze((a.build_dir/'readonly_kernel.offline.bin').read_bytes(),json.loads((a.build_dir/'build_receipt.json').read_text()));a.output.open('x').write(json.dumps(r,indent=2));print('PASS',len(r['cases']),'compiled runtime cases')
