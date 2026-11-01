"""Execute the compiled reader core against read-only synthetic flash. No transport or hardware."""
import argparse,binascii,hashlib,json
from pathlib import Path

def request(address,count,nonce=bytes.fromhex('0123456789abcdef'),sequence=1):
    body=b'AR\x01\x01'+nonce+sequence.to_bytes(4,'big')+address.to_bytes(3,'big')+bytes([count])
    return body+binascii.crc_hqx(body,0xFFFF).to_bytes(2,'big')

def run(code,entry,wire,capacity=54,request_pointer=None,reply_pointer=None):
    from unicorn import Uc,UC_ARCH_M68K,UC_MODE_BIG_ENDIAN,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_READ,UC_PROT_READ
    from unicorn.m68k_const import UC_CPU_M68K_M68020,UC_M68K_REG_A7,UC_M68K_REG_PC,UC_M68K_REG_D0
    if len(code)>4096 or not 0xFF9006<=entry<0xFF9006+len(code):raise ValueError('Unbounded or invalid core')
    u=Uc(UC_ARCH_M68K,UC_MODE_BIG_ENDIAN);u.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    flash=bytes((i*17+(i>>16))&255 for i in range(0x100000))
    u.mem_map(0,0x100000);u.mem_write(0,flash);u.mem_protect(0,0x100000,UC_PROT_READ)
    u.mem_map(0xFF8000,0x8000);u.mem_write(0xFF9006,code);u.mem_map(0x300000,0x1000)
    req,out,stack=0xFFA500,0xFFA600,0xFFB000
    u.mem_write(req,wire);u.mem_write(out,b'\xcc'*54)
    u.mem_write(stack,b''.join(i.to_bytes(4,'big') for i in (0x300000,req if request_pointer is None else request_pointer,len(wire),out if reply_pointer is None else reply_pointer,capacity)))
    u.reg_write(UC_M68K_REG_A7,stack);reads=[];writes=[]
    def instruction(machine,pc,size,_):
        if pc==0x300000:machine.emu_stop();return
        if not 0xFF9006<=pc<0xFF9006+len(code):raise ValueError('Execution escaped compiled core')
    def write(machine,access,address,size,value,_):
        if not ((out<=address and address+size<=out+min(capacity,54)) or (stack-0x400<=address and address+size<=stack)):
            raise ValueError('Write outside reply/stack: '+hex(address))
        writes.append((address,size))
    def read(machine,access,address,size,value,_):
        if address<0x100000:reads.extend(range(address,address+size))
    u.hook_add(UC_HOOK_CODE,instruction);u.hook_add(UC_HOOK_MEM_WRITE,write);u.hook_add(UC_HOOK_MEM_READ,read)
    u.emu_start(entry,0x300002,count=100000)
    if u.reg_read(UC_M68K_REG_PC)!=0x300000:raise ValueError('Instruction budget exhausted')
    n=u.reg_read(UC_M68K_REG_D0)
    if n>54:raise ValueError('Invalid returned length')
    return bytes(u.mem_read(out,n)),reads,writes

def analyze(code,entry):
    if binascii.crc_hqx(b'123456789',0xFFFF)!=0x29B1:raise ValueError('CRC reference mismatch')
    cases=[]
    for address,count in [(0,1),(0x3FD8,4),(0xC4C66,2),(0x8000,32),(0x18000,32),(0xFFFFF,1),(0xFFFF0,16)]:
        r=request(address,count);reply,reads,writes=run(code,entry,r)
        expected=bytes((i*17+(i>>16))&255 for i in range(address,address+count))
        assert reply[:4]==b'ar\x01\0' and reply[4:20]==r[4:20] and reply[20:-2]==expected
        assert int.from_bytes(reply[-2:],'big')==binascii.crc_hqx(reply[:-2],0xFFFF)
        assert reads==list(range(address,address+count))
        cases.append(dict(address=address,count=count,request_hex=r.hex(),reply_hex=reply.hex(),flash_read_bytes=len(reads),write_scope='reply and stack only'))
    bad=[request(0xFFFFF,2),request(0x100000,1),request(0,0),request(0,33),request(0,1,nonce=bytes(8)),request(0xFF8000,1)]
    for index,value in ((0,0),(2,2),(3,2),(3,0x36),(3,0x3D)):
        wrong=bytearray(request(0x8000,4));wrong[index]=value;wrong[-2:]=binascii.crc_hqx(wrong[:-2],0xFFFF).to_bytes(2,'big');bad.append(bytes(wrong))
    corrupt=bytearray(request(0x8000,4));corrupt[-1]^=1;bad.extend([bytes(corrupt),request(0x8000,4)[:-1],request(0x8000,4)+b'\0'])
    for r in bad:
        reply,reads,writes=run(code,entry,r);assert reply==b'' and reads==[] and all(a<0xFFA600 or a>=0xFFA636 for a,n in writes)
    reply,reads,_=run(code,entry,request(0x8000,32),capacity=53);assert not reply and not reads
    for pointers in ((0,None),(None,0),(None,0xFFFFE800)):
        reply,reads,writes=run(code,entry,request(0x8000,4),request_pointer=pointers[0],reply_pointer=pointers[1]);assert not reply and not reads
    return dict(core_sha256=hashlib.sha256(code).hexdigest(),core_bytes=len(code),entry=hex(entry),valid_cases=cases,rejected_cases=len(bad)+4,
        flash_writes=0,peripheral_accesses=0,live_upload_enabled=False,hardware_qualified=False,
        limitations=['Synthetic flash and CPU emulation only; no bus, watchdog, interrupt or RAM-placement qualification.',
                    'The compiled function is callable core code, not an autonomous controller kernel.',
                    'Requests/replies are experimental core payloads, without a VPW transport wrapper.'])
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--core',type=Path,required=True);p.add_argument('--entry',type=lambda v:int(v,0),required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('New output required')
    r=analyze(a.core.read_bytes(),a.entry);a.output.open('x').write(json.dumps(r,indent=2));print('PASS',len(r['valid_cases']),'compiled-core reads and',r['rejected_cases'],'rejections; no hardware')
