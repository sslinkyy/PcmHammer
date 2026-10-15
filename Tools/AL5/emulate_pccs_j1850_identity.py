"""Pinned TJ1850 probe-reply classifier and reset prefix, independently offline.

Probe buffers/clock/string assignment are synthetic. Reset stops before its
probe call. No driver, complete identification or recovery exchange executes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

THIS, OTHER, STACK, AUX = 0x10000000, 0x11000000, 0x20000000, 0x30000000
PROBE, PROBE_STOP, CLOCK_BOUNDARY = 0x7265b3, 0x72670e, 0x7266e9
RESET, RESET_STOP = 0x726734, 0x726761
SETTER, SETTER_STOP = 0x5b0af8, 0x5b0aff


def machine(data):
    if hashlib.sha256(data).hexdigest()!=SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    import unicorn
    if unicorn.__version__!='2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
    uc=Uc(UC_ARCH_X86,UC_MODE_32)
    pe=struct.unpack_from('<I',data,0x3c)[0]
    base,size=struct.unpack_from('<I',data,pe+52)[0],struct.unpack_from('<I',data,pe+80)[0]
    uc.mem_map(base,(size+0xfff)&~0xfff)
    for s in executable_sections(data):
        uc.mem_write(s['va'],data[s['raw_offset']:s['raw_offset']+s['raw_bytes']])
    for addr,size in ((THIS,0x75000),(OTHER,0x75000),(STACK,0x10000),(AUX,0x1000)):
        uc.mem_map(addr,size)
    return uc


def permitted_pc(phase,address,size):
    ranges={'probe':((PROBE,CLOCK_BOUNDARY),(SETTER,SETTER_STOP)), 'reset':((RESET,RESET_STOP),)}
    return size>0 and any(start<=address and address+size<=stop for start,stop in ranges.get(phase,()))


def run_probe_reply(data,*,reply=bytes.fromhex('00000000486b1841'),index=3):
    uc=machine(data)
    if type(reply) is not bytes or len(reply)>0x21a or type(index) is not int or not 0<=index<=255:
        raise ValueError('Invalid synthetic J1850 probe context')
    from unicorn import UC_HOOK_CODE,UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX,UC_X86_REG_EDX,UC_X86_REG_EBX,UC_X86_REG_EBP,UC_X86_REG_ESP,UC_X86_REG_EIP
    bp,sp=STACK+0x8000,STACK+0x7000
    uc.mem_write(0x81eaf0,struct.pack('<I',AUX))
    uc.mem_write(AUX,struct.pack('<I',index))
    uc.mem_write(THIS+0x52898,struct.pack('<H',len(reply)))
    uc.mem_write(THIS+0x528b0,reply)
    uc.mem_write(THIS+0x528a4,b'\x01')
    uc.mem_write(THIS+index*0xa4+0x80,b'\x09')
    uc.mem_write(THIS+index*0xa4+0xb6,b'\x09')
    uc.mem_write(THIS+0x68c60,b'\x01')
    uc.mem_write(THIS+0x72d90,b'\x01')
    for reg,value in ((UC_X86_REG_EBX,THIS),(UC_X86_REG_EBP,bp),(UC_X86_REG_ESP,sp)):
        uc.reg_write(reg,value)
    stops,strings,clocks,steps=[],[],[],[0]
    def code(engine,pc,size,_):
        if pc in (PROBE_STOP,CLOCK_BOUNDARY):
            stops.append(pc);engine.emu_stop();return
        if pc in (0x40e23c,0x407208):
            current=engine.reg_read(UC_X86_REG_ESP)
            ret=int.from_bytes(engine.mem_read(current,4),'little')
            if pc==0x40e23c:
                if ret!=0x7265fa or clocks:raise ValueError('Unexpected synthetic probe clock')
                clocks.append('synthetic_clock')
                engine.reg_write(UC_X86_REG_EAX,0)
            else:
                source=engine.reg_read(UC_X86_REG_EDX)
                if (engine.reg_read(UC_X86_REG_EAX)!=THIS+index*0xa4+0x44
                        or (ret,source) not in ((0x726631,0x726720),(0x72666e,0x726720),(0x7266b1,0x726730))):
                    raise ValueError('Unexpected synthetic probe string assignment')
                strings.append('   ' if source==0x726720 else 'BP ')
            engine.reg_write(UC_X86_REG_ESP,current+4)
            engine.reg_write(UC_X86_REG_EIP,ret);return
        if not permitted_pc('probe',pc,size):raise ValueError(f'Unexpected probe PC {pc:#x}+{size}')
        steps[0]+=1
    def write(engine,access,address,size,value,_):
        if not (STACK<=address and address+size<=STACK+0x10000 and size>0
                or size==1 and address in (THIS+0x528a4,THIS+index*0xa4+0x80,THIS+index*0xa4+0xb6)):
            raise ValueError('Unexpected native probe write')
    uc.hook_add(UC_HOOK_CODE,code);uc.hook_add(UC_HOOK_MEM_WRITE,write)
    uc.emu_start(PROBE,0,count=300)
    if len(stops)!=1 or uc.reg_read(UC_X86_REG_ESP)!=sp:raise ValueError('Probe slice did not reach balanced boundary')
    return dict(context=dict(reply_hex=reply.hex(),index=index),boundary='reply_handler_exit' if stops[0]==PROBE_STOP else 'clock_or_retry_boundary',
                family=uc.mem_read(THIS+index*0xa4+0x80,1)[0],version=uc.mem_read(THIS+index*0xa4+0xb6,1)[0],
                host_status=uc.mem_read(THIS+0x528a4,1)[0],identity_assignments=strings,synthetic_clock_calls=clocks,
                quick_write=uc.mem_read(THIS+0x68c60,1)[0],alternate=uc.mem_read(THIS+0x72d90,1)[0],
                native_instructions=steps[0],driver_executed=False,full_probe_executed=False,
                live_write_enabled=False,ready_to_flash=False,would_send=[])


def run_reset_prefix(data,*,quick_write=1,global_same_object=True):
    uc=machine(data)
    if type(quick_write) is not int or not 0<=quick_write<=255 or type(global_same_object) is not bool:
        raise ValueError('Invalid synthetic J1850 reset context')
    from unicorn import UC_HOOK_CODE,UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX,UC_X86_REG_ESP,UC_X86_REG_EIP
    owner=THIS if global_same_object else OTHER
    uc.mem_write(0x81f328,struct.pack('<I',AUX));uc.mem_write(AUX,struct.pack('<I',owner))
    for obj in (THIS,OTHER):
        uc.mem_write(obj+0x68c60,bytes([quick_write]));uc.mem_write(obj+0x72d90,b'\x01')
        for index in range(256):uc.mem_write(obj+index*0xa4+0xb4,b'\xaa')
    sp=STACK+0x8000;uc.reg_write(UC_X86_REG_ESP,sp);uc.reg_write(UC_X86_REG_EAX,THIS)
    cleared,steps=[],[0]
    def code(engine,pc,size,_):
        if not permitted_pc('reset',pc,size):raise ValueError('Unexpected reset prefix PC')
        steps[0]+=1
    def write(engine,access,address,size,value,_):
        if size==1 and address==THIS+0x72d90 and value==0:return
        if size==1 and value==0 and 0<=address-owner-0xb4<=255*0xa4 and (address-owner-0xb4)%0xa4==0:
            cleared.append((address-owner-0xb4)//0xa4);return
        if size==4 and sp-12<=address<sp:return
        raise ValueError('Unexpected reset prefix write')
    uc.hook_add(UC_HOOK_CODE,code);uc.hook_add(UC_HOOK_MEM_WRITE,write)
    uc.emu_start(RESET,RESET_STOP,count=4000)
    if uc.reg_read(UC_X86_REG_EIP)!=RESET_STOP or cleared!=list(range(256)) or uc.reg_read(UC_X86_REG_ESP)!=sp-12:
        raise ValueError('Reset prefix did not reach probe-call boundary')
    return dict(context=dict(quick_write=quick_write,global_same_object=global_same_object),
                cleared_global_owner_indices=cleared,local_alternate=uc.mem_read(THIS+0x72d90,1)[0],
                local_quick_write=uc.mem_read(THIS+0x68c60,1)[0],global_owner_quick_write=uc.mem_read(owner+0x68c60,1)[0],
                local_flag0=uc.mem_read(THIS+0xb4,1)[0],global_owner_flag0=uc.mem_read(owner+0xb4,1)[0],
                native_instructions=steps[0],probe_call_executed=False,full_reset_executed=False,
                live_write_enabled=False,ready_to_flash=False,would_send=[])


def audit(data):
    contexts=({},dict(reply=bytes.fromhex('000000006cf118a2')),dict(reply=bytes.fromhex('00000000486b1941')),
              dict(reply=bytes.fromhex('00000000486b1842')),dict(reply=b'1234567'),dict(reply=bytes(128)))
    ranges=[]
    for start,stop in ((PROBE,CLOCK_BOUNDARY),(SETTER,SETTER_STOP),(RESET,RESET_STOP)):
        s=next(s for s in executable_sections(data) if s['va']<=start and stop<=s['va']+s['raw_bytes'])
        off=s['raw_offset']+start-s['va'];ranges.append(dict(start=hex(start),exclusive_end=hex(stop),file_offset=off,
                                                         sha256=hashlib.sha256(data[off:off+stop-start]).hexdigest()))
    return dict(schema='pccs-j1850-probe-reset-slices-v1',source_sha256=SOURCE_SHA256,source_ranges=ranges,
                probe_cases=[run_probe_reply(data,**c) for c in contexts],
                reset_cases=[run_reset_prefix(data,quick_write=q,global_same_object=same) for q in (0,1,255) for same in (True,False)],
                limitations=['Independent native probe-reply and reset-prefix stages; no continuous invocation.',
                             'Synthetic received fields, clock and identity-string assignment.',
                             'Reset stops before probe; later metadata reads/classification/QuickWrite changes excluded.',
                             'No driver, complete identification, programming or recovery qualification.'],
                live_write_enabled=False,ready_to_flash=False,would_send=[])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('exe',type=Path);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    if args.output.exists():p.error('Output exists; refusing overwrite')
    result=audit(args.exe.read_bytes());result['source_path']=str(args.exe.resolve())
    with args.output.open('x',encoding='utf-8') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(dict(probe_cases=len(result['probe_cases']),reset_cases=len(result['reset_cases']),ready_to_flash=False)))


if __name__=='__main__':main()
