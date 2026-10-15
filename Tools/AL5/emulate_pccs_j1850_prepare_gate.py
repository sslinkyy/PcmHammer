"""Pinned inherited EnterWrite gate with TJ1850 virtual bindings, offline.

The +44 method and delay are synthetic, state-preserving callbacks. Stops
before +60 startup, ordinary request construction, or alternate preparation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from itertools import product
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

START, END = 0x5b8c1d, 0x5b8caa
BOUNDARIES={0x5b8c50:'startup_virtual_60',0x5b8ed6:'ordinary_request_builder',END:'alternate_preparation'}
THIS,STACK=0x10000000,0x20000000
VMT,QUIET,STARTUP=0x723ba0,0x725154,0x7251b8


def permitted_pc(address,size):
    return size>0 and START<=address and address+size<=END


def run(data,*,flag_144=0,flag_158=0,flag_110=0,alternate=0):
    if hashlib.sha256(data).hexdigest()!=SOURCE_SHA256:raise ValueError('source executable pin changed')
    if any(type(v) is not int or not 0<=v<=255 for v in (flag_144,flag_158,flag_110,alternate)):
        raise ValueError('Requires byte-valued synthetic preparation flags')
    import unicorn
    if unicorn.__version__!='2.1.4':raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc,UC_ARCH_X86,UC_MODE_32,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX,UC_X86_REG_EDX,UC_X86_REG_ECX,UC_X86_REG_ESI,UC_X86_REG_ESP,UC_X86_REG_EIP
    sections=executable_sections(data)
    uc=Uc(UC_ARCH_X86,UC_MODE_32)
    pe=struct.unpack_from('<I',data,0x3c)[0]
    base,size=struct.unpack_from('<I',data,pe+52)[0],struct.unpack_from('<I',data,pe+80)[0]
    uc.mem_map(base,(size+0xfff)&~0xfff)
    for s in sections:uc.mem_write(s['va'],data[s['raw_offset']:s['raw_offset']+s['raw_bytes']])
    uc.mem_map(THIS,0x75000);uc.mem_map(STACK,0x10000)
    uc.mem_write(THIS,struct.pack('<I',VMT));uc.mem_write(THIS+0x72d90,bytes([alternate]))
    for address,value in ((0x81d144,flag_144),(0x81d158,flag_158),(0x81d110,flag_110)):
        uc.mem_write(address,bytes([value]))
    if int.from_bytes(uc.mem_read(VMT+0x44,4),'little')!=QUIET or int.from_bytes(uc.mem_read(VMT+0x60,4),'little')!=STARTUP:
        raise ValueError('TJ1850 virtual bindings changed')
    sp=STACK+0x8000;uc.reg_write(UC_X86_REG_ESI,THIS);uc.reg_write(UC_X86_REG_ESP,sp)
    callbacks,stops,steps=[],[],[0]
    def code(engine,pc,n,_):
        if pc in BOUNDARIES:stops.append(pc);engine.emu_stop();return
        if pc in (QUIET,0x40e3e4):
            current=engine.reg_read(UC_X86_REG_ESP);ret=int.from_bytes(engine.mem_read(current,4),'little')
            if pc==QUIET:
                if ret!=0x5b8c3f or callbacks or engine.reg_read(UC_X86_REG_EAX)!=THIS:
                    raise ValueError('Unexpected synthetic +44 method')
                callbacks.append('state_preserving_virtual_44');cleanup=4
            else:
                if ret!=0x5b8c46 or int.from_bytes(engine.mem_read(current+4,4),'little')!=50:
                    raise ValueError('Unexpected synthetic preparation delay')
                callbacks.append('suppressed_delay_50');cleanup=8
            engine.reg_write(UC_X86_REG_ESP,current+cleanup);engine.reg_write(UC_X86_REG_EIP,ret);return
        if not permitted_pc(pc,n):raise ValueError(f'Unexpected preparation gate PC {pc:#x}+{n}')
        steps[0]+=1
    def write(engine,access,address,n,value,_):
        if not (n==4 and sp-8<=address and address+n<=sp):raise ValueError('Unexpected preparation gate write')
    uc.hook_add(UC_HOOK_CODE,code);uc.hook_add(UC_HOOK_MEM_WRITE,write)
    uc.emu_start(START,0,count=100)
    if len(stops)!=1:raise ValueError('Preparation gate did not reach boundary')
    startup=stops[0]==0x5b8c50
    if uc.reg_read(UC_X86_REG_ESP)!=sp-(4 if startup else 0):raise ValueError('Unexpected preparation boundary stack')
    args=None
    if startup:
        args=dict(slot='0x60',source_bound_target=hex(STARTUP),dl=uc.reg_read(UC_X86_REG_EDX)&255,
                  ecx=uc.reg_read(UC_X86_REG_ECX),pending_stack_argument=int.from_bytes(uc.mem_read(sp-4,4),'little'))
        if (args['dl'],args['ecx'],args['pending_stack_argument'])!=(1,0,1):raise ValueError('Unexpected startup call context')
    return dict(context=dict(flag_144=flag_144,flag_158=flag_158,flag_110=flag_110,alternate=alternate),
                boundary=BOUNDARIES[stops[0]],startup_call=args,synthetic_callbacks=callbacks,native_instructions=steps[0],
                security_prerequisites_assumed=True,virtual_44_effects_proven=False,
                startup_executed=False,ordinary_builder_executed=False,alternate_preparation_executed=False,
                full_enter_write_executed=False,transport_used=False,live_write_enabled=False,ready_to_flash=False,would_send=[])


def audit(data):
    contexts=[dict(flag_144=a,flag_158=b,flag_110=c,alternate=d) for a,b,c,d in product((0,1),(0,1),(0,1),(0,1,255))]
    cases=[run(data,**c) for c in contexts]
    s=next(s for s in executable_sections(data) if s['va']<=START and END<=s['va']+s['raw_bytes'])
    off=s['raw_offset']+START-s['va']
    return dict(schema='pccs-j1850-inherited-preparation-gate-v1',source_sha256=SOURCE_SHA256,
                source_range=dict(start=hex(START),exclusive_end=hex(END),file_offset=off,sha256=hashlib.sha256(data[off:off+END-START]).hexdigest()),
                cases=cases,limitations=['Interior inherited EnterWrite gate only; preceding security/caller checks excluded.',
                                        'Virtual+44 and delay are state-preserving synthetic callbacks.',
                                        'Stops before startup, ordinary construction or alternate preparation; no continuous session.',
                                        'No AL5 programming or recovery qualification.'],
                live_write_enabled=False,ready_to_flash=False,would_send=[])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('exe',type=Path);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    if args.output.exists():p.error('Output exists; refusing overwrite')
    result=audit(args.exe.read_bytes());result['source_path']=str(args.exe.resolve())
    with args.output.open('x',encoding='utf-8') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(dict(cases=len(result['cases']),ready_to_flash=False)))


if __name__=='__main__':main()
