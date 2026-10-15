"""Bounded native TJ1850 request construction; stops before every send/dispatch."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

RANGES={'seed':(0x725d72,0x725dae),'key':(0x725ebb,0x725f17),'read':(0x7252c5,0x72530e)}
THIS,STACK=0x10000000,0x20000000


def permitted_pc(phase,a,n):
    lo,hi=RANGES.get(phase,(0,0))
    return n>0 and lo<=a and a+n<=hi


def run(data,*,phase='read',identifier=0x1a40,key=0x1234,client=1):
    if hashlib.sha256(data).hexdigest()!=SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if (type(phase) is not str or phase not in RANGES
            or any(type(v) is not int or not 0<=v<=65535 for v in (identifier,key,client))):
        raise ValueError('Invalid prerequisite context')
    import unicorn
    if unicorn.__version__!='2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc,UC_ARCH_X86,UC_MODE_32,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_EDX,UC_X86_REG_EDI,UC_X86_REG_EBP,UC_X86_REG_ESP,UC_X86_REG_EIP
    uc=Uc(UC_ARCH_X86,UC_MODE_32)
    pe=struct.unpack_from('<I',data,0x3c)[0]
    base,size=struct.unpack_from('<I',data,pe+52)[0],struct.unpack_from('<I',data,pe+80)[0]
    uc.mem_map(base,(size+0xfff)&~0xfff)
    for s in executable_sections(data):
        uc.mem_write(s['va'],data[s['raw_offset']:s['raw_offset']+s['raw_bytes']])
    uc.mem_map(THIS,0x75000)
    uc.mem_map(STACK,0x10000)
    bp,sp=STACK+0x8000,STACK+0x7000
    uc.mem_write(THIS,struct.pack('<I',THIS+0x1000))
    uc.mem_write(THIS+0x2c,struct.pack('<H',client))
    uc.mem_write(THIS+0x29e,struct.pack('<H',key))
    for r,v in ((UC_X86_REG_EBX,THIS),(UC_X86_REG_EDI,THIS),(UC_X86_REG_EDX,identifier),
                (UC_X86_REG_EBP,bp),(UC_X86_REG_ESP,sp)):
        uc.reg_write(r,v)
    start,stop=RANGES[phase]
    steps=[]
    def code(engine,a,n,_):
        if not permitted_pc(phase,a,n):
            raise ValueError(f'Unexpected prerequisite PC {a:#x}+{n}')
        steps.append(a)
    def write(engine,access,a,n,value,_):
        permitted=(n==4 and sp-20<=a<sp
                   or phase=='read' and n==1 and THIS+0x52250<=a<THIS+0x52254
                   or phase=='read' and n==4 and a in (THIS+0x52894,THIS+0x5289c)
                   or phase in ('seed','key') and n==1 and THIS+0x528b0<=a<THIS+0x528b0+(6 if phase=='seed' else 8))
        if not permitted:
            raise ValueError(f'Unexpected prerequisite write {a:#x}+{n}')
    uc.hook_add(UC_HOOK_CODE,code)
    uc.hook_add(UC_HOOK_MEM_WRITE,write)
    uc.emu_start(start,stop,count=100)
    if uc.reg_read(UC_X86_REG_EIP)!=stop:
        raise ValueError('Did not reach before-call boundary')
    count=2 if phase=='read' else 5
    args=struct.unpack('<'+'I'*count,uc.mem_read(sp-count*4,count*4))
    if uc.reg_read(UC_X86_REG_ESP)!=sp-count*4:
        raise ValueError('Unexpected pending call stack')
    if phase=='read':
        packet=bytes(uc.mem_read(THIS+0x52250,4))
        if args!=(0x18,0):raise ValueError('Unexpected read dispatch arguments')
    else:
        length=6 if phase=='seed' else 8
        packet=bytes(uc.mem_read(THIS+0x528b0,length))
        if args!=(client,THIS+0x528b0,length,0,1):raise ValueError('Unexpected send arguments')
    return dict(context=dict(phase=phase,identifier=identifier,key=key,client=client),
                constructed_buffer_hex=packet.hex(),pending_stack_arguments=list(args),
                request_length=int.from_bytes(uc.mem_read(THIS+0x52894,4),'little') if phase=='read' else len(packet),
                reply_prefix_length=int.from_bytes(uc.mem_read(THIS+0x5289c,4),'little') if phase=='read' else None,
                native_instructions=len(steps),send_or_dispatch_executed=False,
                supplied_key_synthetic=True,key_algorithm_executed=False,security_authorization_proven=False,
                transport_used=False,live_write_enabled=False,ready_to_flash=False,would_send=[])


def audit(data):
    contexts=[dict(phase='read',identifier=i) for i in (0x1a40,0x1a4a,0x1a68,0x1a69,0x1a6a)]
    contexts += [dict(phase='seed')]+[dict(phase='key',key=k) for k in (0,0x1234,0xffff)]
    ranges=[]
    for phase,(a,b) in RANGES.items():
        s=next(s for s in executable_sections(data) if s['va']<=a<s['va']+s['raw_bytes'])
        off=s['raw_offset']+a-s['va']
        ranges.append(dict(phase=phase,start=hex(a),exclusive_end=hex(b),file_offset=off,sha256=hashlib.sha256(data[off:off+b-a]).hexdigest()))
    return dict(schema='pccs-j1850-prerequisite-construction-v1',source_sha256=SOURCE_SHA256,
                source_ranges=ranges,cases=[run(data,**c) for c in contexts],
                limitations=['Independent constructor slices only; no caller flow or security algorithm.',
                             'Constructed bytes are host buffers, not qualified physical packets.',
                             'No sends, receives, authorization, programming or recovery executed.'],
                live_write_enabled=False,ready_to_flash=False,would_send=[])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('exe',type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if args.output.exists():parser.error('Output exists; refusing overwrite')
    result=audit(args.exe.read_bytes())
    result['source_path']=str(args.exe.resolve())
    with args.output.open('x',encoding='utf-8') as f:
        json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(dict(cases=len(result['cases']),ready_to_flash=False)))


if __name__=='__main__':main()
