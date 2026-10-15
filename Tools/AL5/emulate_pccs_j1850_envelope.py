"""Offline native TJ1850 host envelope; stops before RP1210 SendMessage.

The payload copy is a guarded synthetic Delphi Move boundary. No DLL is loaded.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

START, STOP = 0x72468b, 0x7246f7
THIS, STACK = 0x10000000, 0x20000000


def permitted_pc(a, n):
    return n > 0 and START <= a and a+n <= STOP


def run(data, *, target=0x18, payload=b'\x10\x10', client=1):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if (type(target) is not int or not 0 <= target <= 255 or type(client) is not int
            or not 0 <= client <= 65535 or type(payload) is not bytes or not 1 <= len(payload) <= 128):
        raise ValueError('Invalid bounded J1850 envelope context')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base, size = struct.unpack_from('<I', data, pe+52)[0], struct.unpack_from('<I', data, pe+80)[0]
    uc.mem_map(base, (size+0xfff)&~0xfff)
    for s in executable_sections(data):
        uc.mem_write(s['va'], data[s['raw_offset']:s['raw_offset']+s['raw_bytes']])
    uc.mem_map(THIS, 0x75000)
    uc.mem_map(STACK, 0x10000)
    def put(a, v):
        uc.mem_write(a, struct.pack('<I', v))
    bp, sp = STACK+0x8000, STACK+0x7000
    put(bp+8, target)
    put(THIS+0x2c, client)
    put(THIS+0x52894, len(payload))
    uc.mem_write(THIS+0x52250, payload)
    for reg, value in ((UC_X86_REG_EBP,bp), (UC_X86_REG_ESP,sp), (UC_X86_REG_EBX,THIS)):
        uc.reg_write(reg,value)
    copies, steps, stopped = [], [], []
    def code(engine,a,n,_):
        if a == STOP:
            stopped.append(a)
            engine.emu_stop()
            return
        if a == 0x404820:
            current=engine.reg_read(UC_X86_REG_ESP)
            ret=int.from_bytes(engine.mem_read(current,4),'little')
            regs=tuple(engine.reg_read(r) for r in (UC_X86_REG_EAX,UC_X86_REG_EDX,UC_X86_REG_ECX))
            if copies or ret != 0x7246db or regs != (THIS+0x52250,THIS+0x528b4,len(payload)):
                raise ValueError('Unexpected synthetic payload-copy boundary')
            engine.mem_write(regs[1],bytes(engine.mem_read(regs[0],regs[2])))
            copies.append(dict(source=hex(regs[0]),destination=hex(regs[1]),length=regs[2]))
            engine.reg_write(UC_X86_REG_ESP,current+4)
            engine.reg_write(UC_X86_REG_EIP,ret)
            return
        if not permitted_pc(a,n):
            raise ValueError(f'Unexpected J1850 envelope PC {a:#x}+{n}')
        steps.append(a)
    def write(engine,access,a,n,value,_):
        fields={THIS+0x528ac:4,THIS+0x52898:2,THIS+0x528a4:1,
                THIS+0x528b0:1,THIS+0x528b1:1,THIS+0x528b2:1,THIS+0x528b3:1}
        if not (fields.get(a)==n or n==4 and sp-20 <= a < sp):
            raise ValueError(f'Unexpected J1850 envelope write {a:#x}+{n}')
    uc.hook_add(UC_HOOK_CODE,code)
    uc.hook_add(UC_HOOK_MEM_WRITE,write)
    uc.emu_start(START,0,count=100)
    args=struct.unpack('<5I',uc.mem_read(sp-20,20))
    if stopped != [STOP] or args != (client,THIS+0x528b0,len(payload)+4,0,0) or uc.reg_read(UC_X86_REG_ESP)!=sp-20:
        raise ValueError('J1850 envelope did not stop before expected send call')
    packet=bytes(uc.mem_read(THIS+0x528b0,len(payload)+4))
    return dict(context=dict(target=target,payload_hex=payload.hex(),client=client),
                constructed_buffer_hex=packet.hex(),constructed_length=len(packet),
                pending_callback_args=list(args),send_call_executed=False,
                native_instructions=len(steps),synthetic_payload_copies=copies,
                physical_vpw_frame_proven=False,transport_used=False,
                live_write_enabled=False,ready_to_flash=False,would_send=[])


def audit(data):
    contexts=[{},dict(target=0xfe,payload=b'\x19\x12\xff\x00'),dict(target=0),
              dict(target=255,payload=bytes(range(128)),client=65535)]
    s=next(s for s in executable_sections(data) if s['va']<=START<s['va']+s['raw_bytes'])
    off=s['raw_offset']+START-s['va']
    return dict(schema='pccs-j1850-envelope-v1',source_sha256=SOURCE_SHA256,
                source_range=dict(start=hex(START),exclusive_end=hex(STOP),file_offset=off,
                                  sha256=hashlib.sha256(data[off:off+STOP-START]).hexdigest()),
                cases=[run(data,**c) for c in contexts],class_bindings=audit_class_bindings(data),
                limitations=['Native TJ1850 packet prefix and call arguments only; synthetic payload-copy helper.',
                             'Payload 1..128 is a model resource bound, not a claimed protocol maximum.',
                             'No SendMessage execution, SPX driver implementation, physical CRC, programming or recovery proof.'],
                live_write_enabled=False,ready_to_flash=False,would_send=[])


def audit_class_bindings(data):
    """Read selected source VMT slots; no provider mutation or target execution."""
    if hashlib.sha256(data).hexdigest()!=SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    sections=executable_sections(data)
    def read(va,length):
        s=next(s for s in sections if s['va']<=va and va+length<=s['va']+s['raw_bytes'])
        off=s['raw_offset']+va-s['va']
        return off,data[off:off+length]
    def pointer(va):
        off,raw=read(va,4)
        return dict(address=hex(va),file_offset=off,value=int.from_bytes(raw,'little'),
                    bytes_hex=raw.hex(),sha256=hashlib.sha256(raw).hexdigest())
    base=pointer(0x5a4004)
    alternate=pointer(0x723b48)
    name_pointer=pointer(0x723b68)
    _,length=read(name_pointer['value'],1)
    name_offset,raw_name=read(name_pointer['value']+1,length[0])
    names={0:'dispatch',0x10:'WriteData',0x18:'QuickWriteData',0x24:'slot_24',
           0x2c:'ReadData',0x34:'RequestSeed',0x38:'SendKey',0x3c:'EnterWrite',
           0x40:'EndWrite',0x50:'slot_50',0x54:'slot_54',0x70:'reset_identify'}
    slots=[]
    for slot,label in names.items():
        ordinary=pointer(base['value']+slot)
        j1850=pointer(alternate['value']+slot)
        slots.append(dict(slot=hex(slot),label=label,base=ordinary,j1850=j1850,
                          inherited_same_target=ordinary['value']==j1850['value']))
    return dict(base_descriptor=base,j1850_descriptor=alternate,
                parent_descriptor=pointer(0x723b70),name_pointer=name_pointer,
                class_name=dict(value=raw_name.decode('ascii'),file_offset=name_offset,bytes_hex=raw_name.hex()),
                selected_slots=slots,scope='Selected source slots only; no constructor or complete programming execution',
                base_dispatch_assumptions_valid_for_j1850=False,ready_to_flash=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('exe',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():
        parser.error('Output exists; refusing overwrite')
    result=audit(args.exe.read_bytes())
    result['source_path']=str(args.exe.resolve())
    with args.output.open('x',encoding='utf-8') as f:
        json.dump(result,f,indent=2)
        f.write('\n')
    print(json.dumps(dict(cases=len(result['cases']),ready_to_flash=False)))


if __name__=='__main__':
    main()
