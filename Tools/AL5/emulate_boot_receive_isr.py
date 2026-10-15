"""Pinned boot ISR with synthetic FIFO; dispatch, upload and RTE are trapped.

Interrupt entry is supplied explicitly. Native LINK/MOVEM executes unchanged.
No IRQ delivery, peripheral, MMIO, dispatcher or uploaded code is executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
from emulate_boot_session import EXPECTED_LOW

START, RTE = 0x39ac, 0x3b78
STACK = 0x208000


def permitted_pc(a,n):
    return n>0 and (START<=a and a+n<=0x39f4 or 0x3a04<=a and a+n<=RTE)


def run(low,*,enabled=True,events=((0,0),),prior_armed=False):
    if len(low)!=0x20000 or hashlib.sha256(low).hexdigest()!=EXPECTED_LOW:
        raise ValueError('unexpected firmware source pin')
    if low[0x6c:0x70]!=bytes.fromhex('000039ac'):
        raise ValueError('boot vector binding changed')
    if (type(enabled) is not bool or type(prior_armed) is not bool or type(events) is not tuple
            or len(events)>32 or any(type(e) is not tuple or len(e)!=2
              or any(type(v) is not int or not 0<=v<=255 for v in e) for e in events)):
        raise ValueError('Invalid synthetic interrupt context')
    import unicorn
    if unicorn.__version__!='2.1.4':raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc,UC_ARCH_M68K,UC_MODE_BIG_ENDIAN,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_PROT_READ,UC_PROT_EXEC
    from unicorn.m68k_const import UC_CPU_M68K_M68020,UC_M68K_REG_SR,UC_M68K_REG_A7,UC_M68K_REG_PC,UC_M68K_REG_D0
    uc=Uc(UC_ARCH_M68K,UC_MODE_BIG_ENDIAN)
    uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    uc.mem_map(0,0x5000)
    uc.mem_write(0,low[:0x5000])
    uc.mem_protect(0,0x5000,UC_PROT_READ|UC_PROT_EXEC)
    uc.mem_map(0xff8000,0x8000)
    uc.mem_map(0x200000,0x10000)
    uc.mem_write(0xff8010,bytes([int(enabled)]))
    uc.mem_write(0xff8185,bytes([int(prior_armed)]))
    uc.reg_write(UC_M68K_REG_SR,0x2700)
    uc.reg_write(UC_M68K_REG_A7,STACK)
    queue=list(events);calls=[];stops=[];steps=[];flushes=[]
    def callback_return(engine,expected):
        sp=engine.reg_read(UC_M68K_REG_A7)
        ret=int.from_bytes(engine.mem_read(sp,4),'big')
        if ret!=expected:raise ValueError('Unexpected ISR synthetic callback return')
        engine.reg_write(UC_M68K_REG_A7,sp+4)
        engine.reg_write(UC_M68K_REG_PC,ret)
    def hook(engine,pc,n,_):
        if pc in (RTE,0x341c,0x3074):
            stops.append(pc);engine.emu_stop();return
        if pc==0x2e8c:
            if not queue:raise ValueError('Synthetic FIFO exhausted')
            event=queue.pop(0);calls.append(event)
            engine.reg_write(UC_M68K_REG_D0,(event[0]<<8)|event[1])
            callback_return(engine,0x39ce);return
        if pc==0x2d98:
            flushes.append('synthetic_flush')
            callback_return(engine,0x3a22);return
        if not permitted_pc(pc,n):raise ValueError(f'Unexpected ISR PC {pc:#x}+{n}')
        steps.append(pc)
    def write(engine,access,a,n,value,_):
        if not (STACK-64<=a and a+n<=STACK or 0xff8160<=a and a+n<=0xff8172
                or a==0xff8182 and n==1):
            raise ValueError(f'Unexpected ISR write {a:#x}+{n}')
    def read(engine,access,a,n,value,_):
        if 0xffe800<=a<0xffe802:raise ValueError('MMIO escaped synthetic FIFO boundary')
    uc.hook_add(UC_HOOK_CODE,hook)
    uc.hook_add(UC_HOOK_MEM_WRITE,write)
    uc.hook_add(UC_HOOK_MEM_READ,read)
    uc.emu_start(START,0,count=4000)
    if len(stops)!=1:raise ValueError('ISR failed to reach declared boundary')
    pc=stops[0];sp=uc.reg_read(UC_M68K_REG_A7)
    if pc==RTE and sp!=STACK:raise ValueError('Native ISR epilogue stack imbalance')
    if pc!=RTE:
        expected=0x3b1e if pc==0x341c else 0x3aca
        if int.from_bytes(uc.mem_read(sp,4),'big')!=expected:raise ValueError('Unexpected pending dispatcher return')
    return dict(context=dict(enabled=enabled,prior_armed=prior_armed,events=[list(e) for e in events]),
                stop={RTE:'before_rte',0x341c:'resident_dispatch_entry',0x3074:'ram_transfer_entry'}[pc],
                stop_pc=hex(pc),fifo_events_consumed=len(calls),fifo_events_remaining=len(queue),
                flush_calls=len(flushes),staged_buffer_hex=bytes(uc.mem_read(0xff8164,14)).hex(),
                staged_length=int.from_bytes(uc.mem_read(0xff8170,2),'big'),
                processing_flag=uc.mem_read(0xff8182,1)[0],upload_armed=uc.mem_read(0xff8185,1)[0],
                stack_delta=sp-STACK,native_instructions=len(steps),native_link_movem_executed=True,
                exception_return_executed=False,actual_interrupt_delivered=False,
                selected_boot_vbr_zero_context=True,hardware_fifo_qualified=False,
                dispatcher_or_transfer_executed=False,transport_used=False,
                live_write_enabled=False,ready_to_flash=False,would_send=[])


def audit(low):
    normal=tuple((0x20,v) for v in (0x6d,0x18,0xf0,0x34))+((0xa0,0),)
    transfer=tuple((0x20,v) for v in (0x6d,0x18,0xf0,0x36))
    contexts=[dict(enabled=False,events=()),{},dict(events=normal),dict(events=transfer),
              dict(events=normal,prior_armed=True),dict(events=tuple((0x20,1) for _ in range(12))+((0,0),))]
    return dict(schema='al5-boot-isr-boundaries-v1',source_sha256=EXPECTED_LOW,
                vector=dict(offset=0x6c,hex=low[0x6c:0x70].hex(),handler=hex(START)),
                source_range=dict(start=hex(START),exclusive_end=hex(RTE),sha256=hashlib.sha256(low[START:RTE]).hexdigest()),
                cases=[run(low,**c) for c in contexts],
                limitations=['Explicit synthetic interrupt entry and FIFO; peripheral initialization/IRQ delivery excluded.',
                             'Native prologue and MOVEM run unchanged; RTE trapped before execution.',
                             'Dispatch and RAM-transfer entry trapped; arming/loading are separate prior models.',
                             'No flash, MMIO, transport or recovery qualification.'],
                live_write_enabled=False,ready_to_flash=False,would_send=[])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--low',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('Output exists; refusing overwrite')
    result=audit(args.low.read_bytes());result['source_path']=str(args.low.resolve())
    with args.output.open('x',encoding='utf-8') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(dict(cases=len(result['cases']),ready_to_flash=False)))


if __name__=='__main__':main()
