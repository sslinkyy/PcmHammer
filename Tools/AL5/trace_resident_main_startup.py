"""Bounded native application-entry/main trace with explicit unknown-MMIO and storage stops.

Only a pinned saved image executes in Unicorn. Register readback after an earlier
native write is a conditional inert-memory model, never hardware verification.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
from emulate_calibration_marker import validate_source

BASE=0xFF8000
FIELDS={'pending':(0xF3F,1),'tracking':(0xF46,2),'body':(0x2269,6),
        'rx_length':(0xF2C,2),'tx_count':(0x16E9,1),'ring':(0xEB6,54)}
STORAGE=(0x22B18,0x22C3C,0x22CF0)


def is_register(address):
    a=address&0xFFFFFF
    return a>=0xFFF000 or 0xFFE800<=a<0xFFE810


def trace(image,pattern=0xA5,mmio_inputs=None,*,model_bank_programs=False,stop_after_communication=False,stop_before_startup_wait=False,scheduled_ticks=0,mmio_site_inputs=None):
    if type(scheduled_ticks) is not int or not 0<=scheduled_ticks<=320:
        raise ValueError('Scripted tick campaign requires an integer count from zero through 320')
    if scheduled_ticks and stop_after_communication:
        raise ValueError('Tick continuation cannot stop at the earlier communication boundary')
    validate_source(image[:0x20000],image[0x20000:])
    from unicorn import Uc,UC_ARCH_M68K,UC_MODE_BIG_ENDIAN,UC_PROT_ALL,UC_PROT_READ,UC_PROT_EXEC,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_INVALID,UcError
    from unicorn.m68k_const import UC_CPU_M68K_M68020,UC_M68K_REG_A7,UC_M68K_REG_SR,UC_M68K_REG_PC
    from capstone import Cs,CS_ARCH_M68K,CS_MODE_BIG_ENDIAN,CS_MODE_M68K_020
    u=Uc(UC_ARCH_M68K,UC_MODE_BIG_ENDIAN);u.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    u.mem_map(0,0x100000);u.mem_write(0,image);u.mem_protect(0,0x100000,UC_PROT_READ|UC_PROT_EXEC)
    backing=ctypes.create_string_buffer(0x8000);u._alias_backing=backing
    u.mem_map_ptr(BASE,0x8000,UC_PROT_ALL,ctypes.addressof(backing))
    u.mem_map_ptr(0xFFFF8000,0x8000,UC_PROT_ALL,ctypes.addressof(backing))
    u.mem_write(BASE,bytes([pattern])*0x3800)
    u.reg_write(UC_M68K_REG_A7,int.from_bytes(image[:4],'big'));u.reg_write(UC_M68K_REG_SR,0x2700)
    decoder=Cs(CS_ARCH_M68K,CS_MODE_M68K_020|CS_MODE_BIG_ENDIAN)
    out=dict(initial_pattern=pattern,stop=None,instructions=0,mmio_writes=[],critical_writes=[],main_calls=[],boundaries=[],synthetic_bank_programs=[],scripted_ticks=[],native_event_masks=[],entry_counts={},software_submissions=[])
    written=set();active=None;next_call=None;poll_reads={};foreground_resume=False
    inputs=[dict(row) for row in (mmio_inputs or [])];consumed=[]
    sites=[dict(row) for row in (mmio_site_inputs or [])];site_map={};site_consumed=[]
    for row in inputs+sites:
        if set(row)!={'pc','address','size','value'} or any(type(v) is not int for v in row.values()):
            raise ValueError('Each explicit MMIO input requires integer pc/address/size/value')
        if not 0<=row['pc']<0x100000 or not 0<=row['address']<=0xFFFFFFFF or row['size'] not in (1,2,4) or row['address']+row['size']>0x100000000 or not all(is_register(row['address']+i) for i in range(row['size'])) or not 0<=row['value']<1<<(8*row['size']):
            raise ValueError('Explicit MMIO input outside the declared register context')
    for row in sites:
        key=(row['pc'],row['address'],row['size'])
        if key in site_map:raise ValueError('Repeated MMIO assumption site')
        site_map[key]=row

    def state():
        return {name:bytes(u.mem_read(BASE+a,n)).hex() for name,(a,n) in FIELDS.items()}

    def scheduling_state():
        return dict(sr=u.reg_read(UC_M68K_REG_SR),handshake=u.mem_read(BASE+0xD0,1)[0],
                    current=int.from_bytes(u.mem_read(BASE+0xF4,4),'big'),pending=int.from_bytes(u.mem_read(BASE+0xF8,4),'big'),
                    tick=int.from_bytes(u.mem_read(BASE+0x118,4),'big'),divider=int.from_bytes(u.mem_read(BASE+0x11C,4),'big'),
                    slow_phase=int.from_bytes(u.mem_read(BASE+0x120,4),'big'))

    def halt(reason,**details):
        if out['stop'] is None:
            out['stop']=dict(reason=reason,pc=u.reg_read(UC_M68K_REG_PC),**details)
            if reason=='before_storage_primitive':
                sp=u.reg_read(UC_M68K_REG_A7)
                out['stop']['stack_pointer']=sp
                out['stop']['stack_hex']=bytes(u.mem_read(sp,32)).hex()
        u.emu_stop()

    def code(machine,pc,size,user):
        nonlocal active,next_call
        out['instructions']+=1
        if pc in STORAGE:
            if pc==0x22C3C and model_bank_programs:
                from emulate_storage_recovery import require_programmable
                sp=machine.reg_read(UC_M68K_REG_A7)
                args=[int.from_bytes(machine.mem_read(sp+4+i*4,4),'big') for i in range(4)]
                status,source,destination,words=args;length=2*(words&0xFFFF)
                ram=lambda a,n: BASE<=(a&0xFFFFFF) and (a&0xFFFFFF)+n<=BASE+0x3800
                if len(out['synthetic_bank_programs'])>=32 or not 0<length<=0x2000 or not ram(source,length) or not ram(status,2) or not any(bank<=destination and destination+length<=bank+0x2000 for bank in (0x4000,0x6000)):
                    halt('rejected_synthetic_bank_program',arguments=args);return
                before=bytes(machine.mem_read(destination,length));payload=bytes(machine.mem_read(source,length))
                try:require_programmable(before,payload)
                except ValueError:
                    halt('synthetic_program_requires_erase',arguments=args);return
                machine.mem_write(destination,payload);machine.mem_write(status,b'\x00\x00')
                out['synthetic_bank_programs'].append(dict(caller_return=int.from_bytes(machine.mem_read(sp,4),'big'),source=source,destination=destination,bytes=length,before=before.hex(),after=payload.hex(),implementation_executed=False))
                machine.reg_write(UC_M68K_REG_PC,int.from_bytes(machine.mem_read(sp,4),'big'));machine.reg_write(UC_M68K_REG_A7,sp+4);return
            halt('before_storage_primitive',entry=pc);return
        if not 0<=pc<0x100000:halt('unexpected_execution_target',target=pc);return
        if pc in (0x238AC,0xA4A38,0xC3D98,0xBD6D8,0x4FEE8):
            key=hex(pc);out['entry_counts'][key]=out['entry_counts'].get(key,0)+1
        if pc==0xA4560:
            sp=machine.reg_read(UC_M68K_REG_A7)
            out['native_event_masks'].append(int.from_bytes(machine.mem_read(sp+4,4),'big'))
        if pc==0x70A44:
            length=machine.mem_read(BASE+0x16E9,1)[0]
            out['software_submissions'].append(dict(hex=bytes(machine.mem_read(BASE+0x16DE,length)).hex(),
                response_index=int.from_bytes(machine.mem_read(BASE+0xF54,2),'big'),tick=scheduling_state()['tick']))
        if pc in (0xBE4F4,0x994D0,0xBDC38,0xC02F8,0x99766,0x9976E):
            out['boundaries'].append(dict(pc=pc,state=state(),scheduling=scheduling_state()))
        if next_call is not None:
            next_call['target']=pc;active=next_call;out['main_calls'].append(active);next_call=None
        if active is not None and pc==active['return_pc']:
            active.update(returned=True,after=state());active=None
        if pc==0x99604 and stop_after_communication:
            halt('after_communication_setup_return');return
        if pc==0x5003C and not foreground_resume and (stop_before_startup_wait or scheduled_ticks):
            halt('before_startup_handshake_wait');return
        if pc==0x5004C and foreground_resume:
            halt('after_native_startup_handshake');return
        if 0x994D0<=pc<0x99780:
            instructions=list(decoder.disasm(bytes(machine.mem_read(pc,12)),pc,count=1))
            if instructions and instructions[0].mnemonic=='jsr':
                ins=instructions[0];next_call=dict(call_pc=pc,return_pc=pc+ins.size,returned=False,before=state())

    def read(machine,access,address,size,value,user):
        pc=machine.reg_read(UC_M68K_REG_PC)
        if is_register(address) and inputs and all(inputs[0][k]==v for k,v in (('pc',pc),('address',address),('size',size))):
            row=inputs.pop(0);machine.mem_write(address,row['value'].to_bytes(size,'big'))
            consumed.append(row);poll_reads.clear();return
        key=(pc,address,size)
        if is_register(address) and not inputs and key in site_map:
            row=site_map[key];machine.mem_write(address,row['value'].to_bytes(size,'big'))
            site_consumed.append(dict(row));poll_reads.clear();return
        if is_register(address) and any(((address+i)&0xFFFFFF) not in written for i in range(size)):
            halt('unknown_mmio_read',address=address,size=size)
        elif is_register(address):
            observed=bytes(machine.mem_read(address,size));key=(pc,address,size)
            if poll_reads.get(key)==observed:halt('unchanged_peripheral_poll',address=address,size=size,value=int.from_bytes(observed,'big'))
            poll_reads[key]=observed

    def write(machine,access,address,size,value,user):
        if address<0x100000:halt('blocked_flash_store',address=address,size=size,value=value);return
        if is_register(address):
            poll_reads.clear()
            for i in range(size):written.add((address+i)&0xFFFFFF)
            out['mmio_writes'].append(dict(pc=machine.reg_read(UC_M68K_REG_PC),address=address,size=size,value=value))
        else:
            a=address&0xFFFFFF
            for name,(offset,count) in FIELDS.items():
                if a<BASE+offset+count and a+size>BASE+offset:
                    out['critical_writes'].append(dict(pc=machine.reg_read(UC_M68K_REG_PC),field=name,address=address,size=size,value=value))

    def invalid(machine,access,address,size,value,user):
        halt('unmapped_or_protected_memory',access=access,address=address,size=size);return False

    u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_READ,read);u.hook_add(UC_HOOK_MEM_WRITE,write);u.hook_add(UC_HOOK_MEM_INVALID,invalid)
    entry=int.from_bytes(image[0x20408:0x2040C],'big')
    try:u.emu_start(entry,0x100000,timeout=30_000_000,count=8000000)
    except UcError as error:
        if out['stop'] is None:out['stop']=dict(reason='emulator_error',pc=u.reg_read(UC_M68K_REG_PC),detail=str(error))
    if out['stop'] is None:out['stop']=dict(reason='instruction_or_time_budget',pc=u.reg_read(UC_M68K_REG_PC))
    if scheduled_ticks and out['stop']['reason']=='before_startup_handshake_wait':
        for number in range(scheduled_ticks):
            saved=u.context_save();sp=u.reg_read(UC_M68K_REG_A7)-4;old=bytes(u.mem_read(sp,4))
            before=scheduling_state();counts=dict(out['entry_counts']);mask_start=len(out['native_event_masks'])
            out['stop']=None;u.mem_write(sp,(0x100000).to_bytes(4,'big'));u.reg_write(UC_M68K_REG_A7,sp)
            u.reg_write(UC_M68K_REG_SR,before['sr']|0x700)
            try:u.emu_start(0xBD6D8,0x100000,timeout=5_000_000,count=1000000)
            except UcError as error:
                if out['stop'] is None:out['stop']=dict(reason='emulator_error',pc=u.reg_read(UC_M68K_REG_PC),detail=str(error))
            returned=u.reg_read(UC_M68K_REG_PC)==0x100000 and out['stop'] is None
            after=scheduling_state();u.context_restore(saved);u.mem_write(sp,old)
            out['scripted_ticks'].append(dict(number=number+1,before=before,after=after,returned=returned,
                event_masks=out['native_event_masks'][mask_start:],state=state(),
                entries={key:value-counts.get(key,0) for key,value in out['entry_counts'].items() if value!=counts.get(key,0)},
                physical_exception_delivered=False))
            if not returned:
                if out['stop'] is None:out['stop']=dict(reason='scripted_tick_budget',pc=u.reg_read(UC_M68K_REG_PC))
                break
            if after['handshake']==2:
                foreground_resume=True
                try:u.emu_start(0x5003C,0x100000,timeout=1_000_000,count=100)
                except UcError as error:
                    if out['stop'] is None:out['stop']=dict(reason='emulator_error',pc=u.reg_read(UC_M68K_REG_PC),detail=str(error))
                if out['stop'] is None:out['stop']=dict(reason='foreground_resume_budget',pc=u.reg_read(UC_M68K_REG_PC))
                break
        else:out['stop']=dict(reason='scripted_tick_limit',pc=u.reg_read(UC_M68K_REG_PC))
    out.update(final_state=state(),banks_unchanged=bytes(u.mem_read(0x4000,0x4000))==image[0x4000:0x8000],
               application_entry=entry,flash_image_sha256=hashlib.sha256(image).hexdigest(),
               consumed_mmio_inputs=consumed,unused_mmio_inputs=inputs,
               consumed_mmio_site_inputs=site_consumed,mmio_site_inputs=sites,
               model_bank_programs=model_bank_programs,stop_after_communication=stop_after_communication,
               stop_before_startup_wait=stop_before_startup_wait,scheduled_ticks=scheduled_ticks)
    out['scheduling_context']=scheduling_state()
    banks=bytes(u.mem_read(0x4000,0x4000))
    out['bank_comparison']=dict(original_sha256=hashlib.sha256(image[0x4000:0x8000]).hexdigest(),final_sha256=hashlib.sha256(banks).hexdigest(),
                                changed_addresses=[0x4000+i for i,(old,new) in enumerate(zip(image[0x4000:0x8000],banks)) if old!=new])
    out['communication_context']=dict(receive_flags=bytes(u.mem_read(BASE+0xF56,7)).hex(),
        transmit_eligibility=bytes(u.mem_read(BASE+0xF48,11)).hex(),mode23_eligible=bool(u.mem_read(BASE+0xF51,1)[0]&0x10),
        producer=u.mem_read(BASE+0xEFE,1)[0],consumer=u.mem_read(BASE+0xEFF,1)[0])
    return out


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--full-reference',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--mmio-inputs',type=Path)
    parser.add_argument('--model-bank-programs',action='store_true',help='Host-model bounded atomic bank programs only; never execute flash implementation')
    parser.add_argument('--stop-after-communication',action='store_true')
    parser.add_argument('--stop-before-startup-wait',action='store_true')
    parser.add_argument('--scheduled-ticks',type=int,default=0,help='Synthetic calls to native timer body; no hardware interrupt delivery or elapsed-time claim')
    parser.add_argument('--mmio-site-inputs',type=Path,help='Explicit repeatable read-site assumptions, usable only after ordered inputs are consumed')
    args=parser.parse_args()
    if args.output.exists():parser.error('New output required')
    inputs=[] if args.mmio_inputs is None else json.loads(args.mmio_inputs.read_text(encoding='utf-8'))
    if not isinstance(inputs,list):parser.error('MMIO input document must be an explicit list')
    sites=[] if args.mmio_site_inputs is None else json.loads(args.mmio_site_inputs.read_text(encoding='utf-8'))
    if not isinstance(sites,list):parser.error('MMIO site document must be an explicit list')
    image=args.full_reference.read_bytes();result=dict(schema='al5-offline-application-startup-audit-v1',cases=[trace(image,mmio_inputs=inputs,model_bank_programs=args.model_bank_programs,stop_after_communication=args.stop_after_communication,stop_before_startup_wait=args.stop_before_startup_wait,scheduled_ticks=args.scheduled_ticks,mmio_site_inputs=sites)],
        input_reference=dict(selected=str(args.full_reference),resolved=str(args.full_reference.resolve())),
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        source_dependency_sha256={name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in
            ('emulate_calibration_marker.py','emulate_storage_recovery.py','emulate_storage_selection.py','emulate_application_boot.py','checksum.py','al5_segment.py')},
        mmio_input_reference=None if args.mmio_inputs is None else dict(selected=str(args.mmio_inputs),resolved=str(args.mmio_inputs.resolve()),sha256=hashlib.sha256(args.mmio_inputs.read_bytes()).hexdigest()),
        mmio_site_input_reference=None if args.mmio_site_inputs is None else dict(selected=str(args.mmio_site_inputs),resolved=str(args.mmio_site_inputs.resolve()),sha256=hashlib.sha256(args.mmio_site_inputs.read_bytes()).hexdigest()),
        hardware_access=False,full_startup_verified=False,physical_receiver_ready_verified=False,session_boundary_proven=False,
        live_read_enabled=False,live_upload_enabled=False,live_execution_enabled=False,live_write_enabled=False,
        limits=['Pinned image in Unicorn with declared 24-bit RAM alias and synthetic dirty RAM.',
                'MMIO readback after a prior write is conditional inert storage, not verified device behavior.',
                'Unknown MMIO, storage primitives and unexpected execution stop before being assumed successful.',
                'Optional bank continuation uses bounded atomic host programs; native flash implementation and physical persistence are not verified.',
                'Scripted timer-body calls preserve foreground registers but do not deliver physical exceptions or execute the vector wrapper/RTE.',
                'No real exception delivery, physical peripheral timing or controller/adapter/USB drain.'])
    with args.output.open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2)
    print(json.dumps(dict(stop=result['cases'][0]['stop'],main_calls=len(result['cases'][0]['main_calls']),banks_unchanged=result['cases'][0]['banks_unchanged'])))
