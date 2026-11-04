"""Native captured-loader status, watchdog-service delays and retained-RAM park.

All peripheral instructions are suppressed before access, with MOVE condition
codes modeled explicitly. Real instruction flow uses no watchdog/delay stubs.
No device, hardware timer, upload, flash operation or physical reset executes.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
from emulate_loader_parser import EXPECTED_SHA,BASE,STACK


def experiment(code,*,entry='success_tail',busy_reads=0,park_visits=16):
    if hashlib.sha256(code).hexdigest()!=EXPECTED_SHA:raise ValueError('Exact captured loader required')
    entries={'success_tail':0xFF9224,'bad_sum_tail':0xFF922E,'shared_exit':0xFF9236,'idle_expiry':0xFF903C}
    if type(entry) is not str or entry not in entries or (busy_reads is not None and (type(busy_reads) is not int or not 0<=busy_reads<=4095)):
        raise ValueError('Named entry and bounded explicit readiness scenario required')
    if type(park_visits) is not int or not 1<=park_visits<=64:raise ValueError('One through 64 native park visits required')
    import unicorn
    if unicorn.__version__!='2.1.4':raise ValueError('Unicorn 2.1.4 required')
    from unicorn import Uc,UC_ARCH_M68K,UC_MODE_BIG_ENDIAN,UC_PROT_ALL,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_INVALID
    from unicorn.m68k_const import UC_CPU_M68K_M68020,UC_M68K_REG_PC,UC_M68K_REG_SR,UC_M68K_REG_A7,UC_M68K_REG_D0,UC_M68K_REG_D3,UC_M68K_REG_D5
    u=Uc(UC_ARCH_M68K,UC_MODE_BIG_ENDIAN);u.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    backing=ctypes.create_string_buffer(0x8000);u._alias_backing=backing
    for address in (0xFF8000,0xFFFF8000):u.mem_map_ptr(address,0x8000,UC_PROT_ALL,ctypes.addressof(backing))
    u.mem_write(BASE,code);u.mem_write(0xFF9A78,bytes.fromhex('f06c'))
    u.reg_write(UC_M68K_REG_SR,0x2700);u.reg_write(UC_M68K_REG_A7,STACK)
    if entry=='idle_expiry':u.reg_write(UC_M68K_REG_D3,0x4FFFF) # Selected last idle iteration, not a measured idle interval.
    out=dict(stop=None,instructions=0,ready_reads=0,watchdog_pairs=0,watchdog_writes_suppressed=0,
        phases={},delay_calls=0,delay_entries=[],delay_returns=[],fifo_data=[],fifo_writes=[],interface_writes=[],marker_writes=[],park_visits=0,
        first_park_instruction=None,service_pairs_at_park=None,last_service_instruction=None,receive_entries=0,reset_opcodes=0)
    phase='status' if entry in ('success_tail','bad_sum_tail') else 'exit';pending_service=False
    service_digest=hashlib.sha256()
    def move_flags(value,bits):
        sr=u.reg_read(UC_M68K_REG_SR);mask=(1<<bits)-1;value&=mask
        u.reg_write(UC_M68K_REG_SR,(sr&~15)|(8 if value&(1<<(bits-1)) else 0)|(4 if value==0 else 0))
    def skipped_store(pc,address,value,size):
        # MOVE.{B,W} to memory changes NZVC, preserves X, and changes no data register.
        move_flags(value,size*8);u.reg_write(UC_M68K_REG_PC,pc+6)
    def code_hook(machine,pc,size,_):
        nonlocal phase,pending_service
        out['instructions']+=1
        if pc==0xFF9000:out['stop']='sender_busy_loader_restart_boundary';machine.emu_stop();return
        if pc==0xFF903A:out['receive_entries']+=1;raise RuntimeError('Unexpected receive-loop entry')
        if pc==0xFF961A:
            out['delay_calls']+=1;phase='delay_'+str(out['delay_calls']);out['phases'][phase]=0
            out['delay_entries'].append(dict(phase=phase,instruction=out['instructions']))
        if pc==0xFF962A:out['delay_returns'].append(dict(phase=phase,d5=machine.reg_read(UC_M68K_REG_D5)&65535))
        if pc in (0xFF960C,0xFF9612):
            value=0x55 if pc==0xFF960C else 0xAA
            if pending_service!=(value==0xAA):raise RuntimeError('Watchdog service order violated')
            pending_service=value==0x55;out['watchdog_writes_suppressed']+=1
            service_digest.update(pc.to_bytes(4,'big')+bytes([value]))
            if value==0xAA:
                out['watchdog_pairs']+=1;out['phases'][phase]=out['phases'].get(phase,0)+1;out['last_service_instruction']=out['instructions']
            skipped_store(pc,0xFFFFFA27,value,1);return
        controls={0xFF952E:0x14,0xFF95BE:4,0xFF95B2:0x0C,0xFF923A:0x40}
        if pc in controls:
            out['interface_writes'].append(dict(pc=pc,address=0xFFFFE800,value=controls[pc],phase=phase,instruction=out['instructions']))
            skipped_store(pc,0xFFFFE800,controls[pc],1);return
        if pc in (0xFF95C4,0xFF9240):
            value=machine.reg_read(UC_M68K_REG_D0)&255 if pc==0xFF95C4 else 0
            if pc==0xFF95C4:
                out['fifo_data'].append(value);out['fifo_writes'].append(dict(value=value,instruction=out['instructions']))
            else:out['interface_writes'].append(dict(pc=pc,address=0xFFFFE801,value=value,phase=phase,instruction=out['instructions']))
            # Register-source MOVE.B is four bytes; immediate MOVE.B is six.
            move_flags(value,8);machine.reg_write(UC_M68K_REG_PC,pc+(4 if pc==0xFF95C4 else 6));return
        if pc==0xFF95D8:
            out['ready_reads']+=1;value=3 if busy_reads is None or out['ready_reads']<=busy_reads else 0
            machine.reg_write(UC_M68K_REG_D0,(machine.reg_read(UC_M68K_REG_D0)&0xFFFFFF00)|value)
            move_flags(value,8);machine.reg_write(UC_M68K_REG_PC,pc+4);return
        if pc==0xFF924A:phase='marker'
        if pc==0xFF9250:
            phase='park';out['park_visits']+=1
            if out['service_pairs_at_park'] is None:
                out['service_pairs_at_park']=out['watchdog_pairs'];out['first_park_instruction']=out['instructions']
            if out['park_visits']>=park_visits:out['stop']='bounded_native_park';machine.emu_stop();return
        if not any(a<=pc and pc+size<=b for a,b in ((0xFF9224,0xFF9252),(0xFF9518,0xFF954E+2),(0xFF959E,0xFF95EE),(0xFF960C,0xFF962C),(0xFF903C,0xFF9048))):
            raise RuntimeError(f'Escaped native tail at {pc:#x}+{size}')
        if bytes(machine.mem_read(pc,2))==b'\x4e\x70':out['reset_opcodes']+=1;raise RuntimeError('RESET instruction not permitted')
    def write_hook(machine,access,address,size,value,_):
        physical=address&0xFFFFFF
        if STACK-64<=physical and physical+size<=STACK:return
        if physical==0xFF8000 and size==2 and machine.reg_read(UC_M68K_REG_PC)==0xFF924A:
            out['marker_writes'].append(dict(address=address,declared_alias=physical,value=value,size=size,instruction=out['instructions']));return
        if size==1 and physical in (0xFF9A80,0xFF9A81,0xFF9A82):return
        raise RuntimeError(f'Untrapped store at {address:#x}+{size}')
    def read_hook(machine,access,address,size,value,_):
        physical=address&0xFFFFFF
        if physical>=0xFFF000 or 0xFFE800<=physical<0xFFE810:raise RuntimeError('Untrapped peripheral read')
    def invalid(*args):raise RuntimeError('Unmapped/protected memory access')
    u.hook_add(UC_HOOK_CODE,code_hook);u.hook_add(UC_HOOK_MEM_WRITE,write_hook);u.hook_add(UC_HOOK_MEM_READ,read_hook);u.hook_add(UC_HOOK_MEM_INVALID,invalid)
    u.emu_start(entries[entry],0xFF962C,timeout=15_000_000,count=1000000)
    if out['stop'] is None or pending_service:raise RuntimeError('Unclassified stop or incomplete service pair')
    out.update(marker=int.from_bytes(u.mem_read(0xFF8000,2),'big'),marker_alias=int.from_bytes(u.mem_read(0xFFFF8000,2),'big'),
        watchdog_service_digest=service_digest.hexdigest(),stack_delta=u.reg_read(UC_M68K_REG_A7)-STACK,
        service_pairs_after_park=0 if out['service_pairs_at_park'] is None else out['watchdog_pairs']-out['service_pairs_at_park'],
        loader_bytes_unchanged=bytes(u.mem_read(BASE,len(code)))==code)
    return dict(context=dict(entry=entry,busy_reads=busy_reads,park_visits=park_visits,initial_sr=0x2700,
                idle_counter_is_selected_last_iteration=entry=='idle_expiry'),observed=out,
        native_checksum_and_flash_marker_programming_executed=False,hardware_access=False,mmio_instructions_executed=0,
        physical_reset_verified=False,physical_timeout_verified=False,physical_fifo_ready_semantics_verified=False,
        final_status_wire_delivery_verified=False,host_readback_window_proven=False,live_upload_enabled=False,live_execution_enabled=False,live_write_enabled=False,ready_to_flash=False)


def analyze(code):
    cases=[dict(case=name,**experiment(code,**options)) for name,options in [
        ('success_ready',{}),('bad_sum_ready',dict(entry='bad_sum_tail')),
        ('success_delayed_ready',dict(busy_reads=5)),('permanent_sender_busy',dict(busy_reads=None)),
        ('last_successful_sender_poll',dict(busy_reads=4094)),('sender_countdown_exhausted',dict(busy_reads=4095)),
        ('shared_exit_no_status',dict(entry='shared_exit')),('idle_expiry_boundary',dict(entry='idle_expiry'))]]
    return dict(schema='al5-native-watchdog-tail-v1',loader_sha256=EXPECTED_SHA,
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),cases=cases,
        dependencies_sha256={'emulate_loader_parser.py':hashlib.sha256(Path(__file__).with_name('emulate_loader_parser.py').read_bytes()).hexdigest()},
        conditional_manual=dict(url='https://www.nxp.com/docs/en/user-guide/MC68336376UMD.pdf',sections=['D.2.12','D.2.15'],actual_mcu_identified=False),
        hardware_access=False,physical_reset_verified=False,physical_timeout_verified=False,host_readback_window_proven=False,
        live_upload_enabled=False,live_execution_enabled=False,live_write_enabled=False,ready_to_flash=False,
        limits=['Direct status/shared-exit or last-idle-iteration entries, not full receive, flash programming or final checksum execution.',
                'Real helper and delay instructions, with every peripheral instruction suppressed and MOVE flags explicitly modeled.',
                'Shared RAM aliases are a declared 24-bit model; native retained-marker storage is not a hardware reset.',
                'No watchdog peripheral, clock, elapsed-time model, actual exception or physical reset is supplied.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--loader',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('New output required')
    result=analyze(args.loader.read_bytes());result['input_reference']=dict(selected=str(args.loader),resolved=str(args.loader.resolve()))
    with args.output.open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2)
    print(json.dumps([(row['case'],row['observed']['stop'],row['observed']['watchdog_pairs']) for row in result['cases']]))
