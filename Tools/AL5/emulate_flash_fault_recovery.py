"""Offline flash address/data fault hypotheses. No electrical pin operation or live transport."""
import argparse,ctypes,hashlib,json
from pathlib import Path
from emulate_calibration_marker import validate_source
from emulate_boot_receive_session import frame_events
from emulate_readonly_native_controls import SPS_SHA

class OfflineBootContext:
    """Retained emulator state only. One native-copy attempt; no transport API."""
    def __init__(self,cpu,report,copy_reader,attach_runtime):
        self.cpu=cpu;self.report=report;self._copy_reader=copy_reader;self._attach_runtime=attach_runtime;self.closed=False
    def copy_readonly_runtime(self,code,receipt,*,execute=True,bad_checksum=False):
        if self.closed:raise ValueError('Offline copy attempt is terminal; create a fresh boot context')
        if type(execute) is not bool or type(bad_checksum) is not bool:raise ValueError('Explicit offline transfer flags required')
        self.closed=True
        return self._copy_reader(code,receipt,execute,bad_checksum)
    def attach_runtime(self,runtime):
        return self._attach_runtime(runtime)

SIZE=0x100000
FAULTS=('a12_direct','cpu_a12_alternative','dq13_word')

def integrity_oracle(data):
    """Independent inclusive BE16 sums for the pinned reset checksum ranges."""
    if len(data)!=SIZE:raise ValueError('Exact flash image required')
    start=int.from_bytes(data[0x20400:0x20404],'big')
    end=int.from_bytes(data[0x20404:0x20408],'big')
    if start!=0x20000 or end!=0xC5F92:raise ValueError('Pinned OS checksum range changed')
    return {name:sum(int.from_bytes(data[a:a+2],'big') for a in range(first,last+2,2))&0xFFFF
            for name,first,last in (('boot',0,0x3F06),('os',start,end))}

def fault_bytes(data,kind):
    if len(data)!=SIZE or kind not in FAULTS:raise ValueError('Exact flash image and named mapping hypothesis required')
    if kind=='dq13_word':return bytes(v&0xDF if i%2==0 else v for i,v in enumerate(data))
    mask=0x2000 if kind=='a12_direct' else 0x1000
    return bytes(data[i&~mask] for i in range(SIZE))

def experiment(low,high,kind='a12_direct',window='none',instruction_limit=1000000,probe_boot_request=True,external_service_magic=0,reset_status=0x80,retained_marker=0,initial_ram=None,retain_context=False,initial_persistent_banks=None):
    validate_source(low,high)
    if kind not in FAULTS or window not in ('none','held','release_at_os_reject','os_check_to_reject','os_check_to_vpw'):
        raise ValueError('Unknown bounded fault hypothesis/window')
    if type(external_service_magic) is not int or not 0<=external_service_magic<=65535 or type(probe_boot_request) is not bool:
        raise ValueError('Invalid synthetic external service/IRQ context')
    if initial_persistent_banks is not None and (not isinstance(initial_persistent_banks,bytes) or len(initial_persistent_banks)!=0x4000):
        raise ValueError('Explicit modeled persistent banks must cover exactly 4000..7FFF')
    if type(retain_context) is not bool:raise ValueError('Explicit emulator-context option required')
    if type(reset_status) is not int or not 0<=reset_status<=255:
        raise ValueError('Synthetic reset status must be a byte')
    if type(retained_marker) is not int or not 0<=retained_marker<=65535:
        raise ValueError('Synthetic retained marker must be a word')
    if initial_ram is not None and (not isinstance(initial_ram,bytes) or len(initial_ram)!=0x3800 or int.from_bytes(initial_ram[:2],'big')!=retained_marker):
        raise ValueError('Explicit RAM handoff requires exactly FF8000..FFB7FF and matching marker')
    if type(instruction_limit) is not int or not 1<=instruction_limit<=1000000:
        raise ValueError('Instruction limit must be 1..1000000')
    from unicorn import Uc,UC_ARCH_M68K,UC_MODE_BIG_ENDIAN,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_PROT_READ,UC_PROT_EXEC,UC_PROT_ALL,UcError
    from unicorn.m68k_const import UC_CPU_M68K_M68020,UC_M68K_REG_A7,UC_M68K_REG_SR,UC_M68K_REG_PC,UC_M68K_REG_D4
    from capstone import Cs,CS_ARCH_M68K,CS_MODE_M68K_020,CS_MODE_BIG_ENDIAN
    decoder=Cs(CS_ARCH_M68K,CS_MODE_M68K_020|CS_MODE_BIG_ENDIAN);fetch_sizes={}
    data=low+high if initial_persistent_banks is None else low[:0x4000]+initial_persistent_banks+low[0x8000:]+high
    bad=fault_bytes(data,kind)
    active=window in ('held','release_at_os_reject');view=bad if active else data
    sp=int.from_bytes(view[:4],'big');pc=int.from_bytes(view[4:8],'big')
    out=dict(fault=kind,window=window,reset_sp=sp,reset_pc=pc,stop=None,instructions=0,events=[],
             aliased_reads=0,changed_data_reads=0,first_changed_fetch=None,register_writes=[],watchdog_stores=0,
             vpw_initializer_entered=False,flash_writes_blocked=0,physical_mapping_verified=False,
             live_upload_enabled=False,live_execution_enabled=False,live_write_enabled=False,recovery_verified=False,
             external_service_magic=external_service_magic,reset_status=reset_status,synthetic_irq_invoked=False,exception_return_executed=False,
             software_tx_frames=[],software_tx_observations=[],fifo_events_consumed=0,integrity_observations=[],
             initial_persistent_banks_sha256=None if initial_persistent_banks is None else hashlib.sha256(initial_persistent_banks).hexdigest(),
             flash_fixture_sha256=hashlib.sha256(data).hexdigest(),retained_marker=retained_marker,initial_ram_sha256=None if initial_ram is None else hashlib.sha256(initial_ram).hexdigest(),reset_status_accesses=[],marker_accesses=[],routing_observations=[])
    if not 0xFF8000<=(sp&0xFFFFFF)<0x1000000 or not 0<=pc<0x4000 or pc%2:
        out['stop']='faulted_reset_vector_outside_declared_context';return out
    u=Uc(UC_ARCH_M68K,UC_MODE_BIG_ENDIAN);u.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    u.mem_map(0,SIZE);u.mem_write(0,view);u.mem_protect(0,SIZE,UC_PROT_READ|UC_PROT_EXEC)
    # Explicit 24-bit decode hypothesis for signed absolute-short RAM/module
    # aliases. Shared backing is a model input, not board continuity evidence.
    backing=ctypes.create_string_buffer(0x8000);ptr=ctypes.addressof(backing)
    u._alias_backing=backing
    u.mem_map_ptr(0xFF8000,0x8000,UC_PROT_ALL,ptr);u.mem_map_ptr(0xFFFF8000,0x8000,UC_PROT_ALL,ptr)
    stack_alias=sp&~0x7FFF
    if stack_alias not in (0xFF8000,0xFFFF8000):
        u.mem_map_ptr(stack_alias,0x8000,UC_PROT_ALL,ptr)
    out['modeled_stack_alias']=stack_alias
    u.mem_map(0x208000,0x1000);u.mem_write(0x208000,external_service_magic.to_bytes(2,'big'))
    u.mem_map(0x20C000,0x1000)  # Explicit inert external-service control byte.
    if initial_ram is not None:u.mem_write(0xFF8000,initial_ram)
    u.mem_write(0xFF8000,retained_marker.to_bytes(2,'big'))
    u.mem_write(0xFFFA07,bytes([reset_status]))  # Synthetic reset/status input; not measured hardware state.
    u.reg_write(UC_M68K_REG_SR,0x2700);u.reg_write(UC_M68K_REG_A7,sp)
    switch=None;irq_phase=False;fifo=[];tx_command=None;tx=[];reader=None;runtime=None;copied=set();handoff=None
    class Guard(Exception):pass

    def code(machine,a,n,_):
        nonlocal switch,handoff
        if runtime is not None:
            runtime.instruction(machine,a,n,_);return
        if reader is not None and a==reader['base']:
            incoming_sp=machine.reg_read(UC_M68K_REG_A7)
            if bytes(machine.mem_read(a,len(reader['code'])))!=reader['code'] or len(copied)!=len(reader['code']):raise Guard('incomplete_native_reader_copy')
            if incoming_sp!=reader['prior_sp']-72 or int.from_bytes(machine.mem_read(incoming_sp,4),'big')!=0x33B8:raise Guard('unqualified_native_reader_stack_boundary')
            if any(event!=(0,0) for event in fifo):raise Guard('pending_native_fifo_at_reader_entry')
            handoff=dict(incoming_sp=incoming_sp,incoming_physical_sp=incoming_sp&0xFFFFFF,pending_return=0x33B8,stack_delta=-72,
                         native_copied_bytes=len(copied),code_preloaded=False,scripted_fifo_remaining=[list(event) for event in fifo],
                         abandoned_frame_sha256=hashlib.sha256(bytes(machine.mem_read(incoming_sp,72))).hexdigest())
            out['stop']='before_offline_runtime_entry';machine.emu_stop();return
        out['instructions']+=1
        if out['instructions']>instruction_limit:out['stop']='instruction_resource_budget';machine.emu_stop();return
        if not active and window.startswith('os_check_') and a==0x806:
            switch=True;machine.emu_stop();return
        release=(window in ('release_at_os_reject','os_check_to_reject') and a==0x890 or window=='os_check_to_vpw' and a==0x3B7C)
        if active and release:switch=False;machine.emu_stop();return
        if a>=0x20000 and a<SIZE:
            out['stop']='application_transfer_boundary';machine.emu_stop();return
        if not 0<=a<0x4000:out['stop']='execution_outside_boot_context';machine.emu_stop();return
        if active:
            if a not in fetch_sizes:
                original=next(decoder.disasm(data[a:a+24],a,count=1),None)
                altered=next(decoder.disasm(bad[a:a+24],a,count=1),None)
                fetch_sizes[a]=max(n,original.size if original else 2,altered.size if altered else 2)
            length=fetch_sizes[a]
            if bad[a:a+length]!=data[a:a+length]:
                out['first_changed_fetch']=dict(pc=a,bytes=length,original_sha256=hashlib.sha256(data[a:a+length]).hexdigest(),faulted_sha256=hashlib.sha256(bad[a:a+length]).hexdigest())
                out['stop']='instruction_fetch_changed_by_fault';machine.emu_stop();return
        if a in (0x7E0,0x86E):out['integrity_observations'].append(dict(pc=a,d4=machine.reg_read(UC_M68K_REG_D4),fault_active=active))
        if a in (0x7EA,0x7F2,0x7FA,0x806,0x874,0x890,0x8B2,0x962,0x96E,0x97C):
            out['routing_observations'].append(dict(pc=a,marker=int.from_bytes(machine.mem_read(0xFF8000,2),'big')))
        if a==0x3B7C:out['vpw_initializer_entered']=True
        if a==0xE80:
            out['idle_interrupt_mask']=(machine.reg_read(UC_M68K_REG_SR)>>8)&7
            out['stop']='native_idle_boundary';machine.emu_stop();return
        if irq_phase and a==0x3B78:out['stop']='before_synthetic_irq_rte';machine.emu_stop();return
        if a==0x96E:out['stop']='native_boot_failure_wait';machine.emu_stop();return

    def read(machine,access,a,n,value,_):
        if runtime is not None:
            runtime.read(machine,access,a,n,value,_);return
        if a<SIZE:
            if active and data[a:a+n]!=bad[a:a+n]:out['changed_data_reads']+=1
            if active and kind!='dq13_word' and any((i&(0x2000 if kind=='a12_direct' else 0x1000)) for i in range(a,a+n)):out['aliased_reads']+=1
            return
        if a==0x208000 and n==2:return
        if a==0x20C000 and n==1:return
        physical=a&0xFFFFFF
        if not (0xFF8000<=physical and physical+n<=0x1000000):raise Guard('unmapped_data_read')
        if physical<=0xFFFA07<physical+n:
            out['reset_status_accesses'].append(dict(operation='read',pc=machine.reg_read(UC_M68K_REG_PC),address=a,size=n,value=machine.mem_read(0xFFFA07,1)[0]))
        if physical==0xFF8000 and n==2:
            out['marker_accesses'].append(dict(operation='read',pc=machine.reg_read(UC_M68K_REG_PC),value=int.from_bytes(machine.mem_read(a,n),'big')))
        if physical==0xFFFC1F and machine.reg_read(UC_M68K_REG_PC)==0xCA8:machine.mem_write(a,b'\x80')
        if physical==0xFFFD02 and n==2:machine.mem_write(a,b'\0\0')
        if physical==0xFFE800 and n==1:machine.mem_write(a,bytes([fifo[0][0] if fifo else 0]))
        if physical==0xFFE801 and n==1:
            if not fifo:raise Guard('data_read_without_scripted_fifo_event')
            _,byte=fifo.pop(0);out['fifo_events_consumed']+=1;machine.mem_write(a,bytes([byte]))

    def write(machine,access,a,n,value,_):
        nonlocal tx_command,tx
        if runtime is not None:
            runtime.write(machine,access,a,n,value,_);return
        if a<SIZE:
            out['flash_writes_blocked']+=1;raise Guard('flash_write_blocked')
        if a==0x20C000 and n==1 and value in (0,1):return
        physical=a&0xFFFFFF
        if not (0xFF8000<=physical and physical+n<=0x1000000):raise Guard('unowned_data_write')
        if physical<=0xFFFA07<physical+n:
            raise Guard('reset_status_write_outside_readonly_model')
        if physical==0xFF8000 and len(out['marker_accesses'])<128:
            out['marker_accesses'].append(dict(operation='write',pc=machine.reg_read(UC_M68K_REG_PC),size=n,value=value))
        if reader is not None and reader['base']<=physical and physical+n<=reader['base']+len(reader['code']):
            if n!=1:raise Guard('unexpected_native_reader_copy_width')
            copied.add(physical-reader['base'])
        if physical in (0xFFFA26,0xFFFA27):out['watchdog_stores']+=1
        elif physical>=0xFFE000 and len(out['register_writes'])<256:
            out['register_writes'].append(dict(pc=machine.reg_read(UC_M68K_REG_PC),address=a,physical_under_hypothesis=physical,size=n,value=value))
        if physical==0xFFE800 and n==1:tx_command=value
        if physical==0xFFE801 and n==1:
            if tx_command==0x14:tx=[value]
            elif tx_command==4 and tx:tx.append(value)
            elif tx_command==0x0C and tx:
                tx.append(value);frame=bytes(tx).hex();out['software_tx_frames'].append(frame)
                out['software_tx_observations'].append(dict(frame=frame,phase='synthetic_irq' if irq_phase else 'native_startup',pc=machine.reg_read(UC_M68K_REG_PC)))
                tx=[]
            tx_command=None

    u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_READ,read);u.hook_add(UC_HOOK_MEM_WRITE,write)
    while out['stop'] is None:
        switch=None
        try:u.emu_start(pc,0,count=instruction_limit)
        except (UcError,Guard) as error:
            out['stop']='emulator_or_ownership_boundary';out['error']=str(error);break
        pc=u.reg_read(UC_M68K_REG_PC)
        if switch is not None:
            active=switch;u.mem_write(0,bad if active else data);u.ctl_remove_cache(0,SIZE)
            out['events'].append(dict(pc=pc,fault_active=active));continue
        if out['stop']=='native_idle_boundary' and probe_boot_request and not active and out['vpw_initializer_entered']:
            # Explicit synthetic interrupt entry, not actual IRQ delivery. The
            # original ISR/parser/sender run in this same reset/RAM session;
            # stop before RTE instead of inventing a CPU exception frame.
            irq_phase=True;out['synthetic_irq_invoked']=True;out['stop']=None
            fifo=list(frame_events(bytes.fromhex('6d18f034')));pc=0x39AC
            u.reg_write(UC_M68K_REG_SR,0x2700);continue
        if out['stop'] is None:out['stop']='instruction_resource_budget'
    def snapshot():
        out.update(final_pc=u.reg_read(UC_M68K_REG_PC),fault_active_at_stop=active,
                   reset_status_snapshot=int.from_bytes(u.mem_read(0xFF8008,2),'big'),
                   reset_marker=int.from_bytes(u.mem_read(0xFF8000,2),'big'),interface_flag=u.mem_read(0xFF8010,1)[0],
                   interrupt_mask=(u.reg_read(UC_M68K_REG_SR)>>8)&7,
                   upload_armed_byte=u.mem_read(0xFF8185,1)[0],
                   rom_unchanged_from_selected_view=bytes(u.mem_read(0,SIZE))==(bad if active else data))
        out['final_sp']=u.reg_read(UC_M68K_REG_A7)
        if reader is not None:out['offline_reader_handoff']=handoff;out['offline_reader_copied_bytes']=len(copied)
        return out

    def copy_reader(code_bytes,receipt,execute,bad_checksum):
        nonlocal reader,fifo,irq_phase
        from readonly_ram_layout import audit
        if out['stop'] not in ('native_idle_boundary','before_synthetic_irq_rte') or active or not out['vpw_initializer_entered'] or runtime is not None:
            raise ValueError('No qualified offline native boot boundary for one transfer')
        if not isinstance(code_bytes,bytes) or receipt.get('text_base')!=0xFF9006 or receipt.get('entry')!=0xFF9006 or hashlib.sha256(code_bytes).hexdigest()!=receipt.get('code_sha256'):
            raise ValueError('Explicit matching compiled reader required')
        audit(len(code_bytes))
        if any(event!=(0,0) for event in fifo) or tx or tx_command is not None:raise ValueError('Pending boot FIFO/transmit ownership')
        if bytes(u.mem_read(0xFF9006,len(code_bytes)))==code_bytes:raise ValueError('Reader must not be preloaded')
        reader=dict(base=0xFF9006,code=code_bytes,prior_sp=u.reg_read(UC_M68K_REG_A7))
        tail=bytes([0x80 if execute else 0])+len(code_bytes).to_bytes(2,'big')+(0xFF9006).to_bytes(3,'big')+code_bytes
        checksum=((sum(tail)+int(bad_checksum))&65535).to_bytes(2,'big')
        fifo=[(0x20,b) for b in bytes.fromhex('6d18f036')+tail+checksum]+[(0xA0,0),(0,0)]
        irq_phase=True;out['stop']=None;u.reg_write(UC_M68K_REG_SR,0x2700)
        try:u.emu_start(0x39AC,0,count=instruction_limit)
        except (UcError,Guard) as error:out['stop']='emulator_or_ownership_boundary';out['error']=str(error)
        if out['stop'] is None:out['stop']='instruction_resource_budget'
        return snapshot()

    def attach_runtime(selected):
        nonlocal runtime
        from emulate_readonly_runtime import Runtime
        if runtime is not None or not isinstance(selected,Runtime) or selected.u is not u or out['stop']!='before_offline_runtime_entry' or handoff is None:
            raise ValueError('Runtime must adopt this exact paused native-copy CPU')
        if selected.base!=reader['base'] or selected.end!=reader['base']+len(reader['code']):raise ValueError('Runtime layout changed after native copy')
        runtime=selected
        return handoff

    snapshot()
    return OfflineBootContext(u,out,copy_reader,attach_runtime) if retain_context else out

def mapping_evidence(loader):
    if len(loader)!=3858 or hashlib.sha256(loader).hexdigest()!=SPS_SHA:raise ValueError('Pinned SPS loader required for mapping observations')
    from capstone import Cs,CS_ARCH_M68K,CS_MODE_M68K_020,CS_MODE_BIG_ENDIAN
    d=Cs(CS_ARCH_M68K,CS_MODE_M68K_020|CS_MODE_BIG_ENDIAN)
    observations=[]
    for pc,expected in ((0xFF9BEA,'#$aaa, a5'),(0xFF9BF4,'#$554, a5')):
        instruction=next(d.disasm(loader[pc-0xFF9006:pc-0xFF9006+8],pc,count=1))
        if instruction.mnemonic!='movea.w' or instruction.op_str!=expected:raise ValueError('Mapping instruction identity changed')
        observations.append(dict(pc=pc,instruction=instruction.mnemonic+' '+instruction.op_str))
    return dict(sps_loader_sha256=SPS_SHA,word_command_observations=observations,
                cpu_byte_unlock_addresses=[0xAAA,0x554],datasheet_word_unlock_addresses=[0x555,0x2AA],
                low_address_shift_consistent=True,high_address_a12_continuity_verified=False,
                datasheet_url='https://www.batronix.com/files/Datenblaetter/29__/AM29F800B.pdf',
                datasheet='AMD/Spansion 21504E5, connection diagrams and word/byte command table',
                limits='Low command address shift supports a contiguous byte/word mapping; it does not prove physical A12 routing or package fitment.')

def analyze(low,high,loader):
    validate_source(low,high);data=low+high;cases=[]
    cases.append(experiment(low,high,'a12_direct','none'))
    for kind in FAULTS:
        for window in (('held','release_at_os_reject','os_check_to_reject','os_check_to_vpw') if kind=='a12_direct' else ('held','os_check_to_reject')):
            cases.append(experiment(low,high,kind,window))
    cases.append(experiment(low,high,'a12_direct','os_check_to_reject',external_service_magic=0x5AA5))
    reset_status_cases=[experiment(low,high,'a12_direct',window,reset_status=status)
                        for status in (0,0x40,0x80,0xC0)
                        for window in ('none','os_check_to_reject')]
    view=fault_bytes(data,'a12_direct')
    return dict(schema='al5-offline-flash-fault-recovery-v1',low_sha256=hashlib.sha256(low).hexdigest(),high_sha256=hashlib.sha256(high).hexdigest(),
                generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),cases=cases,reset_status_cases=reset_status_cases,
                mapping=mapping_evidence(loader),integrity_oracle={
                    'normal':integrity_oracle(data),'a12_direct':integrity_oracle(view)},
                source_classification='historical saved firmware, not current physical flash backup',
                a12_candidate=dict(physical_pin_44so=38,cpu_byte_mask=0x2000,mapping_verified=False,
                    marker_original=data[0x1FFFE:0x20000].hex(),marker_aliased=view[0x1FFFE:0x20000].hex(),
                    vpw_initializer_bytes_changed=view[0x3B7C:0x3B80]!=data[0x3B7C:0x3B80]),
                pin27_candidate=dict(signal_44so='DQ13',fault_kind='dq13_word',physical_word_lane_verified=False),
                live_operations_enabled=False,recovery_verified=False,ready_to_flash=False,would_send=[],
                limits=['Fault windows are software-PC hypotheses, not electrical timings or hardware instructions.',
                        'Both instruction fetch and data see the faulted ROM; changed fetches stop before unowned instruction semantics.',
                        'Shared 24-bit RAM/module aliases and reset/serial-ready/status values are explicit model assumptions.',
                        'External-service magic is an input; synthetic IRQ starts the native ISR without executing RTE or an actual exception frame.',
                        'Native idle/initializer reachability alone does not establish VPW communication or recoverability.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('low','high','loader','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():p.error('New output required')
    r=analyze(a.low.read_bytes(),a.high.read_bytes(),a.loader.read_bytes())
    with a.output.open('x') as f:json.dump(r,f,indent=2)
    for c in r['cases']:print(c['fault'],c['window'],c['stop'],hex(c.get('final_pc',c['reset_pc'])))
