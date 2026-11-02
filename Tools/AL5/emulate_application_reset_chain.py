"""Offline application preparation -> explicit reset hypothesis -> native boot.

Flash implementations and subsystem bodies never execute. No reset is inferred from the park loop.
"""
import argparse
import hashlib
import json
from pathlib import Path
from emulate_calibration_marker import validate_source
from emulate_receive_preparation import Preparation
from emulate_flash_fault_recovery import experiment

class ApplicationPark(Preparation):
    def __init__(self,low,high,*,allow_stubbed_storage_return=False,guard_flags=0):
        super().__init__(low,high,guard_flags=guard_flags)
        self.allow_stubbed_storage_return=allow_stubbed_storage_return
        self.park_iterations=0
        self.watchdog_at_park=None
    def hook(self,machine,pc,size,user_data):
        if pc==0xBE78C:
            self.park_iterations+=1
            if self.watchdog_at_park is None:self.watchdog_at_park=len(self.watchdog_writes)
            if self.park_iterations==8:
                self.observed['stop_pc']=hex(pc)
                machine.emu_stop()
            return
        super().hook(machine,pc,size,user_data)
        if pc==0x226F0 and not self.allow_stubbed_storage_return:
            self.observed['stop_pc']=hex(pc)
            machine.emu_stop()  # Before even the storage-return stub executes.
    def application(self):
        classified=self.classify()
        observed=self.descriptor()
        ram=bytes(self.uc.mem_read(0xFF8000,0x3800))
        observed.update(classified_state=classified['receive_state'],park_iterations=self.park_iterations,
                        watchdog_stores_during_park=0 if self.watchdog_at_park is None else len(self.watchdog_writes)-self.watchdog_at_park,
                        reset_observed=False,storage_return_assumed=self.allow_stubbed_storage_return,
                        ram_sha256=hashlib.sha256(ram).hexdigest(),ram_bytes=len(ram))
        return observed,ram

class PreparationStorageBoundary(ApplicationPark):
    """Execute the real update caller against historical banks, stop before primitives."""
    def __init__(self,low,high):
        super().__init__(low,high)
        from emulate_storage_selection import RANGES
        self.ranges.extend(RANGES)
        for start,end in RANGES:self.uc.mem_write(start,self.data[start:end])
        self.uc.mem_write(0x21422,self.data[0x21422:0x21426])
        self.uc.mem_write(0x4000,low[0x4000:0x8000])
        self.initial_banks_sha256=hashlib.sha256(low[0x4000:0x8000]).hexdigest()
        self.primitive_boundary=None
    def hook(self,machine,pc,size,user_data):
        if pc==0x226F0:
            self.storage_calls.append(dict(entry=hex(pc),caller_executed=True,return_is_stubbed=False,flash_implementation_executed=False))
            return
        if pc in (0x22B18,0x22C3C,0x22CF0):
            from unicorn.m68k_const import UC_M68K_REG_A7
            sp=machine.reg_read(UC_M68K_REG_A7)
            count=2 if pc==0x22B18 else 4
            args=[int.from_bytes(machine.mem_read(sp+4+4*i,4),'big') for i in range(count)]
            self.primitive_boundary=dict(entry=pc,arguments=args,implementation_executed=False)
            self.observed['stop_pc']=hex(pc);machine.emu_stop();return
        super().hook(machine,pc,size,user_data)
    def application(self):
        observed,ram=super().application()
        observed.update(primitive_boundary=self.primitive_boundary,bank_source='pinned_historical_LOW',
                        initial_banks_sha256=self.initial_banks_sha256,
                        banks_unchanged=hashlib.sha256(bytes(self.uc.mem_read(0x4000,0x4000))).hexdigest()==self.initial_banks_sha256)
        return observed,ram

class PreparationFailure(PreparationStorageBoundary):
    """Synthetic erase-status return followed by native copy-wrapper failure handling."""
    def __init__(self,low,high):
        super().__init__(low,high)
        self.ranges.append((0x22CF0,0x22DF0))
        self.uc.mem_write(0x22CF0,self.data[0x22CF0:0x22F14])
        self.injected_returns=[]
    def hook(self,machine,pc,size,user_data):
        from unicorn.m68k_const import UC_M68K_REG_A7,UC_M68K_REG_PC
        sp=machine.reg_read(UC_M68K_REG_A7)
        if pc==0x22B18:
            status=int.from_bytes(machine.mem_read(sp+4,4),'big')
            destination=int.from_bytes(machine.mem_read(sp+8,4),'big')
            machine.mem_write(status,bytes.fromhex('2000'))
            self.injected_returns.append(dict(helper=pc,kind='erase_status_only_no_erase',status_word=0x2000,destination=destination))
            machine.reg_write(UC_M68K_REG_PC,int.from_bytes(machine.mem_read(sp,4),'big'))
            machine.reg_write(UC_M68K_REG_A7,sp+4);return
        if pc==0x22CF0:return  # Native wrapper, not parent primitive trap.
        if 0x200000<=pc<0x210000:
            if int.from_bytes(machine.mem_read(sp,4),'big')!=0x22D7C or bytes(machine.mem_read(pc,0x124))!=self.data[0x22DF0:0x22F14]:
                raise ValueError('Unexpected copied flash implementation boundary')
            status=int.from_bytes(machine.mem_read(sp+4,4),'big')
            machine.mem_write(status,bytes.fromhex('2000'))
            self.injected_returns.append(dict(helper=pc,kind='copied_program_status_only_no_flash_execution',status_word=0x2000))
            machine.reg_write(UC_M68K_REG_PC,0x22D7C);machine.reg_write(UC_M68K_REG_A7,sp+4);return
        if pc==0x22DBC:
            self.observed['stop_pc']=hex(pc);machine.emu_stop();return
        super().hook(machine,pc,size,user_data)
    def application(self):
        observed,ram=super().application()
        observed.update(injected_returns=self.injected_returns,flash_implementation_executed=False,
                        flash_effects_modeled=False,storage_return_assumed=False)
        return observed,ram

def static_chain_evidence(low,high):
    validate_source(low,high)
    from capstone import Cs,CS_ARCH_M68K,CS_MODE_M68K_020,CS_MODE_BIG_ENDIAN
    data=low+high;decoder=Cs(CS_ARCH_M68K,CS_MODE_M68K_020|CS_MODE_BIG_ENDIAN)
    rows=[]
    for pc in (0x48E,0xBE78C):
        i=next(decoder.disasm(data[pc:pc+12],pc,count=1),None)
        if i is None:raise ValueError('Missing native reset/park instruction')
        rows.append(dict(pc=pc,mnemonic=i.mnemonic,operands=i.op_str,size=i.size,sha256=hashlib.sha256(data[pc:pc+i.size]).hexdigest()))
    if rows[0]['mnemonic']!='move.b' or rows[0]['operands']!='#$84, $fffffa21.l':raise ValueError('Pinned watchdog-control store changed')
    if rows[1]['mnemonic']!='bra.b' or rows[1]['operands']!='$be78c':raise ValueError('Pinned park is no longer a self branch')
    return dict(instructions=rows,conditional_sypcr=dict(address=0xFFFA21,value=0x84,watchdog_enable_bit=True,
                manual='https://www.nxp.com/docs/en/user-guide/MC68336376UMD.pdf',section='D.2.12',
                actual_mcu_identified=False,application_watchdog_configuration_proven=False,physical_timeout_proven=False))

def analyze(low,high):
    validate_source(low,high)
    strict,strict_ram=ApplicationPark(low,high).application()
    storage_boundary,_=PreparationStorageBoundary(low,high).application()
    failure,failure_ram=PreparationFailure(low,high).application()
    failure_reset=experiment(low,high,reset_status=0x20,retained_marker=int.from_bytes(failure_ram[:2],'big'),initial_ram=failure_ram)
    accepted,ram=ApplicationPark(low,high,allow_stubbed_storage_return=True).application()
    locked,_=ApplicationPark(low,high,allow_stubbed_storage_return=True,guard_flags=0x20).application()
    continuations=[]
    if accepted['stop_pc']!='0xbe78c' or int.from_bytes(ram[:2],'big')!=0xBFC1:
        raise ValueError('Conditional accepted application did not produce expected native marker')
    for status in (0,2,0x10,0x20,0x40,0x80,0xC0):
        boot=experiment(low,high,reset_status=status,retained_marker=int.from_bytes(ram[:2],'big'),initial_ram=ram)
        continuations.append(dict(reset_injected=True,ram_retention_assumed=True,
                                  source_ram_sha256=accepted['ram_sha256'],boot=boot))
    dependencies=('emulate_flash_fault_recovery.py','emulate_receive_preparation.py',
                  'emulate_application_authorization.py','emulate_application_boot.py','emulate_storage_selection.py')
    return dict(schema='al5-offline-application-reset-chain-v1',static=static_chain_evidence(low,high),strict_application=strict,preparation_storage_boundary=storage_boundary,
                preparation_failure=failure,conditional_failure_reset=dict(reset_injected=True,ram_retention_assumed=True,boot=failure_reset),
                conditional_application=accepted,locked_application=locked,conditional_resets=continuations,
                low_sha256=hashlib.sha256(low).hexdigest(),high_sha256=hashlib.sha256(high).hexdigest(),
                generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256={n:hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in dependencies},
                entry_physically_proven=False,reset_physically_proven=False,storage_preservation_proven=False,
                ready_to_flash=False,live_upload_enabled=False,live_execution_enabled=False,live_write_enabled=False,would_send=[],
                limits=['Application classifier/callback begins with synthetic request and guard values; not full receive routing.',
                        'Failure case injects error statuses without erase/program effects and traps the copied implementation before execution.',
                        'Subsystems are explicit stubs. Strict case stops before persistent storage; conditional case assumes its return.',
                        'Eight native park-loop iterations contain no modeled watchdog service or CPU reset instruction.',
                        'Reset is explicitly injected in a separate CPU instance, carrying the exact application RAM bytes, not elapsed watchdog time.',
                        'Retained RAM, reset cause, peripheral values, synthetic ISR and physical bus behavior remain unqualified.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('low','high','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():p.error('New output required')
    r=analyze(a.low.read_bytes(),a.high.read_bytes())
    with a.output.open('x',encoding='utf-8') as f:json.dump(r,f,indent=2)
    print('strict:',r['strict_application']['stop_pc'],'conditional:',r['conditional_application']['stop_pc'])
    for c in r['conditional_resets']:
        b=c['boot'];print(hex(b['reset_status']),b['stop'],hex(b['reset_marker']),b['software_tx_frames'])
