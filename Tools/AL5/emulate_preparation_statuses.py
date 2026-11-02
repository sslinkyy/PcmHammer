"""Native preparation caller/wrappers with bounded host-only atomic NOR effects.

No flash implementation executes, no physical reset is delivered, no devices.
"""
import argparse
import hashlib
import json
from pathlib import Path
from emulate_calibration_marker import validate_source
from emulate_application_reset_chain import PreparationStorageBoundary
from emulate_storage_recovery import require_programmable

CASES=('success','erase_error_no_effect','copy_status_error','copy_readback_mismatch','program_status_error','program_readback_mismatch')

class StatusTrace(PreparationStorageBoundary):
    def __init__(self,low,high,case):
        if case not in CASES:raise ValueError('Named preparation scenario required')
        super().__init__(low,high)
        self.case=case;self.effects=[];self.copied_calls=[];self.error_park_iterations=0;self.injected=False;self.wrapper_frames=[]
        self.ranges.extend(((0x22C3C,0x22CF0),(0x22CF0,0x22DF0)))
        self.uc.mem_write(0x22C3C,self.data[0x22C3C:0x22F14])
        self.before={a:bytes(self.uc.mem_read(a,0x2000)) for a in (0x4000,0x6000)}
    def return_from_model(self,machine,sp,pc):
        from unicorn.m68k_const import UC_M68K_REG_A7,UC_M68K_REG_PC
        machine.reg_write(UC_M68K_REG_A7,sp+4);machine.reg_write(UC_M68K_REG_PC,pc)
    def hook(self,machine,pc,size,user_data):
        from unicorn.m68k_const import UC_M68K_REG_A7
        sp=machine.reg_read(UC_M68K_REG_A7)
        for frame in self.wrapper_frames:
            if not frame['returned'] and pc==frame['return_pc'] and sp==frame['entry_sp']+4:
                frame['returned']=True
        if pc in (0x22B18,0x22CF0,0x22C3C):
            self.wrapper_frames.append(dict(entry=pc,entry_sp=sp,return_pc=int.from_bytes(machine.mem_read(sp,4),'big'),returned=False))
        if pc==0x22B18:
            status=int.from_bytes(machine.mem_read(sp+4,4),'big');destination=int.from_bytes(machine.mem_read(sp+8,4),'big')
            if destination not in (0x4000,0x6000):raise ValueError('Erase model escaped persistent banks')
            error=self.case=='erase_error_no_effect'
            if not error:machine.mem_write(destination,b'\xff'*0x2000)
            machine.mem_write(status,(0x2000 if error else 0).to_bytes(2,'big'))
            self.effects.append(dict(kind='erase_status_without_effect' if error else 'atomic_erase_model',destination=destination,bytes=0 if error else 0x2000,status=0x2000 if error else 0))
            self.return_from_model(machine,sp,int.from_bytes(machine.mem_read(sp,4),'big'));return
        if pc in (0x22CF0,0x22C3C):
            if self.case=='erase_error_no_effect':
                self.observed['stop_pc']=hex(pc);machine.emu_stop()
            return
        if 0x200000<=pc<0x210000:
            caller=int.from_bytes(machine.mem_read(sp,4),'big')
            if caller not in (0x22D7C,0x22C8C) or bytes(machine.mem_read(pc,0x124))!=self.data[0x22DF0:0x22F14]:raise ValueError('Unexpected copied implementation/caller')
            status,source,destination,words=[int.from_bytes(machine.mem_read(sp+4+i*4,4),'big') for i in range(4)]
            count=words*2
            if count<=0 or not any(a<=destination and destination+count<=a+0x2000 for a in (0x4000,0x6000)):raise ValueError('Program model escaped persistent banks')
            kind='copy' if caller==0x22D7C else 'program'
            fault=not self.injected and self.case.startswith(kind+'_')
            payload=bytes(machine.mem_read(source,count))
            status_word=0x2000 if fault and self.case.endswith('status_error') else 0
            written=payload
            if fault:
                self.injected=True
                if self.case.endswith('readback_mismatch'):
                    damaged=bytearray(payload);damaged[0]^=1;written=bytes(damaged)
            require_programmable(bytes(machine.mem_read(destination,count)),written)
            machine.mem_write(destination,written)
            machine.mem_write(status,status_word.to_bytes(2,'big'))
            self.effects.append(dict(kind=('mismatching_' if fault and self.case.endswith('readback_mismatch') else 'atomic_')+kind+'_model',destination=destination,bytes=count,requested_bytes=count,status=status_word,payload_sha256=hashlib.sha256(payload).hexdigest(),written_sha256=hashlib.sha256(written).hexdigest()))
            self.copied_calls.append(dict(entry=pc,pending_return=caller,flash_implementation_executed=False))
            self.return_from_model(machine,sp,caller);return
        if pc in (0x22CC2,0x22DBC):
            self.error_park_iterations+=1
            if self.error_park_iterations==8:self.observed['stop_pc']=hex(pc);machine.emu_stop()
            return
        super().hook(machine,pc,size,user_data)
    def trace(self):
        observed,ram=self.application()
        observed.update(source_context_sha256=hashlib.sha256(bytes(self.uc.mem_read(0xFF8140,0x9F2))).hexdigest(),
                        bank_context_sha256={hex(a):hashlib.sha256(bytes(self.uc.mem_read(a+0x2A,0x9F2))).hexdigest() for a in self.before},
                        bank_markers={hex(a):bytes(self.uc.mem_read(a+0x28,2)).hex() for a in self.before},
                        case=self.case,effects=self.effects,copied_implementation_calls=self.copied_calls,
                        error_park_iterations=self.error_park_iterations,flash_implementation_executed=False,
                        physical_flash_effects_proven=False,physical_reset_proven=False,
                        remaining_pending_frames_reusable=False,wrapper_frames=self.wrapper_frames,
                        bank_differences={hex(a):sum(x!=y for x,y in zip(self.before[a],bytes(self.uc.mem_read(a,0x2000)))) for a in self.before})
        return observed

def analyze(low,high):
    validate_source(low,high)
    cases=[StatusTrace(low,high,name).trace() for name in CASES]
    return dict(schema='al5-offline-preparation-statuses-v1',cases=cases,
                low_sha256=hashlib.sha256(low).hexdigest(),high_sha256=hashlib.sha256(high).hexdigest(),
                generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256={n:hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in
                    ('emulate_application_reset_chain.py','emulate_receive_preparation.py','emulate_storage_recovery.py')},
                live_upload_enabled=False,live_execution_enabled=False,live_write_enabled=False,ready_to_flash=False,recovery_verified=False,would_send=[],
                limits=['Native application preparation and program/copy wrappers execute with synthetic request/subsystem state.',
                        'Flash implementations are intercepted before execution; successful effects are atomic host memory models only.',
                        'Erase-error case leaves bank bytes unchanged and stops at the next wrapper; no partial erase is inferred.',
                        'Status-error cases model correct payload bytes with an error status; mismatch cases model a changed payload with zero status.',
                        'No physical timing, partial-word/erase behavior, reset, RAM retention or recovery is qualified.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('low','high','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():p.error('New output required')
    r=analyze(a.low.read_bytes(),a.high.read_bytes())
    with a.output.open('x',encoding='utf-8') as f:json.dump(r,f,indent=2)
    for c in r['cases']:print(c['case'],c['stop_pc'],c['marker'],len(c['effects']),c['bank_differences'])
