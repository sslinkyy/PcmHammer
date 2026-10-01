"""Bounded saved small-record caller with atomic host writes/failures; no hardware."""
import argparse
import json
from pathlib import Path
from al5_segment import sha256
from emulate_context_preamble import Preamble, RANGES
from emulate_storage_recovery import begin, require_programmable
from emulate_storage_selection import BASE, RETURN


class RecordWrite(Preamble):
    def __init__(self, low, high, *, cut_after=None, fail_at=None):
        super().__init__(low, high)
        self.cut_after=cut_after
        self.fail_at=fail_at
        self.attempts=[]

    def hook(self, machine, pc, size, user_data):
        from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_PC
        if pc==0x22C3C:
            sp=machine.reg_read(UC_M68K_REG_A7)
            status,source,destination,words=[int.from_bytes(machine.mem_read(sp+4+i*4,4),'big') for i in range(4)]
            length=2*(words&0xFFFF)
            if not 0x4A1C<=destination<destination+length<=0x4A4C:
                raise RuntimeError('write escaped synthetic small records')
            payload=bytes(machine.mem_read(source,length))
            failed=len(self.attempts)+1==self.fail_at
            if not failed:
                require_programmable(bytes(machine.mem_read(destination,length)),payload)
                machine.mem_write(destination,payload)
            machine.mem_write(status,(0x20 if failed else 0).to_bytes(2,'big'))
            self.attempts.append({'destination':hex(destination),'bytes':length,
                                  'payload_sha256':sha256(payload),
                                  'word':payload.hex() if length==2 else None,
                                  'synthetic_status':hex(0x20 if failed else 0),
                                  'host_mutation_applied':not failed,
                                  'implementation_executed':False})
            if self.cut_after==len(self.attempts):
                self.interrupted=True
                machine.emu_stop()
            else:
                machine.reg_write(UC_M68K_REG_PC,int.from_bytes(machine.mem_read(sp,4),'big'))
                machine.reg_write(UC_M68K_REG_A7,sp+4)
        elif pc in (0x22B18,0x22CF0):
            raise RuntimeError('unexpected erase/copy in bounded small-record writer')
        else:
            super().hook(machine,pc,size,user_data)

    def exercise(self,index):
        from unicorn.m68k_const import UC_M68K_REG_PC, UC_M68K_REG_D0
        address=0x4A1C+12*index
        payload=bytes((i*17+index)&255 for i in range(10))
        source,destination=BASE+0x1500,BASE+0x1600
        self.uc.mem_write(BASE+0xE64,b'\x00'*4)
        self.uc.mem_write(source,payload)
        before={a:bytes(self.uc.mem_read(a,0x2000)) for a in (0x4000,0x6000)}
        if self.cut_after==0:self.interrupted=True
        else:
            begin(self,0x2296C,index.to_bytes(4,'big')+source.to_bytes(4,'big'))
            if not self.interrupted and self.uc.reg_read(UC_M68K_REG_PC)!=RETURN:
                raise RuntimeError('writer did not reach bounded return')
        returned=not self.interrupted
        self.uc.mem_write(BASE+0xE64,b'\x00'*4)  # reselect saved parent after boundary
        self.uc.mem_write(destination,b'\x7e'*10)
        self.cut_after=None
        begin(self,0x228D8,index.to_bytes(4,'big')+destination.to_bytes(4,'big'))
        if self.uc.reg_read(UC_M68K_REG_PC)!=RETURN:raise RuntimeError('reader escaped return')
        after={a:bytes(self.uc.mem_read(a,0x2000)) for a in before}
        changed=[i for i,(a,b) in enumerate(zip(before[0x4000],after[0x4000])) if a!=b]
        output=bytes(self.uc.mem_read(destination,10))
        return {'writer_returned':returned,'attempts':self.attempts,
                'slot_marker':hex(int.from_bytes(self.uc.mem_read(address,2),'big')),
                'reader_return_d0':self.uc.reg_read(UC_M68K_REG_D0),
                'reader_payload_matches_requested':output==payload,
                'reader_destination_unchanged':output==b'\x7e'*10,
                'reader_copied_erased_payload':output==b'\xff'*10,
                'only_target_slot_changed':all(address-0x4000<=i<address-0x4000+12 for i in changed) and before[0x6000]==after[0x6000]}


def run_cases(low,high):
    cases=[]
    for index in range(4):
        for cut in range(4):
            observed=RecordWrite(low,high,cut_after=cut).exercise(index)
            marker=(0xFFFF,0xFFFE,0xFFFE,0xFFAA)[cut]
            passed=observed['slot_marker']==hex(marker) and len(observed['attempts'])==cut
            passed &= observed['reader_return_d0']==(0 if cut==3 else 1 if cut==0 else 2)
            passed &= observed['reader_payload_matches_requested']==(cut==3)
            passed &= observed['reader_destination_unchanged']==(cut!=3) and observed['only_target_slot_changed']
            cases.append({'index':index,'interrupt_after_operations':cut,'fail_at':None,'observed':observed,'pass':bool(passed)})
        for failure in range(1,4):
            observed=RecordWrite(low,high,fail_at=failure).exercise(index)
            passed=observed['writer_returned'] and len(observed['attempts'])==3 and observed['only_target_slot_changed']
            passed &= observed['slot_marker']==hex(0xFFFE if failure==3 else 0xFFAA)
            passed &= observed['reader_return_d0']==(2 if failure==3 else 0)
            passed &= observed['reader_payload_matches_requested']==(failure==1)
            passed &= observed['reader_copied_erased_payload']==(failure==2)
            cases.append({'index':index,'interrupt_after_operations':None,'fail_at':failure,'observed':observed,'pass':bool(passed)})
    return {'low_sha256':sha256(low),'high_sha256':sha256(high),
            'code_sha256':{hex(a):sha256((low+high)[a:b]) for a,b in RANGES},
            'scope':'Real small-record writer/reader with pending parent, erased slots, atomic host writes and no-write failure status 0x20.',
            'model_limits':'Operation-boundary stops; no partial words, physical status behavior, full initializer reaction, reset execution or transport. Failure status semantics are synthetic.',
            'cases':cases,'all_pass':all(c['pass'] for c in cases),
            'synthetic_payload_failure_can_leave_committed_erased_payload':all(c['observed']['reader_copied_erased_payload'] for c in cases if c['fail_at']==2),
            'physical_recovery_verified':False,'flash_implementation_executed':False,
            'ready_to_flash':False,'live_write_enabled':False,'would_send':[]}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('low','high','output'):p.add_argument('--'+name,type=Path,required=True)
    args=p.parse_args()
    report=run_cases(args.low.read_bytes(),args.high.read_bytes())
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'all_pass':report['all_pass'],'cases':len(report['cases'])}))
    raise SystemExit(0 if report['all_pass'] else 1)
