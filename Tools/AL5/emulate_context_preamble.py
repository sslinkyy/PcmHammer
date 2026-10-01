"""Real context preamble with atomic host metadata writes; no flash execution."""
import argparse
import json
from pathlib import Path
from al5_segment import sha256
from emulate_startup_context import Startup
from emulate_storage_recovery import Update, begin
from emulate_storage_selection import BASE, CONTEXT_SIZE

RANGES = [(0x5B5E4, 0x5B8EC), (0x228D8, 0x22A00),
          (0xA9BF0, 0xA9C5A), (0xA9CB4, 0xA9D0C), (0xA9D4C, 0xA9D8C),
          (0x5BBDC, 0x5BBF0), (0x5BCA4, 0x5BCC0), (0x5BD78, 0x5BD8C)]
WARM_RANGES = [(0x79112,0x79124),(0x22B0C,0x22B16),(0xC5D50,0xC5E4A)]


class Preamble(Startup):
    def __init__(self, low, high, *, fill=0xA5):
        super().__init__(low, high, fill=fill)
        for a, b in RANGES: self.uc.mem_write(a, (low+high)[a:b])
        for a, b in WARM_RANGES: self.uc.mem_write(a, (low+high)[a:b])
        self.operations = []
        self.cut_after = None
        self.interrupted = False
        self.metadata_calls = []
        self.metadata_results = []
        self.pending_read = None
        self.warm_sequence = False

    def hook(self, machine, pc, size, user_data):
        from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_D0
        if (not self.preparing or self.warm_sequence) and pc in (0x22B18,0x22C3C,0x22CF0):
            Update.hook(self,machine,pc,size,user_data)  # host model only
        elif self.warm_sequence and pc == 0x226F0:
            pass  # execute update caller, with all storage primitives host-modeled
        elif pc == 0x228D8:
            sp = machine.reg_read(UC_M68K_REG_A7)
            self.pending_read = {'index':int.from_bytes(machine.mem_read(sp+4,4),'big'),
                                 'destination':hex(int.from_bytes(machine.mem_read(sp+8,4),'big'))}
            self.metadata_calls.append(dict(self.pending_read))
        elif pc == 0x22968:
            self.metadata_results.append({**self.pending_read,'return_d0':machine.reg_read(UC_M68K_REG_D0)})
        elif any(a <= pc < b for a,b in RANGES+WARM_RANGES):
            pass  # execute real helpers, overriding the former preamble stubs
        else:
            super().hook(machine,pc,size,user_data)

    def warm_reentry(self):
        before_ops=len(self.operations)
        before_defaults=len(self.root_helpers)
        self.warm_sequence=True
        self.preparing=True  # subsystem hooks remain explicitly bypassed
        self.stopped=None
        begin(self,0x79112)
        if self.stopped != '0x5baa6': raise RuntimeError('warm context caller escaped endpoint')
        context=bytes(self.uc.mem_read(BASE+0x140,CONTEXT_SIZE))
        return {'stop_pc':self.stopped,'modeled_storage_operations':self.operations[before_ops:],
                'additional_default_helpers':len(self.root_helpers)-before_defaults,
                'context_sha256':sha256(context),
                'main_bank2_committed':bytes(self.uc.mem_read(0x6028,2))==bytes.fromhex('ffaa'),
                'old_main_bank1_inactive':bytes(self.uc.mem_read(0x4028,2))==b'\x00\x00',
                'metadata_slots_rewritten_in_bank2':all(bytes(self.uc.mem_read(0x6000+0xA1C+slot*12,2))==bytes.fromhex('ffaa') for slot in (0,1,3)),
                'real_flash_implementation_executed':False}

    def read_record(self,index,marker):
        from unicorn.m68k_const import UC_M68K_REG_D0,UC_M68K_REG_PC
        address=0x4000+0xA1C+12*index
        payload=bytes((i*17+index)&255 for i in range(10))
        self.uc.mem_write(address,marker.to_bytes(2,'big')+payload)
        self.uc.mem_write(BASE+0xE64,b'\x00'*4)
        destination=BASE+0x1500
        self.uc.mem_write(destination,b'\x7e'*10)
        bank_before=sha256(bytes(self.uc.mem_read(0x4000,0x2000)))
        begin(self,0x228D8,index.to_bytes(4,'big')+destination.to_bytes(4,'big'))
        if self.uc.reg_read(UC_M68K_REG_PC)!=0x300000:raise RuntimeError('record reader escaped return')
        output=bytes(self.uc.mem_read(destination,10))
        return {'return_d0':self.uc.reg_read(UC_M68K_REG_D0),
                'copied_payload_matches':output==payload,
                'destination_unchanged':output==b'\x7e'*10,
                'bank_unchanged':sha256(bytes(self.uc.mem_read(0x4000,0x2000)))==bank_before}


def run_cases(low,high):
    records=[]
    for fill in (0xA5,0x5A):
        session=Preamble(low,high,fill=fill)
        initial={a:bytes(session.uc.mem_read(a,0x2000)) for a in (0x4000,0x6000)}
        cold=session.cold_context()
        metadata_ops=list(session.operations)
        reads=list(session.metadata_calls)
        results=list(session.metadata_results)
        after={a:bytes(session.uc.mem_read(a,0x2000)) for a in initial}
        changed={a:[i for i,(x,y) in enumerate(zip(initial[a],after[a])) if x!=y] for a in initial}
        allowed={i for slot in (0,1,3) for i in range(0xA1C+slot*12,0xA1C+(slot+1)*12)}
        passed=not session.preamble_bypassed and len(metadata_ops)==9
        passed &= [c['index'] for c in session.metadata_calls]==[0,1,3,2]
        passed &= [c['return_d0'] for c in session.metadata_results]==[1,1,1,1]
        passed &= set(changed[0x4000]) <= allowed and not changed[0x6000]
        passed &= len(changed[0x4000])>0 and cold['startup_clear']['region_all_zero']
        persistence=session.preparation_and_modeled_commit()
        passed &= persistence['prepared_context_crc_matches'] and persistence['modeled_committed_context_matches_prepared']
        # The main-context update copies from +0xA4C onward, after four slots.
        slots_erased=session.modeled_banks[0x6000][0xA1C:0xA4C]==b'\xff'*48
        passed &= slots_erased
        warm=session.warm_reentry()
        passed &= len(warm['modeled_storage_operations'])==16 and warm['additional_default_helpers']==0
        passed &= warm['main_bank2_committed'] and warm['old_main_bank1_inactive'] and warm['metadata_slots_rewritten_in_bank2']
        passed &= warm['context_sha256']==persistence['prepared_context_sha256']
        metadata={'read_calls':reads,'read_results':results,
                  'modeled_program_operations':metadata_ops,
                  'changed_bank1_offsets':[hex(i) for i in changed[0x4000]],
                  'changed_bank2_bytes':len(changed[0x6000]),
                  'only_expected_small_records_changed':set(changed[0x4000])<=allowed and not changed[0x6000],
                  'new_bank_slots_erased_after_separate_main_update':slots_erased}
        records.append({'synthetic_initial_fill':hex(fill),'cold_context':cold,
                        'metadata':metadata,'separate_preparation_and_modeled_commit':persistence,
                        'warm_reentry':warm,'pass':bool(passed)})
    same=records[0]['cold_context']['context_sha256']==records[1]['cold_context']['context_sha256']
    readers=[]
    for index in range(4):
        for marker,expected in ((0xFFFF,1),(0xFFAA,0),(0x0000,2)):
            observed=Preamble(low,high).read_record(index,marker)
            passed=observed['return_d0']==expected and observed['bank_unchanged']
            passed &= observed['copied_payload_matches'] if expected==0 else observed['destination_unchanged']
            readers.append({'index':index,'synthetic_record_marker':hex(marker),
                            'observed':observed,'pass':bool(passed)})
    return {'low_sha256':sha256(low),'high_sha256':sha256(high),
            'code_sha256':{hex(a):sha256((low+high)[a:b]) for a,b in RANGES+WARM_RANGES},
            'scope':'Four real preamble/metadata helpers and bounded warm invocation; all storage effects atomic host models. Read-only slot-marker cases also exercised. No flash implementation execution.',
            'model_limits':'Two pending cold cases and bounded warm path starting at 0x79112; earlier warm-path and startup calls, subsystem effects, other record states, partial programming and hardware omitted.',
            'cases':records,'record_reader_cases':readers,'cold_context_independent_of_fill':same,
            'all_pass':all(c['pass'] for c in records+readers) and same,
            'complete_startup_verified':False,'physical_recovery_verified':False,
            'flash_implementation_executed':False,'live_write_enabled':False,'ready_to_flash':False,'would_send':[]}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('low','high','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    report=run_cases(args.low.read_bytes(),args.high.read_bytes())
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'all_pass':report['all_pass'],'pipeline_cases':len(report['cases']),'reader_cases':len(report['record_reader_cases'])}))
    raise SystemExit(0 if report['all_pass'] else 1)
