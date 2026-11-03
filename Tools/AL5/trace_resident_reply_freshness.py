"""Join resident Mode 23 dispatch, selected scheduler submission and native status/event paths offline.

Numeric MMIO status/data bytes are scripted inputs, never asserted physical
success/error meanings. No controller, USB/serial transport or live operation.
"""
import argparse
import hashlib
import json
from pathlib import Path
from trace_preentry_banks import PreEntryBanks
from emulate_application_boot import BASE, STACK, RETURN

RANGES=((0x23428,0x23692),(0x2377C,0x23798),(0xB6230,0xB6394),
        (0xC54CC,0xC54F8),(0xC17BC,0xC180C),(0x70AA8,0x70CE0),
        (0x70A44,0x70AA6),(0x70E58,0x70EA4),(0x23ABC,0x23B62),
        (0xB77C8,0xB7826),(0xC04B8,0xC0558),(0xC5A30,0xC5A32),
        (0xBE478,0xBE540))


class ReplyFreshness(PreEntryBanks):
    def __init__(self,low,high):
        super().__init__(low,high)
        from unicorn import UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
        self.ranges.extend(RANGES)
        for start,end in RANGES:self.uc.mem_write(start,self.data[start:end])
        self.uc.mem_write(0x6D940,self.data[0x6D940:0x6D949])
        self.uc.mem_write(0x6D9C0,self.data[0x6D9C0:0x6D9C2])
        self.uc.mem_write(0x6DD5E,self.data[0x6DD5E:0x6DD5F])
        self.uc.mem_write(0xC5E4A,self.data[0xC5E4A:0xC5F82])
        self.uc.mem_map(0xFFFFE000,0x1000)
        self.status_bytes=[];self.mmio_writes=[];self.events=[];self.lifecycle=[];self.stop_before_main=False
        self.uc.hook_add(UC_HOOK_MEM_READ,self.read_status,begin=0xFFFFE802,end=0xFFFFE802)
        self.uc.hook_add(UC_HOOK_MEM_WRITE,self.write_mmio,begin=0xFFFFE000,end=0xFFFFEFFF)

    def hook(self,machine,pc,size,user_data):
        from unicorn.m68k_const import UC_M68K_REG_A7
        if pc==0x994D0 and self.stop_before_main:
            self.observed['stop_pc']=hex(pc);machine.emu_stop();return
        if pc==0x23428:
            sp=machine.reg_read(UC_M68K_REG_A7)
            self.events.append(int.from_bytes(machine.mem_read(sp+4,4),'big'))
        if pc in (0xC54CC,0xC54E8,0xC04FC):self.lifecycle.append(hex(pc))
        super().hook(machine,pc,size,user_data)

    def read_status(self,machine,access,address,size,value,user_data):
        if size!=1:raise ValueError('Unexpected status access width')
        machine.mem_write(address,bytes([self.status_bytes.pop(0) if self.status_bytes else 0]))

    def write_mmio(self,machine,access,address,size,value,user_data):
        if size!=1 or address not in (0xFFFFE800,0xFFFFE801):raise ValueError('Unexpected MMIO write')
        self.mmio_writes.append(dict(address=address,value=value))

    def state(self):
        u=self.uc
        return dict(pending=u.mem_read(BASE+0xF3F,1).hex(),body=u.mem_read(BASE+0x2269,6).hex(),
                    tracked_index=int.from_bytes(u.mem_read(BASE+0xF46,2),'big'),
                    tx_count=u.mem_read(BASE+0x16E9,1)[0],rx_length=int.from_bytes(u.mem_read(BASE+0xF2C,2),'big'),
                    producer=u.mem_read(BASE+0xEFE,1)[0],consumer=u.mem_read(BASE+0xEFF,1)[0],
                    ring=u.mem_read(BASE+0xEB6,54).hex(),events=list(self.events),lifecycle=list(self.lifecycle),
                    banks_unchanged=bytes(u.mem_read(0x4000,0x4000))==self.data[0x4000:0x8000])

    def submit_selected(self):
        from unicorn.m68k_const import UC_M68K_REG_A5,UC_M68K_REG_A7,UC_M68K_REG_SR,UC_M68K_REG_D7,UC_M68K_REG_PC
        if int.from_bytes(self.uc.mem_read(BASE+0xF3F,1),'big') & 0x10==0:
            raise ValueError('The selected Mode 23 pending bit must be set')
        # Explicit call-frame input for the scheduler's selected-index tail.
        # Selection/eligibility and elapsed timers are not inferred by this slice.
        self.uc.mem_write(STACK,bytes(8)+RETURN.to_bytes(4,'big'))
        for register,value in ((UC_M68K_REG_SR,0x2000),(UC_M68K_REG_A5,BASE),
                               (UC_M68K_REG_A7,STACK),(UC_M68K_REG_D7,75)):
            self.uc.reg_write(register,value)
        start=len(self.mmio_writes)
        self.uc.emu_start(0x23ABC,RETURN,timeout=5_000_000,count=100000)
        if self.uc.reg_read(UC_M68K_REG_PC)!=RETURN:raise ValueError('Selected scheduler tail did not return')
        # The data-register writes are exactly the logical software submission.
        writes=self.mmio_writes[start:]
        return bytes(row['value'] for row in writes if row['address']==0xFFFFE801)

    def accumulate(self,address=0x4004):
        frame=bytes.fromhex('6d18f023')+address.to_bytes(3,'big')+b'\x01'
        for byte in frame:self.call_local(0x23570,[byte])

    def status(self,status,data):
        self.status_bytes=[status,0];self.uc.mem_write(0xFFFFE803,bytes([data]))
        self.call_local(0x70AA8,[])


def submitted(low,high):
    peer=ReplyFreshness(low,high)
    observed=peer.dispatch(bytes.fromhex('6d18f02300400001'))
    assert not observed['storage_calls'] and observed['banks_unchanged']
    wire=peer.submit_selected();state=peer.state()
    assert wire==bytes.fromhex('6cf01863')+bytes.fromhex(observed['response_body'])
    assert state['pending']=='00' and state['tracked_index']==75 and state['tx_count']==0
    return peer,wire


def analyze(low,high):
    cases=[]
    inputs=[('requeue',0xE0,0,True,0),('retire',0xE0,0x30,True,0),
            ('retain_tracking',0xE0,0xC0,True,0),('discard_and_requeue',0xE0,0xF0,True,0),
            ('class_a0',0xA0,0,True,0),('nonempty_tx',0xE0,0,True,10),
            ('empty_rx_retains_tracking',0xE0,0x30,False,0)]
    for label,status,data,rx,tx in inputs:
        peer,wire=submitted(low,high)
        if rx:peer.accumulate()
        peer.uc.mem_write(BASE+0x16E9,bytes([tx]))
        before=peer.state();peer.status(status,data);after=peer.state()
        assert after['body']==before['body'] and after['banks_unchanged']
        if label in ('requeue','discard_and_requeue'):assert after['pending']=='10' and after['tracked_index']==0
        elif label=='retire':assert after['pending']=='00' and after['tracked_index']==0
        else:assert after['pending']=='00' and after['tracked_index']==75
        second=None
        if after['pending']=='10':
            second=peer.submit_selected();assert second==wire
        cases.append(dict(case=label,status=status,data=data,before=before,after=after,
                          first_submission_hex=wire.hex(),repeated_submission_hex=None if second is None else second.hex()))
    # The native interface-reset path clears TX/ring state but requeues tracking.
    peer,wire=submitted(low,high);peer.accumulate();before=peer.state()
    peer.call_local(0xC04FC,[]);after=peer.state()
    assert after['pending']=='10' and after['tracked_index']==0 and after['tx_count']==0
    assert after['producer']==after['consumer']==1 and after['ring']=='00'*54
    assert peer.submit_selected()==wire and after['body']==before['body']
    cases.append(dict(case='native_interface_reset_requeues_reply',before=before,after=after,
                      repeated_submission_hex=wire.hex()))
    # Retirement is not a queue fence: native receive can commit a later aliased
    # request, and native dispatch can stage a new same-echo response afterwards.
    peer,wire=submitted(low,high);peer.accumulate();peer.status(0xE0,0x30)
    retired=peer.state();assert retired['tracked_index']==0 and retired['pending']=='00'
    peer.accumulate(0x14000);peer.status(0xE0,0)
    queued=peer.state();peer.call_local(0xA4A38,[]);dispatched=peer.state()
    assert dispatched['body'][:4]=='4000' and dispatched['pending']=='10'
    assert dispatched['body'][4:]==peer.data[0x14000:0x14004].hex()
    assert dispatched['banks_unchanged'] and queued['tracked_index']==0
    alias=peer.submit_selected();assert alias[4:6]==wire[4:6]
    cases.append(dict(case='retired_tracking_does_not_fence_later_aliased_request',retired=retired,
                      queued=queued,dispatched=dispatched,original_submission_hex=wire.hex(),aliased_submission_hex=alias.hex()))
    # Interface initialization is not application C-runtime initialization.
    peer,wire=submitted(low,high);before=peer.state();peer.call_local(0xC04B8,[]);after=peer.state()
    assert after['tracked_index']==75 and after['body']==before['body'] and after['pending']=='00'
    cases.append(dict(case='interface_initializer_retains_old_tracking',before=before,after=after))
    # Execute the actual application data-copy/BSS-zero entry, stopping before
    # main and never executing the application's hardware/subsystem initialization.
    for pattern in (0xA5,0x5A):
        peer=ReplyFreshness(low,high)
        peer.uc.mem_write(BASE,bytes([pattern])*0x37B0)
        before=peer.state();peer.stop_before_main=True
        observed=peer.call_local(0xBE4F4,[]);cleared=peer.state()
        assert observed['stop_pc']=='0x994d0'
        assert cleared['body']=='00'*6 and cleared['pending']=='00' and cleared['tracked_index']==0
        assert cleared['rx_length']==cleared['tx_count']==0 and cleared['ring']=='00'*54
        peer.call_local(0xC04B8,[]);initialized=peer.state()
        assert initialized['tracked_index']==0 and initialized['pending']=='00'
        assert initialized['producer']==initialized['consumer']==1 and initialized['banks_unchanged']
        cases.append(dict(case='application_crt_clears_response_state_before_main',pattern=pattern,
                          before=before,cleared=cleared,interface_initialized=initialized,
                          application_main_executed=False,physical_reset_verified=False))
    data=low+high
    return dict(schema='al5-native-resident-reply-freshness-v1',cases=cases,
                low_sha256=hashlib.sha256(low).hexdigest(),high_sha256=hashlib.sha256(high).hexdigest(),
                code_sha256={hex(a):hashlib.sha256(data[a:b]).hexdigest() for a,b in RANGES},
                sources={name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in
                         ('trace_resident_reply_freshness.py','trace_preentry_banks.py','emulate_application_boot.py',
                          'emulate_application_authorization.py','emulate_receive_preparation.py','emulate_application_reset_chain.py')},
                hardware_access=False,session_boundary_proven=False,physical_status_semantics_verified=False,
                live_read_enabled=False,live_upload_enabled=False,live_execution_enabled=False,live_write_enabled=False,
                limits=['Pinned historical code and bank data with synthetic RX, status/data registers and call frames.',
                        'Selected scheduler tail executes; full eligibility, timer and interrupt scheduling are not modeled.',
                        'Submission bytes are native data-register writes, not a measured physical transmission.',
                        'Numeric status/data combinations are input values, not validated physical success/error labels.',
                        'No controller/adapter/USB drain or physical request freshness is established.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--full-reference',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('New output file required')
    data=args.full_reference.read_bytes();result=analyze(data[:0x20000],data[0x20000:])
    result['input_reference']=dict(selected=str(args.full_reference),resolved=str(args.full_reference.resolve()),
                                   sha256=hashlib.sha256(data).hexdigest())
    with args.output.open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2)
    print('PASS',len(result['cases']),'joined native scheduling/status cases; physical freshness remains unqualified')
