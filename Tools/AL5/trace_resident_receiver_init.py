"""Offline CRT -> native communication init -> guarded IRQ/RX -> dispatch/scheduler slice.

Application main's other initializers, real IRQ delivery and peripheral semantics
remain outside the model. No live reader, reset, upload or writer is provided.
"""
import argparse
import hashlib
import json
from pathlib import Path
from trace_resident_reply_freshness import ReplyFreshness,BASE

RANGES=((0xBDC38,0xBDC92),(0xB0B94,0xB0D52),(0x9EAF8,0x9EB18),
        (0x8BE54,0x8BE5C),(0xBD144,0xBD184),(0xA9C5C,0xA9DC8),
        (0xC3D98,0xC3DF6),(0x238AC,0x23C9C),(0xA9BF0,0xA9C5A),
        (0xC448C,0xC44C2),(0xB0A40,0xB0B94),(0x22250,0x2266A),
        (0x2266C,0x226F0),(0xA95D0,0xA960A))


class ReceiverInit(ReplyFreshness):
    def __init__(self,low,high):
        super().__init__(low,high)
        self.ranges.extend(RANGES)
        for start,end in RANGES:self.uc.mem_write(start,self.data[start:end])
        for start,end in ((0x10920,0x10AB0),(0x23424,0x23425),(0xC44C2,0xC44C6)):
            self.uc.mem_write(start,self.data[start:end])
        self.consumer_entries=0;self.initializer_entries=[]

    def hook(self,machine,pc,size,user_data):
        if pc==0x70AA8:self.consumer_entries+=1
        if pc in (0xBDC38,0xC04B8,0xB0B94,0xA9D0C):self.initializer_entries.append(hex(pc))
        super().hook(machine,pc,size,user_data)

    def initialized(self,pattern=0xA5):
        self.uc.mem_write(BASE,bytes([pattern])*0x37B0)
        self.stop_before_main=True
        result=self.call_local(0xBE4F4,[])
        if result['stop_pc']!='0x994d0':raise ValueError('CRT did not reach the main boundary')
        before=self.state();self.call_local(0xBDC38,[]);after=self.state()
        return dict(before=before,after=after,initializer_entries=list(self.initializer_entries),
                    receive_flags=self.uc.mem_read(BASE+0xF56,7).hex(),
                    transmit_eligibility=self.uc.mem_read(BASE+0xF48,11).hex(),
                    mode23_eligible=bool(self.uc.mem_read(BASE+0xF51,1)[0]&0x10))

    def irq(self,status,data):
        # The guard reads status once; the consumer then reads it and loops to zero.
        self.status_bytes=[status,status,0]
        self.uc.mem_write(0xFFFFE803,bytes([data]))
        self.call_local(0xC3D98,[])

    def schedule(self):
        start=len(self.mmio_writes);self.call_local(0x238AC,[])
        return bytes(row['value'] for row in self.mmio_writes[start:] if row['address']==0xFFFFE801)

    def receive_read(self,address):
        for byte in bytes.fromhex('6d18f023')+address.to_bytes(3,'big')+b'\x01':self.irq(0x40,byte)
        self.irq(0xE0,0)

    def timer(self):
        return int.from_bytes(self.uc.mem_read(BASE+0x22FC,2),'big')


def analyze(low,high):
    cases=[]
    for status,blocked,alternate,allow60 in ((0x40,False,False,False),(0x20,False,False,False),
            (0x60,False,False,False),(0x60,False,False,True),(0x40,True,False,False),(0x40,False,True,False)):
        peer=ReceiverInit(low,high);initial=peer.initialized()
        assert initial['after']['body']=='00'*6 and initial['after']['tracked_index']==0 and initial['mode23_eligible']
        if blocked:peer.uc.mem_write(BASE+0xF57,b'\x01')
        if alternate:peer.uc.mem_write(BASE+0xF58,b'\x01')
        if allow60:peer.uc.mem_write(BASE+0xF5B,b'\x01')
        before=peer.state();peer.irq(status,0x6D);after=peer.state()
        expected_consumer=(not blocked and (status==0x40 or (status==0x60 and allow60)))
        assert bool(peer.consumer_entries)==expected_consumer
        assert after['rx_length']==(1 if expected_consumer and not alternate else 0)
        assert after['body']=='00'*6 and after['pending']=='00' and after['banks_unchanged']
        cases.append(dict(case='native_irq_guard',status=status,blocked=blocked,alternate=alternate,allow60=allow60,
                          initialization=initial,before=before,after=after,consumer_entries=peer.consumer_entries))
    peer=ReceiverInit(low,high);initial=peer.initialized(0x5A)
    for byte in bytes.fromhex('6d18f02300400001'):peer.irq(0x40,byte)
    accumulated=peer.state();assert accumulated['rx_length']==8
    peer.irq(0xE0,0);committed=peer.state()
    peer.call_local(0xA4A38,[]);dispatched=peer.state()
    assert dispatched['body']==('4000'+(low+high)[0x4000:0x4004].hex()) and dispatched['pending']=='10'
    submission=peer.schedule();scheduled=peer.state()
    assert submission==bytes.fromhex('6cf01863')+bytes.fromhex(dispatched['body'])
    assert scheduled['tracked_index']==75 and scheduled['pending']=='00' and scheduled['tx_count']==0
    cases.append(dict(case='initialized_guarded_receive_to_native_scheduler',initialization=initial,
                      accumulated=accumulated,committed=committed,dispatched=dispatched,scheduled=scheduled,
                      submission_hex=submission.hex(),banks_unchanged=scheduled['banks_unchanged']))
    # A warm communication initializer does not provide the CRT's clearing.
    peer=ReceiverInit(low,high);peer.initialized();peer.receive_read(0x4000)
    peer.call_local(0xA4A38,[]);first=peer.schedule();before=peer.state()
    peer.call_local(0xBDC38,[]);after=peer.state()
    assert after['tracked_index']==75 and after['body']==before['body'] and after['banks_unchanged']
    cases.append(dict(case='communication_init_alone_retains_old_tracking',before=before,after=after))
    # Different function-call interleavings reproduce a possible software race,
    # not real interrupt cadence. The timer uses its actual native decrement helper.
    for early_scheduler in (False,True):
        peer=ReceiverInit(low,high);peer.initialized();peer.receive_read(0x4000)
        peer.call_local(0xA4A38,[]);first=peer.schedule();peer.receive_read(0x4004)
        queued=peer.state();duplicate=peer.schedule() if early_scheduler else b''
        if early_scheduler:assert duplicate==first
        peer.call_local(0xA4A38,[]);pending=peer.state();second=peer.schedule()
        blocked_timer=peer.timer();ticks=0
        if early_scheduler:
            assert second==b'' and blocked_timer==0x640 and pending['pending']=='10'
            while peer.timer():
                peer.call_local(0xC448C,[]);ticks+=1
                if ticks>100:raise ValueError('Native timer did not expire within its derived 1600/16 bound')
            second=peer.schedule();assert ticks==100
        assert second==bytes.fromhex('6cf018634004')+(low+high)[0x4004:0x4008]
        assert peer.state()['banks_unchanged']
        cases.append(dict(case='next_read_scheduler_interleaving',early_scheduler=early_scheduler,
                          first_submission_hex=first.hex(),duplicate_submission_hex=duplicate.hex(),
                          next_submission_hex=second.hex(),queued=queued,pending=pending,
                          blocked_timer=blocked_timer,native_timer_calls=ticks,
                          physical_tick_duration_verified=False,after=peer.state()))
    # The real persistent-context restore used by startup copies only the lower
    # application context, not the Mode 23 body, pending bits or tracking fields.
    from unicorn.m68k_const import UC_M68K_REG_D0
    peer=ReceiverInit(low,high);peer.stop_before_main=True;peer.call_local(0xBE4F4,[])
    before=peer.state();peer.call_local(0x2266C,[BASE+0x140])
    assert peer.uc.reg_read(UC_M68K_REG_D0)==0
    selected=int.from_bytes(peer.uc.mem_read(BASE+0xE64,4),'big')
    context=bytes(peer.uc.mem_read(BASE+0x140,0x9F2))
    assert selected in (0x4028,0x6028) and context==peer.data[selected+2:selected+2+0x9F2]
    peer.call_local(0xA95D0,[BASE+0x140,BASE+0xB30,0])
    checksum=peer.uc.reg_read(UC_M68K_REG_D0)&0xFFFF
    assert checksum==int.from_bytes(context[-2:],'big')
    restored=peer.state();assert restored['body']=='00'*6 and restored['pending']=='00' and restored['tracked_index']==0
    peer.call_local(0xBDC38,[]);peer.receive_read(0x4000);peer.call_local(0xA4A38,[])
    wire=peer.schedule();assert wire==bytes.fromhex('6cf018634000')+peer.data[0x4000:0x4004]
    assert peer.state()['banks_unchanged']
    cases.append(dict(case='persistent_context_restore_preserves_response_clear',before=before,restored=restored,
                      source_address=selected+2,destination_start=BASE+0x140,destination_end_exclusive=BASE+0xB32,
                      bytes_restored=len(context),context_sha256=hashlib.sha256(context).hexdigest(),
                      native_crc=checksum,stored_crc=int.from_bytes(context[-2:],'big'),
                      submission_hex=wire.hex(),after=peer.state()))
    data=low+high
    return dict(schema='al5-offline-resident-receiver-init-v1',cases=cases,
                low_sha256=hashlib.sha256(low).hexdigest(),high_sha256=hashlib.sha256(high).hexdigest(),
                code_sha256={hex(a):hashlib.sha256(data[a:b]).hexdigest() for a,b in RANGES},
                sources={n:hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in
                         ('trace_resident_receiver_init.py','trace_resident_reply_freshness.py','trace_preentry_banks.py',
                          'emulate_storage_selection.py')},
                hardware_access=False,physical_receiver_ready_verified=False,session_boundary_proven=False,
                live_read_enabled=False,live_upload_enabled=False,live_execution_enabled=False,live_write_enabled=False,
                limits=['Pinned historical image, synthetic call frames, dirty RAM and inert scripted MMIO.',
                        'Real CRT and communication initializer execute on the same emulator; other main initializers are not executed.',
                        'Native IRQ guard, accumulator, event commit, dispatcher and full scheduler execute as explicit function calls.',
                        'Native countdown helper calls are not a physical elapsed-time measurement.',
                        'No real exception delivery, peripheral status meaning, timing or controller/adapter/USB drain is qualified.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--full-reference',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('New output file required')
    data=args.full_reference.read_bytes();result=analyze(data[:0x20000],data[0x20000:])
    result['input_reference']=dict(selected=str(args.full_reference),resolved=str(args.full_reference.resolve()),sha256=hashlib.sha256(data).hexdigest())
    with args.output.open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2)
    print('PASS',len(result['cases']),'native communication-init/IRQ cases; live operations disabled')
