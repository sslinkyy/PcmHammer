"""Execute saved receive dequeue and reply staging; no peripheral or transport code."""
import argparse
import hashlib
import json
from pathlib import Path
from emulate_mode23_coverage import Probe, HIGH_HASH

EXTRA=((0x23694,0x2377a),(0x23c9c,0x23d14),(0x23e88,0x23f28),
       (0x70e34,0x70e56),(0xc17e4,0xc180c),(0x23bd4,0x23c9a),(0xa9bf0,0xa9c5a))


class Boundary(Probe):
    def __init__(self, high):
        super().__init__(high)
        self.ranges.extend(EXTRA)

    def request(self,address):
        # Unlike Probe.handler, retain the pending bit and shared response body.
        self.u.mem_write(0x208000,bytes.fromhex('086d18f023')+address.to_bytes(3,'big')+b'\x01')
        self.call(0xbfda0,[0x208000])

    def snapshot(self):
        return dict(body=self.u.mem_read(0xffa269,6).hex(),
                    pending=self.u.mem_read(0xff8f3f,1).hex(),
                    tx_count=self.u.mem_read(0xff96e9,1)[0],
                    tx=self.u.mem_read(0xff96de,self.u.mem_read(0xff96e9,1)[0]).hex())

    def format(self):
        # Synthetic dispatcher metadata: priority group 3, requesting tool F0.
        self.u.mem_write(0xff8f32,b'\x03')
        self.u.mem_write(0xff8efd,b'\xf0')
        self.u.mem_write(0xff96e9,b'\0')
        self.call(0xc17e4,[75])  # scheduler clears selected pending bit before formatting
        self.call(0x23c9c,[0x6ddba,1])
        return self.snapshot()


def analyze(high):
    p=Boundary(high)
    records=[]
    # Empty RX says nothing about a pending response.
    p.request(0x15fd8)
    before=p.snapshot()
    result=p.call(0x23694,[])
    assert result==0 and p.snapshot()==before and before['pending']=='10'
    records.append(dict(case='empty_receive_preserves_pending',dequeue_result=result,observed=p.snapshot()))

    # Two real handlers before formatting overwrite the single staging slot.
    p.request(0x1fffc)
    formatted=p.format()
    assert formatted['tx']=='6cf01863fffcbfd0e1f2' and formatted['pending']=='00'
    records.append(dict(case='second_request_replaces_first_staged_response',observed=formatted))
    assert p.call(0x23694,[])==0 and p.snapshot()==formatted
    records.append(dict(case='empty_receive_and_clear_pending_still_have_tx_bytes',observed=p.snapshot()))

    # A pending response can be replaced even by a request whose low-16 echo aliases it.
    p=Boundary(high)
    p.request(0x8000); first=p.snapshot()
    p.request(0x18000); second=p.snapshot()
    assert first==second
    records.append(dict(case='same_echo_and_data_are_indistinguishable',observed=second))

    # Native queue iterator: initial record, next record, then no-next sentinel.
    p=Boundary(high)
    p.u.mem_write(0xff8eb7,bytes.fromhex('886d18f023015fd801'))
    p.u.mem_write(0xff8ec0,bytes.fromhex('086d18f02301fffc01'))
    p.u.mem_write(0xff8eff,b'\x01')
    p.u.mem_write(0xff8efe,b'\x13')
    p.u.mem_write(0xff8f00,b'\x01')
    offsets=[]
    for _ in range(3):offsets.append(p.call(0x23694,[]))
    assert offsets==[1,10,0]
    assert bytes(p.u.mem_read(0xff8eb7,9))==b'\0'*9
    assert p.u.mem_read(0xff8ec0,1)[0]==8
    records.append(dict(case='native_queue_advance',returned_offsets=offsets,
                        consumer_offset=p.u.mem_read(0xff8eff,1)[0],
                        previous_record_cleared=True,last_record_retained=True))
    # Producer equals consumer in the first-record state: no dequeue.
    p=Boundary(high)
    p.u.mem_write(0xff8eb7,b'\x08')
    p.u.mem_write(0xff8efe,b'\x01\x01\x01')
    assert p.call(0x23694,[])==0
    records.append(dict(case='initial_equal_offsets_return_zero',dequeue_result=0))
    # At the end of the small ring the native iterator wraps to offset one.
    p=Boundary(high)
    p.u.mem_write(0xff8eb6+40,bytes.fromhex('086d18f023015fd801'))
    p.u.mem_write(0xff8eb7,bytes.fromhex('886d18f02301fffc01'))
    p.u.mem_write(0xff8eff,bytes([40]))
    assert p.call(0x23694,[])==1
    assert p.u.mem_read(0xff8eb7,1)[0]==8 and p.u.mem_read(0xff93a7,1)[0]==0x88
    records.append(dict(case='native_queue_wrap',returned_offset=1,raw_record_flag=0x88,normalized_length=8))
    # Selection is by pending-bit index, not request arrival order.
    p=Boundary(high)
    p.request(0x15fd8)  # index 75 pending first
    p.u.mem_write(0xff8f3e,b'\x40')  # synthetic later index 65 / service 62 pending
    p.u.mem_write(0xff8f50,b'\x40\x10')  # both indices eligible
    p.call(0x23bd4,[1,85])
    selected=int.from_bytes(p.u.mem_read(0xff8f42,2),'big')
    assert selected==65
    p.call(0xc17e4,[65]);p.call(0x23bd4,[1,85])
    next_selected=int.from_bytes(p.u.mem_read(0xff8f42,2),'big')
    assert next_selected==75
    p.u.mem_write(0xff8f51,b'\0')  # remove eligibility for index 75
    p.call(0x23bd4,[1,85])
    suppressed=int.from_bytes(p.u.mem_read(0xff8f42,2),'big')
    assert suppressed==0xffff and p.snapshot()['pending']=='10'
    records.append(dict(case='native_pending_priority_and_eligibility',first_selected=selected,
                        next_selected=next_selected,ineligible_selection=suppressed,
                        mode23_still_pending=True))
    return dict(firmware_sha256=HIGH_HASH,
                code_sha256={hex(a):hashlib.sha256(high[a-0x20000:b-0x20000]).hexdigest() for a,b in EXTRA},
                scheduler_slice_sha256=hashlib.sha256(high[0x23abc-0x20000:0x23b5c-0x20000]).hexdigest(),
                response_record_address='0x6ddba',response_descriptor_address='0x6df50',
                response_index=75,cases=records,
                session_boundary_proven=False,live_read_enabled=False,live_write_enabled=False,
                limits=['Synthetic receive queue, dispatcher metadata and read data.',
                        'Pending selector, selected bit-clear and formatter executed directly; outer scheduling gates not executed.',
                        'Actual TX helper stages RAM bytes only. No peripheral, interrupts, USB or bus execution.',
                        'No bound on pending response latency or guarantee of transport FIFO ordering established.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--high',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=analyze(args.high.read_bytes())
    args.output.write_bytes((json.dumps(result,indent=2)+'\n').encode())
    print('PASS',len(result['cases']),'native dequeue/staging cases; session boundary remains unproven')
