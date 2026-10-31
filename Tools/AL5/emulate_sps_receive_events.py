"""Pinned downstream queue/event execution; scripted RAM only, no device or timing model."""
import argparse,hashlib,json
from pathlib import Path
from emulate_mode23_boundary import Boundary
RANGES=((0x23428,0x2356E),(0x23570,0x23692),(0x2377C,0x23798),
        (0xB6230,0xB6328),(0xB6328,0xB6394),(0xC54CC,0xC54F8),(0xC17BC,0xC180C))
class Events(Boundary):
 def __init__(self,module):
  super().__init__(module,source='sps_os');self.ranges.extend(RANGES)
  self.ranges.extend(((0x70A44,0x70AA6),(0x70E58,0x70E94)))
  self.u.mem_map(0xFFFFE000,0x1000)
  self.u.mem_map(0xFFFFF000,0x1000) # inert watchdog register storage
  self.u.mem_write(0xFF8EFE,b'\x01');self.u.mem_write(0xFF8EFF,b'\x01')
  self.u.mem_write(0xFF8F54,b'\x00\x4b');self.call(0xC54E8,[])
  self.u.mem_write(0xFF8F3F,b'\x00');self.u.mem_write(0xFFA269,bytes.fromhex('800012345678'))
 def receive(self):
  for byte in bytes.fromhex('6d18f02300800001'):self.call(0x23570,[byte])
 def state(self):
  return dict(pending=self.u.mem_read(0xFF8F3F,1).hex(),body=self.u.mem_read(0xFFA269,6).hex(),
   active_response_index=int.from_bytes(self.u.mem_read(0xFF8F46,2),'big'),
   rx_length=int.from_bytes(self.u.mem_read(0xFF8F2C,2),'big'),producer=self.u.mem_read(0xFF8EFE,1)[0],
   consumer=self.u.mem_read(0xFF8EFF,1)[0],ring=self.u.mem_read(0xFF8EB6,16).hex())
def analyze(module):
 cases=[]
 for event in (0,0x10,0x20,0x40,0x80):
  p=Events(module);p.receive();before=p.state();p.call(0x23428,[event]);after=p.state()
  assert before['pending']=='00' and before['active_response_index']==75
  assert after['body']==before['body']
  cases.append(dict(event_mask=event,before=before,after=after))
 # Zero event requeues the tracked response; a discard event rolls back only RX bytes.
 assert cases[0]['after']['pending']=='10' and cases[0]['after']['active_response_index']==0
 p=Events(module);p.receive();before=p.state();p.call(0xB6328,[]);after=p.state()
 assert after['producer']==1 and after['body']==before['body'] and after['active_response_index']==75
 assert after['ring'][2:20]=='00'*9
 cases.append(dict(case='explicit_receive_discard',before=before,after=after))
 # Empty event processing is not evidence that a tracked request has completed.
 p=Events(module);p.call(0x23428,[0]);empty=p.state()
 assert empty['pending']=='00' and empty['active_response_index']==75
 cases.append(dict(case='empty_event',after=empty))
 # Execute format -> software submission -> tracked event requeue -> format again.
 p=Events(module);p.u.mem_write(0xFF8F3F,b'\x10');first=p.format()
 p.call(0x70A44,[]);p.call(0xC54E8,[]);p.receive();p.call(0x23428,[0]);second=p.format()
 assert first['tx']==second['tx']=='6cf01863800012345678'
 cases.append(dict(case='saved_body_reformatted_after_submission_and_event',first=first,second=second,
                   identical_formatted_bytes=True,physical_transmission_observed=False))
 return dict(sps_os_sha256=hashlib.sha256(module).hexdigest(),cases=cases,
  code_sha256={hex(a):hashlib.sha256(module[a-0x20000:b-0x20000]).hexdigest() for a,b in RANGES},
  native_case_count=len(cases),requeue_demonstrated=True,session_boundary_proven=False,
  live_read_enabled=False,live_write_enabled=False,
  limits=['Synthetic ring and saved response metadata; no actual peripheral completion or adapter queues.',
   'Event masks are input values, not asserted physical success/error labels.',
   'Native response formatting/submission and event requeue execute; physical retransmission is not modeled.',
   'Watchdog MMIO is inert RAM; no timing or reset behavior is modeled.'])
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--sps-os',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if a.output.exists():p.error('New output required')
 r=analyze(a.sps_os.read_bytes());a.output.open('x').write(json.dumps(r,indent=2));print('PASS',r['native_case_count'],'native downstream cases')
