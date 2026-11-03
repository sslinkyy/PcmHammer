"""Reset-vector -> native ISR/copy -> inherited compiled reader; synthetic hardware only."""
import argparse
import copy
import hashlib
import json
import unittest
from pathlib import Path
from emulate_flash_fault_recovery import experiment
from emulate_readonly_runtime import Runtime
from emulate_readonly_core import request
from unicorn.m68k_const import UC_M68K_REG_PC,UC_M68K_REG_A7

class ResetReaderTests(unittest.TestCase):
 def context(self,probe=True,**kwargs):
  options=dict(reset_status=0x20,retained_marker=0xBFC1)
  options.update(kwargs)
  return experiment(self.low,self.high,probe_boot_request=probe,retain_context=True,**options)
 def runtime(self,c,flash=None):
  report=c.copy_readonly_runtime(self.code,self.receipt)
  self.assertEqual(report['stop'],'before_offline_runtime_entry')
  r=Runtime(self.code,self.receipt,flash_image=self.low+self.high if flash is None else flash,trace_detail='summary',inherited_cpu=c.cpu)
  c.attach_runtime(r);r.entry_steps=0;r.u.emu_start(self.receipt['entry'],0x1000000,count=100000)
  return r
 def send(self,r,address,count,sequence):
  before=len(r.frames);wire=bytes.fromhex('6d18f0b1')+request(address,count,sequence=sequence)
  r.fifo.extend((0x20,v) for v in wire);r.fifo.append((0xE0,0));r.entry_steps=100
  r.u.emu_start(r.u.reg_read(UC_M68K_REG_PC),0x1000000,count=1000000)
  self.assertEqual(r.entry_steps,-1);self.assertFalse(r.fifo)
  return before
 def test_copy_rejection_cases_keep_real_reset_context_without_execution(self):
  for name,probe,execute,bad,suffix in [('unarmed',False,True,False,'7f36800530ff9022'),('copy_only',True,False,False,'760073'),('bad_checksum',True,True,True,'768077')]:
   with self.subTest(case=name):
    c=self.context(probe);prior=c.report['final_sp']
    report=c.copy_readonly_runtime(self.code,self.receipt,execute=execute,bad_checksum=bad)
    self.assertEqual(report['stop'],'before_synthetic_irq_rte')
    self.assertEqual(report['final_sp'],prior)
    self.assertEqual(report['offline_reader_copied_bytes'],len(self.code))
    self.assertIsNone(report['offline_reader_handoff'])
    self.assertTrue(report['software_tx_frames'][-1].endswith(suffix))
    self.assertTrue(report['rom_unchanged_from_selected_view'])
    self.assertFalse(report['exception_return_executed'])
    with self.assertRaises(ValueError):c.copy_readonly_runtime(self.code,self.receipt)
    dummy=Runtime(self.code,self.receipt)
    with self.assertRaises(ValueError):c.attach_runtime(dummy)
 def test_actual_reset_stack_and_historical_region_reads(self):
  for options in ({},{'retained_marker':0x6124},{'reset_status':0x80,'retained_marker':0,'window':'os_check_to_reject'}):
   c=self.context(**options);r=self.runtime(c);h=c.report['offline_reader_handoff']
   self.assertIs(r.u,c.cpu);self.assertTrue(r.inherited_cpu)
   self.assertEqual(h['incoming_physical_sp'],h['incoming_sp']&0xFFFFFF)
   self.assertLess(h['incoming_physical_sp'],r.base)
   self.assertEqual(h['pending_return'],0x33B8);self.assertEqual(h['stack_delta'],-72)
   self.assertEqual(h['native_copied_bytes'],len(self.code));self.assertFalse(h['code_preloaded'])
   self.assertTrue(all(event==[0,0] for event in h['scripted_fifo_remaining']))
   for seq,(address,count) in enumerate(((0,8),(0x3FD8,4),(0x3FFF,2),(0x4000,32),(0x6000,32),(0xFFFF,2),(0x10000,32),(0x15FD8,32),(0x1FFFE,2),(0x20000,32),(0xC4C66,2),(0xFFFFF,1)),1):
    before=self.send(r,address,count,seq);self.assertEqual(len(r.frames),before+1)
    self.assertEqual(r.frames[-1][24:-2],(self.low+self.high)[address:address+count])
   quiesce=r.quiesce_from_saved_loop();self.assertTrue(quiesce['software_parked']);self.assertFalse(quiesce['safe_exit_proven'])
   self.assertEqual(hashlib.sha256(bytes(r.u.mem_read(h['incoming_sp'],72))).hexdigest(),h['abandoned_frame_sha256'])
   self.assertEqual(bytes(r.u.mem_read(0,0x100000)),self.low+self.high)
   self.assertFalse(c.report['live_write_enabled'])
 def test_out_of_range_and_cross_end_reads_never_reuse_stale_response(self):
  c=self.context();r=self.runtime(c);self.send(r,0x4000,32,1)
  for seq,(address,count) in enumerate(((0x100000,1),(0xFFFFE0,32),(0xFFFFFF,1),(0xFFFFF,2),(0xFFFF0,32),(0xFFFA26,1)),2):
   before=(len(r.frames),r.flash_read_count,r.tx_count)
   self.send(r,address,count,seq)
   self.assertEqual((len(r.frames),r.flash_read_count,r.tx_count),before)
  before=self.send(r,0xFFFE0,32,99);self.assertEqual(len(r.frames),before+1)
  self.assertEqual(r.frames[-1][24:-2],self.high[-32:])
 def test_atomic_preparation_banks_are_a_separate_fixture_epoch(self):
  from emulate_preparation_statuses import StatusTrace
  preparation=StatusTrace(self.low,self.high,'success');observed=preparation.trace()
  banks=bytes(preparation.uc.mem_read(0x4000,0x4000));ram=bytes(preparation.uc.mem_read(0xFF8000,0x3800))
  fixture=self.low[:0x4000]+banks+self.low[0x8000:]+self.high
  c=self.context(initial_ram=ram,initial_persistent_banks=banks);r=self.runtime(c,fixture)
  self.assertEqual(c.report['initial_ram_sha256'],observed['ram_sha256'])
  self.assertEqual(c.report['initial_persistent_banks_sha256'],hashlib.sha256(banks).hexdigest())
  self.assertEqual(c.report['flash_fixture_sha256'],hashlib.sha256(fixture).hexdigest())
  self.assertNotEqual(fixture,self.low+self.high)
  for seq,address in enumerate((0x4028,0x6028,0x602A,0x8000),1):
   before=self.send(r,address,32,seq);self.assertEqual(len(r.frames),before+1)
   self.assertEqual(r.frames[-1][24:-2],fixture[address:address+32])
  self.assertFalse(c.report['live_write_enabled'])
  for bad in (bytes(0x3FFF),bytes(0x4001),bytearray(0x4000)):
   with self.assertRaises(ValueError):self.context(initial_persistent_banks=bad)
 def test_summary_trace_and_symbol_ownership(self):
  observations=[]
  for detail in ('full','summary'):
   receipt=copy.deepcopy(self.receipt);r=Runtime(self.code,receipt,trace_detail=detail)
   owned_step=r.symbols['al5_ro_step'];receipt['symbols']['al5_ro_step']=0
   self.assertEqual(r.symbols['al5_ro_step'],owned_step)
   r.call('al5_ro_init');r.feed(bytes.fromhex('6d18f0b1')+request(0x18000,32));r.drain();r.validate_watchdog()
   observations.append((r.frames,r.watchdog_count,r.tx_count,r.flash_read_count,r.ram_write_count,r.stack_low))
   if detail=='summary':self.assertEqual((r.tx,r.watchdog,r.flash_reads,r.ram_writes),([],[],[],[]))
  self.assertEqual(observations[0],observations[1])

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('low','high','build_dir'):p.add_argument('--'+n.replace('_','-'),dest=n,type=Path,required=True)
 a=p.parse_args();ResetReaderTests.low=a.low.read_bytes();ResetReaderTests.high=a.high.read_bytes()
 ResetReaderTests.code=(a.build_dir/'readonly_kernel.offline.bin').read_bytes();ResetReaderTests.receipt=json.loads((a.build_dir/'build_receipt.json').read_text())
 unittest.main(argv=[__file__])
