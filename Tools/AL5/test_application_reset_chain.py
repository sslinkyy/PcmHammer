"""Offline application-to-reset boundary regressions; no reset or flash devices."""
import argparse
import unittest
from pathlib import Path
from emulate_application_reset_chain import analyze
from emulate_flash_fault_recovery import experiment

class ChainTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.report=analyze(*cls.inputs)
 def test_strict_storage_boundary(self):
  c=self.report['strict_application']
  self.assertEqual(c['stop_pc'],'0x226f0')
  self.assertEqual(c['park_iterations'],0)
  self.assertFalse(c['storage_return_assumed'])
  self.assertFalse(c['reset_observed'])
  self.assertEqual(c['storage_calls'][0]['source_argument'],'0xff8140')
  self.assertFalse(c['storage_calls'][0]['implementation_executed'])
 def test_native_preparation_erase_boundary(self):
  c=self.report['preparation_storage_boundary']
  self.assertEqual(c['stop_pc'],'0x22b18')
  self.assertEqual(c['primitive_boundary']['entry'],0x22B18)
  self.assertEqual(c['primitive_boundary']['arguments'][1],0x6000)
  self.assertFalse(c['primitive_boundary']['implementation_executed'])
  self.assertTrue(c['banks_unchanged'])
  self.assertEqual(c['bank_source'],'pinned_historical_LOW')
  self.assertEqual(c['park_iterations'],0)
  self.assertFalse(c['reset_observed'])
  self.assertFalse(c['storage_calls'][0]['return_is_stubbed'])
 def test_preparation_failure_does_not_return_to_accepted_park(self):
  c=self.report['preparation_failure']
  self.assertEqual(c['stop_pc'],'0x22dbc')
  self.assertEqual(c['marker'],'0x6124')
  self.assertEqual(c['park_iterations'],0)
  self.assertTrue(c['banks_unchanged'])
  self.assertFalse(c['flash_effects_modeled'])
  self.assertFalse(c['flash_implementation_executed'])
  self.assertEqual([r['kind'] for r in c['injected_returns']],['erase_status_only_no_erase','copied_program_status_only_no_flash_execution'])
  self.assertEqual(c['injected_returns'][0]['destination'],0x6000)
  b=self.report['conditional_failure_reset']['boot']
  self.assertTrue(self.report['conditional_failure_reset']['reset_injected'])
  self.assertEqual(b['initial_ram_sha256'],c['ram_sha256'])
  self.assertEqual(b['retained_marker'],0x6124)
  self.assertEqual(b['reset_marker'],0x23CB)
  self.assertEqual(b['software_tx_frames'],['6df0187444'])
  self.assertFalse(b['live_write_enabled'])
 def test_conditional_park_and_ram_identity(self):
  c=self.report['conditional_application']
  self.assertEqual(c['stop_pc'],'0xbe78c')
  self.assertEqual(c['marker'],'0xbfc1')
  self.assertEqual(c['interrupt_mask'],7)
  self.assertEqual(c['park_iterations'],8)
  self.assertEqual(c['watchdog_stores_during_park'],0)
  self.assertFalse(c['reset_observed'])
  for continuation in self.report['conditional_resets']:
   boot=continuation['boot']
   self.assertTrue(continuation['reset_injected'])
   self.assertEqual(boot['initial_ram_sha256'],c['ram_sha256'])
   self.assertEqual(boot['initial_ram_sha256'],continuation['source_ram_sha256'])
   self.assertEqual(boot['retained_marker'],0xBFC1)
   self.assertEqual(boot['events'],[])
   if boot['reset_status']&0xC0:
    self.assertEqual(boot['stop'],'application_transfer_boundary')
    self.assertEqual(boot['software_tx_frames'],[])
   else:
    self.assertEqual(boot['stop'],'before_synthetic_irq_rte')
    self.assertEqual(boot['reset_marker'],0xB094)
    self.assertEqual([(o['phase'],o['frame']) for o in boot['software_tx_observations']],
                     [('native_startup','6cf0187444'),('synthetic_irq','6df0187444')])
   self.assertTrue(boot['rom_unchanged_from_selected_view'])
   self.assertEqual(boot['flash_writes_blocked'],0)
   self.assertFalse(boot['live_write_enabled'])
 def test_locked_and_input_boundaries(self):
  c=self.report['locked_application']
  self.assertEqual(c['storage_calls'],[])
  self.assertEqual(c['park_iterations'],0)
  self.assertEqual(c['negative_helper_calls'][0]['reason'],0x33)
  for ram in (bytes(0x37FF),bytes(0x3801),bytearray(0x3800)):
   with self.assertRaises(ValueError):experiment(*self.inputs,initial_ram=ram)
  with self.assertRaises(ValueError):experiment(*self.inputs,initial_ram=bytes(0x3800),retained_marker=0xBFC1)
  for flag in ('entry_physically_proven','reset_physically_proven','storage_preservation_proven','ready_to_flash','live_upload_enabled','live_execution_enabled','live_write_enabled'):
   self.assertFalse(self.report[flag])
  self.assertEqual(self.report['would_send'],[])

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('low','high'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();ChainTests.inputs=(a.low.read_bytes(),a.high.read_bytes())
 unittest.main(argv=[__file__])
