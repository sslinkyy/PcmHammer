"""Native preparation status/readback/stack semantics with no flash implementation."""
import argparse
import unittest
from pathlib import Path
from emulate_preparation_statuses import analyze,StatusTrace

class StatusTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.report=analyze(*cls.inputs);cls.cases={c['case']:c for c in cls.report['cases']}
 def test_success_returns_all_storage_wrappers_before_application_park(self):
  c=self.cases['success']
  self.assertEqual(c['stop_pc'],'0xbe78c');self.assertEqual(c['marker'],'0xbfc1')
  self.assertEqual(len(c['effects']),13)
  self.assertEqual(len(c['wrapper_frames']),7)
  self.assertTrue(all(f['returned'] for f in c['wrapper_frames']))
  self.assertEqual(c['bank_markers'],{'0x4000':'0000','0x6000':'ffaa'})
  self.assertEqual(c['source_context_sha256'],c['bank_context_sha256']['0x6000'])
  self.assertEqual(c['park_iterations'],8)
 def test_erase_error_status_is_followed_by_copy_not_checked_return(self):
  c=self.cases['erase_error_no_effect']
  self.assertEqual(c['stop_pc'],'0x22cf0');self.assertEqual(c['marker'],'0x0')
  self.assertTrue(c['banks_unchanged'])
  self.assertEqual(c['effects'][0]['status'],0x2000)
  self.assertEqual([f['returned'] for f in c['wrapper_frames']],[True,False])
  self.assertEqual(c['copied_implementation_calls'],[])
 def test_error_status_and_real_mismatch_both_park_with_pending_frames(self):
  for kind,stop in [('copy','0x22dbc'),('program','0x22cc2')]:
   for suffix in ('status_error','readback_mismatch'):
    c=self.cases[kind+'_'+suffix];effect=c['effects'][-1]
    self.assertEqual(c['stop_pc'],stop);self.assertEqual(c['marker'],'0x6124')
    self.assertEqual(c['error_park_iterations'],8);self.assertEqual(c['park_iterations'],0)
    self.assertTrue(all(f['returned'] for f in c['wrapper_frames'][:-1]))
    self.assertFalse(c['wrapper_frames'][-1]['returned'])
    self.assertEqual(c['bank_differences']['0x4000'],0)
    if suffix=='status_error':
     self.assertEqual(effect['status'],0x2000)
     self.assertEqual(effect['payload_sha256'],effect['written_sha256'])
    else:
     self.assertEqual(effect['status'],0)
     self.assertNotEqual(effect['payload_sha256'],effect['written_sha256'])
 def test_no_case_provides_physical_or_session_reuse_authority(self):
  for c in self.cases.values():
   self.assertFalse(c['flash_implementation_executed'])
   self.assertFalse(c['physical_flash_effects_proven'])
   self.assertFalse(c['physical_reset_proven'])
   self.assertFalse(c['remaining_pending_frames_reusable'])
   self.assertTrue(all(not r['flash_implementation_executed'] for r in c['copied_implementation_calls']))
  for flag in ('live_upload_enabled','live_execution_enabled','live_write_enabled','ready_to_flash','recovery_verified'):self.assertFalse(self.report[flag])
  self.assertEqual(self.report['would_send'],[])
  with self.assertRaises(ValueError):StatusTrace(*self.inputs,'unknown')

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('low','high'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();StatusTests.inputs=(a.low.read_bytes(),a.high.read_bytes())
 unittest.main(argv=[__file__])
