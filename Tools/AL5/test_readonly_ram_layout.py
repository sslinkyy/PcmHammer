import unittest
from readonly_ram_layout import audit
from emulate_readonly_runtime import Runtime
class LayoutTests(unittest.TestCase):
 def test_layout_requires_exclusive_handoff_and_never_claims_physical_ownership(self):
  r=audit(1166);self.assertTrue(r['candidate_layout_nonoverlapping']);self.assertTrue(r['requires_exclusive_handoff'])
  self.assertEqual(1166,r['captured_sps_code_overlap_bytes']);self.assertFalse(r['physical_ram_ownership_proven']);self.assertFalse(r['live_upload_enabled'])
 def test_out_of_bounds_code_fails(self):
  for size in (-1,0,4096,100000):
   with self.assertRaises(ValueError):audit(size)
 def test_wrong_runtime_identity_rejected_before_emulator_allocation(self):
  with self.assertRaises(ValueError):Runtime(b'bad',{'code_sha256':'0'*64})
if __name__=='__main__':unittest.main()
