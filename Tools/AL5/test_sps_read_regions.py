import unittest
from audit_sps_read_regions import layout,permission,analyze
from emulate_mode23_coverage import Probe
class RegionTests(unittest.TestCase):
 def test_coverage_keeps_permission_holes_and_does_not_claim_acquisition(self):
  r=layout();self.assertEqual(0x100000,sum(x['bytes'] for x in r));self.assertEqual(6,sum(x['permission_excluded_bytes'] for x in r))
  self.assertEqual(2,sum(len(x['aligned_dwords_rejected']) for x in r));self.assertTrue(all(not x['source_bytes_acquired'] for x in r))
 def test_full_dword_not_only_start_checked(self):
  for a in (0x3FD5,0x3FD8,0xC4C63,0xC4C64,0xC4C66,0xFFFFD,-1):self.assertFalse(permission(a))
  for a in (0x3FD4,0x3FDC,0xC4C62,0xC4C68,0xFFFFC):self.assertTrue(permission(a))
 def test_identity_fails_before_native_dependencies(self):
  with self.assertRaises(ValueError):analyze(bytes(679828),True)
  with self.assertRaises(ValueError):Probe(bytes(679828),source='sps_os')
  with self.assertRaises(ValueError):Probe(b'',source='unknown')
if __name__=='__main__':unittest.main()
