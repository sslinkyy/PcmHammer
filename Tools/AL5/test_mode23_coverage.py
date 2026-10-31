import json
from pathlib import Path
import unittest
from emulate_mode23_coverage import Probe,HIGH_HASH


class CoverageTests(unittest.TestCase):
    def test_saved_native_coverage_and_bounds(self):
        r=json.loads((Path(__file__).resolve().parents[2]/'Docs/AL5/MODE23_COVERAGE_20261030.json').read_text())
        self.assertEqual(HIGH_HASH,r['firmware_sha256'])
        self.assertEqual(10250,r['supplemental_dwords_checked']);self.assertEqual([],r['rejected_addresses'])
        for a in ('0x15fd8','0x1fffc','0xffffc'):self.assertTrue(r['boundary_permissions'][a])
        for a in ('0xffffd','0x100000','0x3fd8','0xc4c64'):self.assertFalse(r['boundary_permissions'][a])
        self.assertEqual(r['handler_samples'][0]['response_body'],r['handler_samples'][1]['response_body'])
        self.assertEqual([0x31],r['handler_samples'][-1]['negative_reasons'])
        self.assertFalse(r['live_read_enabled']);self.assertFalse(r['live_write_enabled'])

    def test_changed_firmware_fails_before_emulation(self):
        # Reject before importing Unicorn or allocating emulator memory.
        with self.assertRaisesRegex(ValueError,'Firmware identity changed'):
            Probe(b'changed')

if __name__=='__main__':unittest.main()
