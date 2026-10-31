from pathlib import Path
import tempfile
import unittest
from audit_pccs_capture_prerequisites import audit


class CapturePrerequisitesTests(unittest.TestCase):
    def test_names_and_config_do_not_prove_support(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'Winrw32.exe').write_bytes(b'unknown build')
            (root/'Controller.ini').write_text('[Utility File]\nTransmission=Z:\\missing\\AppandCal_Utility.Fil\n[Utility File Correct Boot]\nTransmission=B47\n',encoding='cp1252')
            (root/'APPANDCAL_UTILITY.FIL').write_bytes(b'not a qualified utility')
            (root/'SPX1850.DLL').write_bytes(b'not a qualified driver')
            r=audit(root)
            self.assertFalse(r['known_analysis_build'])
            self.assertTrue(r['generic_appandcal_present'])
            self.assertEqual(['SPX1850.DLL'],r['spx1850_candidates'])
            ref=r['transmission_utility_references'][0]
            self.assertFalse(ref['configured_path_exists'])
            self.assertEqual(1,len(ref['same_basename_candidates']))
            self.assertFalse(ref['compatibility_proven'])
            self.assertEqual(1,len(r['transmission_utility_references']))
            self.assertEqual('B47',r['other_utility_settings'][0]['value'])
            self.assertFalse(r['qualified_al5_programming_route'])
            self.assertFalse(r['live_write_enabled'])

    def test_missing_inputs_fail_instead_of_reporting_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):audit(directory)


if __name__=='__main__':unittest.main()
