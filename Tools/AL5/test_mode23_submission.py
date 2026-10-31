import json
from pathlib import Path
import unittest
from emulate_mode23_submission import analyze


class SubmissionTests(unittest.TestCase):
    def test_identity_gate(self):
        with self.assertRaisesRegex(ValueError,'Firmware identity changed'):
            analyze(b'wrong image')

    def test_saved_submission_is_not_completion(self):
        r=json.loads((Path(__file__).resolve().parents[2]/'Docs/AL5/MODE23_SUBMISSION_20261030.json').read_text())
        self.assertEqual(3,len(r['cases']))
        for c in r['cases'][:2]:
            self.assertEqual([],c['register_reads'])
            self.assertEqual(20,len(c['register_writes']))
            self.assertEqual(['0xffffe800',0x14],c['register_writes'][0])
            self.assertEqual(['0xffffe800',0x0c],c['register_writes'][-2])
            self.assertEqual(0,c['tx_count_after'])
            self.assertFalse(c['hardware_completion_observed'])
        self.assertEqual(r['cases'][0]['register_writes'],r['cases'][1]['register_writes'])
        for field in ('pending_preserved','response_body_preserved','receive_record_preserved'):
            self.assertTrue(r['cases'][2][field])
        for field in ('session_boundary_proven','live_read_enabled','live_write_enabled'):
            self.assertFalse(r[field])


if __name__=='__main__':unittest.main()
