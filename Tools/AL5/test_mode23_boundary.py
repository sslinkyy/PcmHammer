import json
from pathlib import Path
import unittest
from emulate_mode23_boundary import analyze


class BoundaryTests(unittest.TestCase):
    def test_identity_rejected_before_emulator_import(self):
        with self.assertRaisesRegex(ValueError,'Firmware identity changed'):
            analyze(b'wrong firmware')

    def test_saved_native_results_do_not_claim_a_boundary(self):
        report=json.loads((Path(__file__).resolve().parents[2]/'Docs/AL5/MODE23_BOUNDARY_20261030.json').read_text())
        cases={c['case']:c for c in report['cases']}
        self.assertEqual(8,len(cases))
        self.assertEqual(65,cases['native_pending_priority_and_eligibility']['first_selected'])
        self.assertEqual(0xffff,cases['native_pending_priority_and_eligibility']['ineligible_selection'])
        self.assertEqual([1,10,0],cases['native_queue_advance']['returned_offsets'])
        self.assertEqual(1,cases['native_queue_wrap']['returned_offset'])
        first=cases['empty_receive_preserves_pending']['observed']
        self.assertEqual('10',first['pending'])
        staged=cases['empty_receive_and_clear_pending_still_have_tx_bytes']['observed']
        self.assertEqual('00',staged['pending'])
        self.assertEqual('6cf01863fffcbfd0e1f2',staged['tx'])
        for field in ('session_boundary_proven','live_read_enabled','live_write_enabled'):
            self.assertFalse(report[field])


if __name__=='__main__':unittest.main()
