"""Receive-loop boundary observations remain distinct from physical FIFO proof."""
import json
from pathlib import Path
import unittest
from al5_segment import sha256
from emulate_loader_receive import experiment
from emulate_loader_parser import EXPECTED_SHA
from test_offline import fixture
from write_plan import plan

ROOT = Path(__file__).resolve().parents[2]


class LoaderReceiveTests(unittest.TestCase):
    def test_unknown_loader_rejected(self):
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            experiment(b'unknown loader', [])

    def test_saved_boundaries_budget_refresh_and_flag_rejection(self):
        report = json.loads((ROOT / 'Docs/AL5/LOADER_RECEIVE_EMULATION.json').read_text())
        self.assertEqual(EXPECTED_SHA, report['payload_sha256'])
        self.assertEqual(sha256((ROOT / 'Tools/AL5/emulate_loader_receive.py').read_bytes()), report['generator_sha256'])
        self.assertEqual(11, len(report['cases']))
        self.assertTrue(report['all_pass'])
        cases = {c['case']: c['observed'] for c in report['cases']}
        for case in report['cases']:
            self.assertTrue(case['pass'])
            self.assertFalse(case['observed']['reset_instruction_executed'])
            self.assertEqual(0, case['observed']['mmio_instructions_executed'])
            for key, expected in case['expected'].items():
                self.assertEqual(expected, case['observed'][key])
        self.assertEqual(2, cases['two_byte_frame']['maximum_frame_bytes'])
        self.assertEqual(16, cases['model_buffer_limit_crossing']['maximum_frame_bytes'])
        self.assertEqual(254, cases['priority_6c_frame_budget']['dispatch_boundaries'])
        self.assertEqual(0, cases['priority_6c_frame_budget']['remaining_frame_budget'])
        self.assertEqual(256, cases['priority_6d_refreshes_budget']['dispatch_boundaries'])
        self.assertEqual(255, cases['priority_6d_refreshes_budget']['remaining_frame_budget'])
        for label in ('top_completion_error', 'middle_completion_error'):
            self.assertEqual(0, cases[label]['dispatch_boundaries'])
            self.assertEqual(255, cases[label]['remaining_frame_budget'])
        self.assertEqual(['0xff903c'], cases['idle_timeout_boundary']['counter_seeds_applied'])
        self.assertEqual(['0xff903c', '0xff906c'], cases['partial_frame_timeout_boundary']['counter_seeds_applied'])

    def test_plan_keeps_fifo_and_timeouts_unverified(self):
        data = fixture()
        result = plan(data, data, sha256(data), 'AL5', 15184109)
        evidence = result['existing_trace_assessment']['loader_receive_assessment']
        self.assertEqual(sha256((ROOT / evidence['evidence']).read_bytes()), evidence['evidence_sha256'])
        self.assertTrue(evidence['offline_cases_pass'])
        self.assertFalse(evidence['physical_fifo_contract_verified'])
        self.assertFalse(evidence['physical_timeout_verified'])
        self.assertFalse(result['ready_to_flash'])
        self.assertFalse(result['live_write_enabled'])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send', 'erase_packets', 'program_packets'):
            self.assertEqual([], result[key])


if __name__ == '__main__':
    unittest.main()
