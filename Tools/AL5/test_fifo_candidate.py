"""Candidate comparisons cannot turn synthetic receive evidence into write readiness."""
import json
from pathlib import Path
import unittest
from al5_segment import sha256
from audit_fifo_candidate import conditional_window, run
from test_offline import fixture
from write_plan import plan

ROOT = Path(__file__).resolve().parents[2]


class FifoCandidateTests(unittest.TestCase):
    def test_unknown_loader_rejected_before_emulation(self):
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            run(b'unknown')

    def test_saved_comparison_exposes_read_past_completion(self):
        report = json.loads((ROOT / 'Docs/AL5/FIFO_CANDIDATE_COMPARISON.json').read_bytes())
        for key, path in (
            ('generator_sha256', 'Tools/AL5/audit_fifo_candidate.py'),
            ('startup_evidence_sha256', 'Docs/AL5/STARTUP_CONTEXT_STATIC_EVIDENCE.json'),
            ('loader_static_evidence_sha256', 'Docs/AL5/CAPTURED_LOADER_STATIC.json')):
            self.assertEqual(sha256((ROOT / path).read_bytes()), report[key])
        comparison = report['receive_comparison']
        self.assertFalse(comparison['completion_order_resolved'])
        self.assertEqual('dispatcher_trap', comparison['synthetic_control']['stop'])
        self.assertEqual('read_after_supplied_completion', comparison['isolated_literal_candidate']['stop'])
        following = comparison['following_frame_literal_candidate']
        self.assertEqual('receive_boundary', following['stop'])
        self.assertEqual(6, following['maximum_frame_bytes'])
        self.assertEqual([0x6D], following['completion_flags'])
        self.assertEqual(0, following['dispatch_boundaries'])
        self.assertEqual(0, following['mmio_instructions_executed'])
        self.assertFalse(following['reset_instruction_executed'])
        self.assertEqual(conditional_window(0xFFE8, 0xD820), report['conditional_sim_window'])
        self.assertEqual('0xffe800', report['conditional_sim_window']['start'])
        self.assertEqual(1, report['conditional_sim_window']['mode'])

    def test_planner_stays_blocked_despite_candidate_match(self):
        data = fixture()
        result = plan(data, data, sha256(data), 'AL5', 15184109)
        evidence = result['existing_trace_assessment']['fifo_candidate_assessment']
        self.assertEqual(sha256((ROOT / evidence['evidence']).read_bytes()), evidence['evidence_sha256'])
        for key in ('completion_order_resolved', 'physical_fifo_contract_verified',
                    'physical_address_aliasing_verified'):
            self.assertFalse(evidence[key])
        self.assertFalse(result['ready_to_flash'])
        self.assertFalse(result['live_write_enabled'])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send', 'erase_packets', 'program_packets'):
            self.assertEqual([], result[key])


if __name__ == '__main__':
    unittest.main()
