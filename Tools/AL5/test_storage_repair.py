"""Repair evidence must retain destructive side effects and readiness blockers."""
import json
import unittest
from pathlib import Path
from al5_segment import sha256
from test_offline import fixture
from write_plan import plan


class StorageRepairTests(unittest.TestCase):
    def test_repair_does_not_establish_surviving_context_preservation(self):
        data = fixture()
        result = plan(data, data, sha256(data), 'AL5', 15184109)
        evidence = result['boot_preparation_assessment']['storage_repair_evidence']
        path = Path(__file__).resolve().parents[2]/evidence['evidence']
        self.assertEqual(sha256(path.read_bytes()), evidence['evidence_sha256'])
        report = json.loads(path.read_text(encoding='utf8'))
        self.assertTrue(report['all_pass'])
        self.assertEqual(4, len(report['interrupted_update_repair_cases']))
        for case in report['interrupted_update_repair_cases']:
            observed = case['observed']
            self.assertEqual('0xaa', observed['selected_state'])
            self.assertTrue(all(b['context_erased'] and b['tail_erased'] for b in observed['bank_metadata']))
        self.assertFalse(evidence['surviving_commit_establishes_safe_repair'])
        self.assertFalse(evidence['physical_recovery_verified'])
        self.assertFalse(evidence['flash_implementation_executed'])
        self.assertFalse(result['ready_to_flash'])
        self.assertFalse(result['live_write_enabled'])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send', 'erase_packets', 'program_packets'):
            self.assertEqual([], result[key])

    def test_error_branches_and_generation_wrap_remain_visible(self):
        root = Path(__file__).resolve().parents[2]
        report = json.loads((root/'Docs/AL5/STORAGE_REPAIR_EMULATION.json').read_text(encoding='utf8'))
        for case in report['wrapper_error_cases']:
            expected_marker = '0x6124' if case['synthetic_status_byte'] == '0x20' else '0x0'
            self.assertEqual(expected_marker, case['observed']['marker'])
        wrap = next(c for c in report['repair_cases'] if c['case'] == 'generation_wrap')
        self.assertEqual([0xFFFF, 0], [b['generation_word'] for b in wrap['observed']['bank_metadata']])


if __name__ == '__main__': unittest.main()
