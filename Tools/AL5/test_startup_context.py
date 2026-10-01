"""Cold RAM convergence cannot waive omitted startup or physical recovery."""
import json
import unittest
from pathlib import Path
from al5_segment import sha256
from test_offline import fixture
from write_plan import plan


class StartupContextTests(unittest.TestCase):
    def test_signed_clear_bounds_and_convergence_remain_separate_from_readiness(self):
        data = fixture()
        result = plan(data, data, sha256(data), 'AL5', 15184109)
        evidence = result['boot_preparation_assessment']['startup_context_evidence']
        path = Path(__file__).resolve().parents[2]/evidence['evidence']
        self.assertEqual(sha256(path.read_bytes()), evidence['evidence_sha256'])
        report = json.loads(path.read_text(encoding='utf8'))
        self.assertTrue(report['all_pass'])
        self.assertTrue(report['cold_context_independent_of_initial_fill'])
        self.assertTrue(report['prepared_context_independent_of_initial_fill'])
        for case in report['cases']:
            clear = case['observed']['startup_clear']
            self.assertEqual('0xff8140', clear['start'])
            self.assertEqual('0xffb7b0', clear['end_exclusive'])
            self.assertEqual(0x3670, clear['observed_unique_bytes_written'])
            self.assertTrue(clear['after_region_probe_unchanged'])
            self.assertTrue(clear['context_all_zero'])
            self.assertEqual(4, len(case['observed']['preamble_helpers_bypassed']))
            self.assertEqual(12, len(case['observed']['remaining_helpers_executed']))
            self.assertTrue(case['observed']['banks_unchanged'])
        for key in ('complete_startup_verified', 'context_persistence_verified', 'physical_recovery_verified'):
            self.assertFalse(evidence[key])
        self.assertFalse(result['ready_to_flash'])
        self.assertFalse(result['live_write_enabled'])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send', 'erase_packets', 'program_packets'):
            self.assertEqual([], result[key])


if __name__ == '__main__': unittest.main()
