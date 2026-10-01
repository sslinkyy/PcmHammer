"""A valid CRC and modeled commit do not establish complete context recovery."""
import json
import unittest
from pathlib import Path
from al5_segment import sha256
from test_offline import fixture
from write_plan import plan


class PendingHelpersTests(unittest.TestCase):
    def test_sentinel_dependent_context_can_have_valid_crc_and_modeled_commit(self):
        data = fixture()
        result = plan(data, data, sha256(data), 'AL5', 15184109)
        evidence = result['boot_preparation_assessment']['pending_helpers_evidence']
        path = Path(__file__).resolve().parents[2]/evidence['evidence']
        self.assertEqual(sha256(path.read_bytes()), evidence['evidence_sha256'])
        report = json.loads(path.read_text(encoding='utf8'))
        self.assertTrue(report['all_pass'])
        for case in report['cases']:
            self.assertTrue(case['observed']['banks_unchanged'])
            self.assertTrue(case['observed']['crc_word_untouched'])
            self.assertEqual(12, len(case['observed']['remaining_helpers_executed']))
            persistence = case['preparation_and_modeled_commit']
            self.assertTrue(persistence['prepared_context_crc_matches'])
            self.assertTrue(persistence['modeled_committed_context_matches_prepared'])
            self.assertFalse(persistence['real_storage_implementation_executed'])
        for comparison in report['sentinel_comparisons']:
            self.assertEqual(500, comparison['sentinel_sensitive_bytes'])
            self.assertEqual(91, comparison['written_but_sentinel_sensitive_bytes'])
            self.assertTrue(comparison['prepared_contexts_differ_despite_matching_crcs'])
        for key in ('complete_context_initialization_verified', 'context_persistence_verified', 'physical_recovery_verified'):
            self.assertFalse(evidence[key])
        self.assertFalse(result['ready_to_flash'])
        self.assertFalse(result['live_write_enabled'])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send', 'erase_packets', 'program_packets'):
            self.assertEqual([], result[key])


if __name__ == '__main__': unittest.main()
