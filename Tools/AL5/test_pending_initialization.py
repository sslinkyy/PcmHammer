"""Partial initialization coverage must not waive context/recovery blockers."""
import json
import unittest
from pathlib import Path
from al5_segment import sha256
from test_offline import fixture
from write_plan import plan


class PendingInitializationTests(unittest.TestCase):
    def test_unwritten_context_and_crc_remain_explicitly_unverified(self):
        data = fixture()
        result = plan(data, data, sha256(data), 'AL5', 15184109)
        evidence = result['boot_preparation_assessment']['pending_initialization_evidence']
        path = Path(__file__).resolve().parents[2]/evidence['evidence']
        self.assertEqual(sha256(path.read_bytes()), evidence['evidence_sha256'])
        report = json.loads(path.read_text(encoding='utf8'))
        self.assertTrue(report['all_pass'])
        pending = [c for c in report['cases'] if c['operation'] == 'pending_caller']
        self.assertEqual(2, len(pending))
        for case in pending:
            observed = case['observed']
            self.assertTrue(observed['banks_unchanged'])
            self.assertTrue(observed['crc_word_untouched'])
            self.assertTrue(observed['untouched_bytes_retain_sentinel'])
            self.assertEqual(526, sum(i['bytes'] for i in observed['untouched_intervals']))
            self.assertNotEqual(observed['stored_crc'], observed['computed_crc'])
        self.assertEqual(pending[0]['observed']['written_intervals'], pending[1]['observed']['written_intervals'])
        self.assertFalse(evidence['complete_context_initialization_verified'])
        self.assertFalse(evidence['physical_recovery_verified'])
        self.assertFalse(result['ready_to_flash'])
        self.assertFalse(result['live_write_enabled'])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send', 'erase_packets', 'program_packets'):
            self.assertEqual([], result[key])


if __name__ == '__main__': unittest.main()
