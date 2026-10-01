"""Preparation evidence cannot waive preservation or emit destructive packets."""
import unittest
from pathlib import Path
from al5_segment import sha256
from test_offline import fixture
from write_plan import plan


class PreparationSafetyTests(unittest.TestCase):
    def test_storage_side_effects_remain_a_separate_blocker(self):
        data = fixture()
        result = plan(data, data, sha256(data), 'AL5', 15184109)
        assessment = result['boot_preparation_assessment']
        self.assertTrue(assessment['offline_cases_pass'])
        root = Path(__file__).resolve().parents[2]
        self.assertEqual(sha256((root/assessment['evidence']).read_bytes()), assessment['evidence_sha256'])
        self.assertFalse(assessment['storage_geometry_verified'])
        self.assertFalse(assessment['current_storage_backup_supplied'])
        self.assertFalse(assessment['storage_implementation_executed'])
        self.assertFalse(assessment['calibration_only_backup_establishes_preservation'])
        self.assertTrue(any('persistent-storage' in blocker for blocker in result['blockers']))
        self.assertIsNone(result['erase_scope'])
        self.assertFalse(result['ready_to_flash'])
        self.assertFalse(result['live_write_enabled'])
        for key in ('would_send', 'erase_packets', 'program_packets'):
            self.assertEqual([], result[key])


if __name__ == '__main__': unittest.main()
