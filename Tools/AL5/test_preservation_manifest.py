"""File coverage and hash identity must never stand in for physical preservation."""
import unittest
from al5_segment import sha256
from test_offline import fixture
from preservation_manifest import manifest


class PreservationManifestTests(unittest.TestCase):
    def test_calibration_only_binding_leaves_collateral_missing(self):
        data = fixture()
        result = manifest(data, data, sha256(data), sha256(data))
        self.assertEqual([], result['input_errors'])
        self.assertEqual(['conditional_sector_collateral', 'persistent_bank_region'], result['missing_components'])
        self.assertFalse(result['all_required_components_hash_bound'])

    def test_complete_synthetic_file_coverage_still_cannot_enable_writing(self):
        data = fixture(); collateral = bytes(41000); banks = bytes(0x4000)
        result = manifest(data, data, sha256(data), sha256(data), collateral=collateral,
                          expected_collateral_hash=sha256(collateral), persistent_banks=banks,
                          expected_persistent_hash=sha256(banks))
        self.assertTrue(result['all_required_components_hash_bound'])
        self.assertEqual([], result['missing_components'])
        for key in ('physical_chip_geometry_verified', 'current_backups_verified',
                    'collateral_preservation_verified', 'persistent_bank_preservation_verified',
                    'physical_recovery_verified', 'ready_to_flash', 'live_write_enabled'):
            self.assertFalse(result[key])
        self.assertFalse(result['completion_marker_inside_collateral']['planned_handling_verified'])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send', 'erase_packets', 'program_packets'):
            self.assertEqual([], result[key])

    def test_changed_candidate_hash_and_wrong_collateral_size_rejected(self):
        data = fixture()
        result = manifest(data, data, sha256(data), '0' * 64, collateral=b'\x00', expected_collateral_hash=sha256(b'\x00'))
        self.assertTrue(any('candidate_calibration: pinned hash mismatch' in e for e in result['input_errors']))
        self.assertTrue(any('41000 bytes' in e for e in result['input_errors']))

    def test_partial_hash_pairs_and_malformed_hash_rejected(self):
        data = fixture()
        for kwargs in ({'collateral': bytes(41000)}, {'expected_collateral_hash': 'a' * 64},
                       {'collateral': bytes(41000), 'expected_collateral_hash': 'bad'}):
            self.assertTrue(manifest(data, data, sha256(data), sha256(data), **kwargs)['input_errors'])


if __name__ == '__main__':
    unittest.main()
