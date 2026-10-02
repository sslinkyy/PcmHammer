"""Finalize sum and conditional sector evidence must not establish write readiness."""
import json
from pathlib import Path
import unittest
from al5_segment import sha256
from analyze_loader_geometry import analyze, finalize_sum_matches
from checksum import checksum_valid
from test_offline import fixture
from write_plan import plan


class LoaderGeometryTests(unittest.TestCase):
    def test_sum_guard_does_not_validate_native_crc(self):
        data = bytearray(fixture())
        self.assertTrue(finalize_sum_matches(data))
        self.assertTrue(checksum_valid(data))
        # Preserve the word sum while changing the data covered by the native CRC.
        data[0:2] = (1).to_bytes(2, 'big')
        data[2:4] = (65535).to_bytes(2, 'big')
        self.assertTrue(finalize_sum_matches(data))
        self.assertFalse(checksum_valid(data))
        for bad in (b'', b'\x00', b'\x00\x00\x00'):
            with self.assertRaises(ValueError):
                finalize_sum_matches(bad)
        self.assertFalse(finalize_sum_matches(b'\x00\x01'))

    def test_pointer_bounds_and_sector_overlap(self):
        low = bytearray(0x20000)
        low[0x8000:0x15FD8] = fixture()
        high = bytearray(0xE0000)
        high[0x46:0x4E] = bytes.fromhex('0000800000015fd7')
        result = analyze(low, high)
        self.assertEqual(57304, result['finalization']['bytes'])
        self.assertEqual('0x15fd6', result['finalization']['final_word_address'])
        self.assertFalse(result['finalization']['loader_recomputes_native_crc'])
        geometry = result['conditional_geometry']
        self.assertEqual(98304, geometry['total_bytes'])
        self.assertEqual(41000, geometry['outside_calibration_bytes'])
        self.assertEqual([32768, 24536], [s['calibration_bytes'] for s in geometry['sectors']])
        self.assertFalse(geometry['physical_sector_geometry_verified'])
        high[0x49] = 1
        with self.assertRaises(ValueError):
            analyze(low, high)
        with self.assertRaises(ValueError):
            analyze(low[:-1], high)

    def test_plan_links_saved_report_without_opening_gates(self):
        data = fixture()
        result = plan(data, data, sha256(data), 'AL5', 15184109)
        evidence = result['preservation_assessment']['datasheet_finalization_evidence']
        path = Path(__file__).resolve().parents[2] / evidence['evidence']
        self.assertEqual(sha256(path.read_bytes()), evidence['evidence_sha256'])
        saved = json.loads(path.read_text())
        static = Path(__file__).resolve().parents[2] / saved['static_evidence']
        self.assertEqual(sha256(static.read_bytes()), saved['static_evidence_sha256'])
        self.assertTrue(saved['finalization']['native_checksum_valid_in_saved_image'])
        self.assertEqual('4afc', saved['finalization']['saved_marker_word'])
        for key in ('physical_chip_identity_verified', 'physical_sector_geometry_verified',
                    'current_collateral_backup_verified'):
            self.assertFalse(evidence[key])
        self.assertFalse(result['ready_to_flash'])
        self.assertFalse(result['live_write_enabled'])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send', 'erase_packets', 'program_packets'):
            self.assertEqual([], result[key])


if __name__ == '__main__':
    unittest.main()
