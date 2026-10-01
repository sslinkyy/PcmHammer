"""Saved bank metadata must not imply preservation or authorize recovery."""
import json
import unittest
from storage_inventory import inspect, SIGNATURE, CONTEXT_SIZE
from checksum import crc16


class StorageInventoryTests(unittest.TestCase):
    def setUp(self):
        self.image = bytearray(0x4000)
        for offset, marker in ((0, 0xFFAA), (0x2000, 0xAA)):
            self.image[offset:offset+4] = SIGNATURE
            self.image[offset+0x28:offset+0x2A] = marker.to_bytes(2, 'big')
            context = bytes(CONTEXT_SIZE-2)
            self.image[offset+0x2A:offset+0x2A+CONTEXT_SIZE] = context+crc16(context).to_bytes(2, 'big')

    def test_complete_metadata_stays_non_executable_and_omits_contents(self):
        report = inspect(self.image, 0x4000)
        self.assertTrue(all(b['header_signature_matches'] and b['context_crc_matches'] for b in report['banks']))
        self.assertEqual(['committed', 'pending'], [b['marker_interpretation'] for b in report['banks']])
        for key in ('preservation_verified', 'current_physical_backup_verified', 'physical_geometry_verified', 'ready_to_flash', 'live_write_enabled'):
            self.assertFalse(report[key])
        self.assertEqual([], report['would_send'])
        self.assertNotIn('context_hex', json.dumps(report))

    def test_invalid_crc_and_signature_are_reported_separately(self):
        self.image[0] ^= 1
        self.image[0x2000+0x2A] ^= 1
        report = inspect(self.image, 0x4000)
        self.assertFalse(report['banks'][0]['header_signature_matches'])
        self.assertTrue(report['banks'][0]['context_crc_matches'])
        self.assertTrue(report['banks'][1]['header_signature_matches'])
        self.assertFalse(report['banks'][1]['context_crc_matches'])

    def test_wrong_origin_partial_and_calibration_only_images_rejected(self):
        for data, origin in ((self.image, 0), (self.image[:-1], 0x4000), (bytes(57304), 0), (self.image, 0x6000)):
            with self.assertRaises(ValueError): inspect(data, origin)


if __name__ == '__main__': unittest.main()
