import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from audit_pccs_lct_checksum_ranges import audit, inspect_range, main, parse_s2


def s2(address, payload):
    fields = bytes([len(payload)+4])+address.to_bytes(3, 'big')+payload
    return b'S2'+(fields+bytes([(~sum(fields)) & 255])).hex().upper().encode()


class PccsLctChecksumRangeTests(unittest.TestCase):
    def test_source_pin_checked_before_parser(self):
        with patch('audit_pccs_lct_checksum_ranges.parse_s2') as parser:
            for variant in ('u2a', 'df9', 'another'):
                with self.assertRaises(ValueError):
                    audit(b'changed', variant)
            parser.assert_not_called()

    def test_strict_records_and_unique_mapping(self):
        record = s2(0x123456, b'\x01\x02\x03')
        memory, records = parse_s2(record+b'\r\n'+s2(0xABCDEF, b'\x99'))
        self.assertEqual(records, 2)
        self.assertEqual(memory[0x123458], 3)
        self.assertEqual(memory[0xABCDEF], 0x99)
        for data in (record+b'\n'+record, record[:-2]+b'00', b'S21400',
                     b'S0'+record[2:], b' '+record, b'', s2(0xFFFFFF, b'\0\0')):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_s2(data)

    def test_crc_and_sum_each_required(self):
        # CRC('123456789')=BB3D; use an even body for the BE16 sum.
        body = b'123456789\0'
        from checksum import crc16
        crc = crc16(body)
        total = sum(int.from_bytes(body[i:i+2], 'big') for i in range(0, len(body), 2))
        field = crc.to_bytes(2, 'big')+((-total-crc) & 0xFFFF).to_bytes(2, 'big')
        memory = dict(enumerate(body+field, 0x8000))
        result = inspect_range(memory, 0x8000, 0x8000+len(body)+4)
        self.assertTrue(result['crc_matches'])
        self.assertTrue(result['compensation_matches'])
        self.assertEqual(result['whole_be16_sum'], 0)
        memory[0x8000] ^= 1
        changed = inspect_range(memory, 0x8000, 0x8000+len(body)+4)
        self.assertFalse(changed['crc_matches'])
        self.assertFalse(changed['compensation_matches'])

    def test_missing_bytes_never_filled(self):
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            inspect_range({0: 0, 1: 0, 3: 0}, 0, 4)
        for start, end in ((-1, 3), (0, 3), (0, 5), (True, 5), (0, 0x1000002)):
            with self.assertRaises(ValueError):
                inspect_range({}, start, end)

    def test_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'source'
            path.write_bytes(b'keep')
            with patch('sys.argv', ['tool', str(path), '--variant', 'u2a', '--output', str(path)]), \
                    patch('sys.stderr'), patch('audit_pccs_lct_checksum_ranges.audit') as runner, \
                    self.assertRaises(SystemExit):
                main()
            runner.assert_not_called()
            self.assertEqual(path.read_bytes(), b'keep')

    @unittest.skipUnless(os.environ.get('AL5_LCT_S2_DIR'), 'Set AL5_LCT_S2_DIR for pinned images')
    def test_both_pinned_images_keep_variant_ranges_separate(self):
        expected = {'u2a': (0x15FD4, '1e0ca374', 36869),
                    'df9': (0x1903C, '8ddc468f', 41551)}
        for variant, (address, stored, records) in expected.items():
            report = audit((Path(os.environ['AL5_LCT_S2_DIR'])/(variant+'.s2')).read_bytes(), variant)
            calibration = report['calibration']
            self.assertEqual(calibration['candidate_crc_address'], address)
            self.assertEqual(calibration['stored_field_hex'], stored)
            self.assertEqual(report['s2_records'], records)
            self.assertTrue(calibration['crc_matches'])
            self.assertTrue(calibration['compensation_matches'])
            self.assertEqual(calibration['whole_be16_sum'], 0)
            self.assertEqual(calibration['candidate_readback_range']['bytes'], 4)
            self.assertTrue(all(v is None for v in report['symbol_bindings'].values()))
            self.assertFalse(report['symbol_equivalence_proven'])
            self.assertFalse(report['live_write_enabled'])
            self.assertFalse(report['ready_to_flash'])
            self.assertEqual(report['would_send'], [])


if __name__ == '__main__':
    unittest.main()
