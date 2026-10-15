import importlib.util
import os
from pathlib import Path
import struct
import unittest

from audit_lct_command_tables import (INITIALIZERS, STACK, TABLE_START, TABLE_END,
                                      audit, descriptors, permitted_pc,
                                      permitted_write, reconstruct, response_descriptors)


class LctTableTests(unittest.TestCase):
    def test_changed_source_refused_before_optional_import(self):
        with self.assertRaisesRegex(ValueError, 'hash differs'):
            reconstruct(b'not the pinned DLL')

    def test_execution_is_bounded_to_active_initializer(self):
        for start, end in INITIALIZERS:
            self.assertTrue(permitted_pc(start, start, end))
            self.assertTrue(permitted_pc(end-1, start, end))
            for pc in (start-1, end, 0x10008a0e, 0x10011521, 0):
                self.assertFalse(permitted_pc(pc, start, end))

    def test_writes_cannot_escape_private_tables_or_stack(self):
        for addr, size in ((TABLE_START, 4), (TABLE_END-1, 1), (STACK, 4)):
            self.assertTrue(permitted_write(addr, size))
        for addr, size in ((TABLE_START-1, 4), (TABLE_END-1, 2),
                           (STACK+0x10000, 1), (0x10001823, 4), (0, 4), (STACK, 0)):
            self.assertFalse(permitted_write(addr, size))

    def test_request_length_excludes_opaque_tail(self):
        raw = bytearray(88)
        struct.pack_into('<II', raw, 0, 0, 7000)
        raw[8:13] = bytes.fromhex('0412ffffff')
        raw[13:16] = bytes.fromhex('343637')
        row = descriptors(lambda address, count: raw, 0x10071228, 1)[0]
        self.assertEqual(row['internal_request_hex'], '12ffffff')
        self.assertEqual(row['timeout_parameter'], 7000)
        self.assertTrue(row['opaque_remaining_storage_hex'].startswith('343637'))
        self.assertNotIn('handler_address_candidate', row)

    def test_bad_storage_length_and_incomplete_row_rejected(self):
        raw = bytearray(88)
        raw[8] = 41
        with self.assertRaises(ValueError):
            descriptors(lambda a, c: raw, 0, 1)
        with self.assertRaises(ValueError):
            descriptors(lambda a, c: raw[:80], 0, 1)

    def test_response_layout_uses_registered_base_and_callback_offset(self):
        raw = bytearray(88)
        raw[41:44] = bytes.fromhex('025010')
        struct.pack_into('<I', raw, 80, 0x1000a783)
        row = response_descriptors(lambda a, c: raw, 0x10074038, 1)[0]
        self.assertEqual(row['match_prefix_hex'], '5010')
        self.assertEqual(row['handler_address_candidate'], '0x1000a783')
        raw[41] = 39
        with self.assertRaises(ValueError):
            response_descriptors(lambda a, c: raw, 0, 1)

    @unittest.skipUnless(os.environ.get('AL5_LCT_DLL') and importlib.util.find_spec('unicorn'),
                         'Set AL5_LCT_DLL and provide optional Unicorn for pinned real input')
    def test_real_initializers_and_catalog(self):
        result = audit(Path(os.environ['AL5_LCT_DLL']).read_bytes())
        self.assertEqual(len(result['tables']), 13)
        self.assertEqual(sum(len(t['rows']) for t in result['tables']), 135)
        self.assertEqual(len(result['initializers']), 15)
        self.assertTrue(all(r['returned_to_synthetic_exit'] for r in result['initializers']))
        startup = next(t for t in result['tables'] if t['selector'] == 1)['rows']
        self.assertEqual(startup[0]['internal_request_hex'], '221a6801')
        self.assertEqual(startup[14]['internal_request_hex'], '12ffffff')
        reset = next(t for t in result['tables'] if t['selector'] == 7)['rows']
        self.assertEqual(reset[12]['internal_request_hex'], 'ae01000020200000')
        self.assertEqual(reset[24]['internal_request_hex'], 'ae01000000000000')
        probe = next(t for t in result['tables'] if t['selector'] == 0)['rows']
        self.assertEqual([r['internal_request_hex'] for r in probe], ['31', '37', '35'])
        self.assertEqual(sum(len(t['rows']) for t in result['response_tables']), 127)
        reply = next(r for t in result['response_tables'] for r in t['rows']
                     if r['match_prefix_hex'] == '5010')
        self.assertEqual(reply['handler_address_candidate'], '0x1000a783')
        self.assertEqual(result['host_prefixes']['j1850'], '0300008c18f0')
        self.assertFalse(result['transport_used'])
        self.assertFalse(result['windows_apis_executed'])
        self.assertFalse(result['live_write_enabled'])
        self.assertFalse(result['ready_to_flash'])
        self.assertEqual(result['would_send'], [])


if __name__ == '__main__':
    unittest.main()
