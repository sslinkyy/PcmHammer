import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_vector_check as vector


class VectorCheckTests(unittest.TestCase):
    def test_pin_before_layout(self):
        with patch.object(vector, 'executable_sections') as layout:
            with self.assertRaisesRegex(ValueError, 'pin changed'):
                vector.run(b'changed')
            layout.assert_not_called()

    def test_context_validation(self):
        data = b'context'
        with patch.object(vector, 'SOURCE_SHA256', hashlib.sha256(data).hexdigest()):
            for context in ({'expected': bytes(1)}, {'observed': bytes(1)},
                            {'lengths': (256,)*4}, {'lengths': (257,)*5},
                            {'lengths': [256]*5}, {'lengths': (-1,)*5},
                            {'status': True}, {'status': 256}, {'prior_slow': 2},
                            {'prior_route': True}):
                with self.subTest(context=context), self.assertRaises(ValueError):
                    vector.run(data, **context)

    def test_bounds(self):
        self.assertTrue(vector.permitted_pc(vector.START, 1))
        self.assertFalse(vector.permitted_pc(vector.SUCCESS-1, 2))
        self.assertFalse(vector.permitted_pc(0x5d3311, 1))
        self.assertTrue(vector.permitted_write(vector.FLAG, 1))
        self.assertFalse(vector.permitted_write(vector.FLAG, 2))
        self.assertFalse(vector.permitted_write(vector.THIS+0x68c60, 1))
        self.assertFalse(vector.permitted_write(vector.STACK+0xffff, 2))

    def test_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'keep'
            path.write_bytes(b'keep')
            with patch('sys.argv', ['tool', 'missing', '--output', str(path)]), \
                    patch('sys.stderr'), patch.object(vector, 'audit') as audit, \
                    self.assertRaises(SystemExit):
                vector.main()
            audit.assert_not_called()
            self.assertEqual(path.read_bytes(), b'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'),
                         'requires local pinned PCCS and Unicorn')
    def test_native_match_mismatch_read_error_and_coverage(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        report = vector.audit(data)
        match, error, absent, short, *mismatches = report['cases']
        self.assertEqual(match['comparison_offsets'], list(range(0x410)))
        self.assertEqual(error['comparison_offsets'], [])
        self.assertEqual(absent['comparison_offsets'], list(range(0x400, 0x410)))
        self.assertEqual(short['vector_mismatch'], [])
        for case in (match, error, absent, short):
            self.assertEqual(case['stop_address'], hex(vector.SUCCESS))
            self.assertEqual(case['final_slow'], 0)
            self.assertEqual(case['synthetic_callbacks'], [])
        for case, offset in zip(mismatches, (0, 255, 256, 1024, 1039)):
            self.assertEqual(case['stop_address'], hex(vector.FAILURE))
            self.assertEqual(case['vector_mismatch'], [{'segment': 0x200+offset//256,
                             'byte_offset': offset%256, 'read_offset': offset}])
            self.assertEqual(case['final_slow'], 1)
            self.assertEqual([c['name'] for c in case['synthetic_callbacks']],
                             ['host_helper', 'format_coordinate', 'format_coordinate',
                              'concat_log_text', 'log_vector_failure', 'disable_control',
                              'update_fast_write_ui'])
        for case in report['cases']:
            self.assertEqual(case['final_route'], 1)
            self.assertFalse(case['transport_used'])
            self.assertFalse(case['read_executed'])
            self.assertFalse(case['live_write_enabled'])
            self.assertFalse(case['ready_to_flash'])
            self.assertEqual(case['would_send'], [])
        pattern = bytes((i*17+i//256) % 251 for i in range(0x500))
        patterned = vector.run(data, expected=pattern, observed=pattern[:0x410])
        self.assertEqual(patterned['vector_mismatch'], [])
        corrupted = bytearray(pattern)
        corrupted[257] ^= 1
        changed = vector.run(data, expected=bytes(corrupted), observed=pattern[:0x410])
        self.assertEqual(changed['vector_mismatch'][0]['read_offset'], 257)
        case = vector.run(data, prior_route=0, prior_slow=1)
        self.assertEqual((case['final_route'], case['final_slow']), (0, 1))


if __name__ == '__main__':
    unittest.main()
