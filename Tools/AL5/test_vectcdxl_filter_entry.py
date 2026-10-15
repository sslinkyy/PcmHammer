import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_vectcdxl_filter_entry as vector


class VectorFilterEntryTests(unittest.TestCase):
    def test_pin_before_layout(self):
        with self.assertRaisesRegex(ValueError, 'pin changed'):
            vector.run(b'not the DLL')

    def test_native_boundaries(self):
        for phase, start, stop in (('command', vector.COMMAND_START, vector.COMMAND_STOP),
                                   ('reset', vector.RESET_START, vector.RESET_STOP)):
            self.assertTrue(vector.permitted_pc(phase, start, 1))
            self.assertFalse(vector.permitted_pc(phase, stop-1, 2))
            self.assertFalse(vector.permitted_pc(phase, stop, 1))
        self.assertFalse(vector.permitted_pc('reset', vector.RESET_CALLBACK, 1))
        self.assertFalse(vector.permitted_pc('unknown', vector.COMMAND_START, 1))

    def test_existing_output_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', 'missing.dll', '--output', str(output)]), patch.object(vector, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    vector.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_VECTCDXL_DLL') and importlib.util.find_spec('unicorn'), 'requires pinned Vector DLL and Unicorn')
    def test_native_matrix(self):
        data = Path(os.environ['AL5_VECTCDXL_DLL']).read_bytes()
        report = vector.audit(data)
        self.assertEqual(len(report['cases']), 9)
        for case in report['cases']:
            ctx = case['context']
            if ctx['phase'] == 'command':
                self.assertEqual(case['result'], 0)
                self.assertEqual(case['boundary'], hex(vector.EXIT))
                self.assertEqual(case['instruction_count'], 5)
                self.assertFalse(case['command_arguments_read'])
                self.assertEqual(case['reset_requests'], [])
            else:
                first, second = ctx['reset_results']
                failed = (first & 65535) != 0 or (second & 65535) != 0
                self.assertEqual(case['boundary'], hex(vector.RESET_FAIL if failed else vector.RESET_STOP))
                self.assertEqual([r['selector'] for r in case['reset_requests']], [1] if first & 65535 else [1, 2])
            for key in ('filter_installation_proven', 'loaded_driver_identity_proven',
                        'transport_used', 'live_write_enabled', 'ready_to_flash'):
                self.assertFalse(case[key])
            self.assertEqual(case['would_send'], [])
        for context in ({'phase': []}, {'phase': 'unknown'}, {'command': True},
                        {'pointer': -1}, {'length': 2**32}, {'reset_results': [0, 0]},
                        {'reset_results': None}, {'reset_results': (0, True)}):
            with self.assertRaises(ValueError):
                vector.run(data, **context)


if __name__ == '__main__':
    unittest.main()
