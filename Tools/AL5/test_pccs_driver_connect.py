import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_driver_connect as connect


class DriverConnectTests(unittest.TestCase):
    def test_pin_before_layout(self):
        with self.assertRaisesRegex(ValueError, 'pin changed'):
            connect.run(b'not the executable')

    def test_execution_bounds(self):
        for phase, start, stop in (('connect', connect.CONNECT_START, connect.CONNECT_STOP),
                                   ('filter', connect.FILTER_START, connect.FILTER_STOP)):
            self.assertTrue(connect.permitted_pc(phase, start, 1))
            self.assertFalse(connect.permitted_pc(phase, stop-1, 2))
        for address in (connect.CONNECT, connect.COMMAND, 0x407a70, 0x5d4b8f):
            self.assertFalse(connect.permitted_pc('connect', address, 1))

    def test_write_ownership(self):
        self.assertTrue(connect.permitted_write('connect', connect.THIS+0x2c, 2))
        self.assertTrue(connect.permitted_write('filter', connect.THIS+0x528a4, 1))
        for phase in ('connect', 'filter'):
            for address, size in ((connect.THIS+8, 4), (connect.THIS+0x72d90, 1),
                                  (connect.THIS+0x528a4, 2), (connect.AUX, 4)):
                self.assertFalse(connect.permitted_write(phase, address, size))

    def test_existing_output_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', 'missing.exe', '--output', str(output)]), patch.object(connect, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    connect.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned local PCCS and Unicorn')
    def test_native_connect_matrix(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        report = connect.audit(data)
        self.assertEqual(len(report['cases']), 8)
        for case in report['cases']:
            context = case['context']
            success = 0 <= context['client_result'] < 128
            self.assertEqual(case['boundary'], 'pass_filter_command_returned' if success else 'client_rejected')
            self.assertEqual(case['connected_byte'], int(success))
            self.assertEqual(case['host_status'], 0 if success else 12)
            self.assertEqual(case['client_word'], context['client_result'] & 65535)
            self.assertEqual(len(case['calls']), 2 if success else 1)
            self.assertEqual(case['calls'][0]['protocol'], context['protocol'])
            if success:
                self.assertEqual(case['calls'][1]['command'], 3)
                self.assertEqual(case['calls'][1]['length'], 0)
                self.assertEqual(case['calls'][1]['return_value'], context['command_result'])
            self.assertFalse(case['filter_installation_proven'])
            self.assertTrue(case['driver_callbacks_synthetic'])
            self.assertTrue(case['independent_phase_handoff'])
            self.assertFalse(case['transport_used'])
            self.assertFalse(case['live_write_enabled'])
            self.assertFalse(case['ready_to_flash'])
            self.assertEqual(case['would_send'], [])
        for context in ({'protocol': []}, {'protocol': 'unknown'}, {'device': True},
                        {'client_result': 32768}, {'command_result': -32769}):
            with self.assertRaises(ValueError):
                connect.run(data, **context)


if __name__ == '__main__':
    unittest.main()
