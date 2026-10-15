import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_filter_commands as filters


class FilterCommandTests(unittest.TestCase):
    def test_pin_before_loading(self):
        with self.assertRaisesRegex(ValueError, 'pin changed'):
            filters.run(b'not the executable')

    def test_execution_bounds(self):
        self.assertTrue(filters.permitted_pc('identification', 'gate', filters.GATE_START, 7))
        self.assertTrue(filters.permitted_pc('enter_write', 'emitter', 0x5b88e2, 2))
        for mode, phase, address, size in (('identification', 'gate', filters.GATE_STOP-1, 2),
                                         ('enter_write', 'emitter', 0x5b8958, 2),
                                         ('unknown', 'gate', filters.GATE_START, 1),
                                         ('identification', 'unknown', filters.GATE_START, 1)):
            self.assertFalse(filters.permitted_pc(mode, phase, address, size))

    def test_write_bounds(self):
        self.assertTrue(filters.permitted_write(filters.STACK, 4))
        for address, size in ((filters.THIS+0x10, 4), (filters.THIS+0x528a4, 1),
                              (filters.STACK+0xffff, 2)):
            self.assertFalse(filters.permitted_write(address, size))

    def test_existing_output_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', 'missing.exe', '--output', str(output)]), patch.object(filters, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    filters.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned local PCCS and Unicorn')
    def test_native_filter_matrix(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        report = filters.audit(data)
        self.assertEqual(len(report['cases']), 7)
        for case in report['cases']:
            context = case['context']
            skipped = context['mode'] == 'identification' and context['target'] != 0xf3
            if skipped:
                self.assertEqual(case['identification_gate'], 'bypass_filter_block')
                self.assertEqual(case['commands'], [])
            else:
                self.assertEqual([c['command'] for c in case['commands']], [17, 5, 5])
                self.assertEqual(case['commands'][0]['length'], 0)
                self.assertEqual(case['commands'][1]['payload_hex'], '00000005f8000005e8')
                self.assertEqual(case['commands'][2]['payload_hex'], '010000f8ff0000f8'+format(context['target'], '02x'))
                self.assertTrue(case['driver_name_eligibility_assumed'])
                for command in case['commands']:
                    self.assertEqual(command['connection'], 0x3456)
                    self.assertEqual(command['synthetic_result'], context['command_result'])
            self.assertEqual(case['final_host_status'], 0)
            self.assertFalse(case['rp1210_callback_executed'])
            self.assertFalse(case['filter_installed'])
            self.assertFalse(case['transport_used'])
            self.assertEqual(case['would_send'], [])
        for context in ({'mode': []}, {'target': True}, {'target': 256}, {'command_result': -1}):
            with self.assertRaises(ValueError):
                filters.run(data, **context)


if __name__ == '__main__':
    unittest.main()
