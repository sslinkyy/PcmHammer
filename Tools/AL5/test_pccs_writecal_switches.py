import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_writecal_switches as switches


class WriteCalSwitchTests(unittest.TestCase):
    def test_pin_before_layout(self):
        for operation in (switches.run, switches.audit, switches.inspect_switches):
            with self.assertRaisesRegex(ValueError, 'pin changed'):
                operation(b'wrong source')

    def test_pc_coverage(self):
        for phase, s in switches.SWITCHES.items():
            self.assertTrue(switches.permitted_pc(phase, s['start'], 1))
            for address, size in ((s['start']-1, 1), (s['end']-1, 2), (s['end'], 1), (s['start'], 0)):
                self.assertFalse(switches.permitted_pc(phase, address, size))

    def test_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', 'missing.exe', '--output', str(output)]), patch.object(switches, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    switches.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned PCCS and Unicorn')
    def test_native_exhaustive_selectors(self):
        report = switches.audit(Path(os.environ['AL5_PCCS_EXE']).read_bytes())
        self.assertEqual(report['selector_coverage'], dict(inputs_per_switch=256, switches=3, cases=768))
        expected_a = {2: 0x7c4faf, 3: 0x7c4f14, 4: 0x7c4f25, 5: 0x7c4f36, 6: 0x7c4f47,
                      7: 0x7c4f58, 10: 0x7c4f77, 11: 0x7c4f69, 15: 0x7c4f85,
                      22: 0x7c4f93, 23: 0x7c4fa1}
        expected_c = {3: 0x7c5bc4, 8: 0x7c5c45, 10: 0x7c5be6, 11: 0x7c5bd8, 15: 0x7c5c29, 22: 0x7c5c37}
        self.assertEqual(report['layouts']['status_c']['remap_indexes'], [0, 0, 0, 1, 0, 0, 0, 0, 6, 0, 3, 2, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 5])
        for case in report['cases']:
            phase, value = case['context']['phase'], case['context']['input']
            if phase == 'status_a':
                expected = expected_a.get(value&127, 0x7c4fbd)
            elif phase == 'status_c':
                expected = expected_c.get(value&127, 0x7c5c53)
            else:
                expected = 0x7c596b if 1 <= value <= 6 else {0: 0x7c595c, 7: 0x7c598a, 8: 0x7c5999, 9: 0x7c59a8}.get(value, 0x7c59b7)
            self.assertEqual(case['destination'], hex(expected))
            self.assertGreater(case['native_instructions'], 0)
            for field in ('destination_executed', 'callees_executed', 'complete_writecal_executed', 'address_conversion_proven', 'programming_bypass_proven', 'transport_used', 'live_write_enabled', 'ready_to_flash'):
                self.assertFalse(case[field])
            self.assertEqual(case['would_send'], [])

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned PCCS and Unicorn')
    def test_context_guards(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        for context in ({'phase': []}, {'phase': 'other'}, {'value': True}, {'value': -1}, {'value': 256}):
            with self.assertRaises(ValueError):
                switches.run(data, **context)


if __name__ == '__main__':
    unittest.main()
