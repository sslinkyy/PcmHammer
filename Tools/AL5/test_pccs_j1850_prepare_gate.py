import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_j1850_prepare_gate as gate


class J1850PreparationGateTests(unittest.TestCase):
    def test_pin_before_layout(self):
        with self.assertRaisesRegex(ValueError, 'pin changed'):
            gate.run(b'wrong source')

    def test_pc_bounds(self):
        self.assertTrue(gate.permitted_pc(gate.START, 1))
        for pc, size in ((gate.START-1, 1), (gate.END-1, 2), (gate.END, 1), (gate.START, 0)):
            self.assertFalse(gate.permitted_pc(pc, size))

    def test_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', 'missing.exe', '--output', str(output)]), patch.object(gate, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    gate.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned PCCS and Unicorn')
    def test_native_matrix(self):
        report = gate.audit(Path(os.environ['AL5_PCCS_EXE']).read_bytes())
        self.assertEqual(len(report['cases']), 24)
        for case in report['cases']:
            c = case['context']
            startup = bool(c['flag_144'] and not c['flag_158'])
            expected = 'startup_virtual_60' if startup else ('alternate_preparation' if c['alternate'] else 'ordinary_request_builder')
            self.assertEqual(case['boundary'], expected)
            callbacks = []
            if startup:
                if not c['flag_110']:
                    callbacks.append('state_preserving_virtual_44')
                callbacks.append('suppressed_delay_50')
                self.assertEqual(case['startup_call'], dict(slot='0x60', source_bound_target=hex(gate.STARTUP), dl=1, ecx=0, pending_stack_argument=1))
            else:
                self.assertIsNone(case['startup_call'])
            self.assertEqual(case['synthetic_callbacks'], callbacks)
            self.assertGreater(case['native_instructions'], 0)
            self.assertTrue(case['security_prerequisites_assumed'])
            for field in ('virtual_44_effects_proven', 'startup_executed', 'ordinary_builder_executed', 'alternate_preparation_executed', 'full_enter_write_executed', 'transport_used', 'live_write_enabled', 'ready_to_flash'):
                self.assertFalse(case[field])
            self.assertEqual(case['would_send'], [])

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned PCCS and Unicorn')
    def test_context_guards(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        for context in ({'flag_144': True}, {'flag_158': -1}, {'flag_110': 256}, {'alternate': '1'}):
            with self.assertRaises(ValueError):
                gate.run(data, **context)


if __name__ == '__main__':
    unittest.main()
