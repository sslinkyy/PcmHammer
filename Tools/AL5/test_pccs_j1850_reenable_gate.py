import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_j1850_reenable_gate as gate


class J1850ReenableGateTests(unittest.TestCase):
    def test_pin_before_layout(self):
        with self.assertRaisesRegex(ValueError, 'pin changed'):
            gate.run(b'wrong source')

    def test_pc_coverage(self):
        self.assertTrue(gate.permitted_pc(gate.START, 1))
        for address, size in ((gate.START-1, 1), (gate.ENABLE-1, 2), (gate.ENABLE, 1), (gate.SKIP, 1), (gate.START, 0)):
            self.assertFalse(gate.permitted_pc(address, size))

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
    def test_native_protocol_branches(self):
        report = gate.audit(Path(os.environ['AL5_PCCS_EXE']).read_bytes())
        self.assertEqual(len(report['cases']), 4)
        for case in report['cases']:
            protocol = case['context']['protocol']
            skip = protocol in ('J1850', 'XCP_ETHERNET')
            self.assertEqual(case['reaches_programming_enable_block'], not skip)
            self.assertEqual(case['stopped_before'], hex(gate.SKIP if skip else gate.ENABLE))
            literals = ['J1850'] if protocol == 'J1850' else ['J1850', 'XCP_ETHERNET']
            self.assertEqual(case['synthetic_comparisons'], [dict(literal=p, equal=protocol == p, synthetic=True) for p in literals])
            self.assertTrue(case['earlier_event_state_assumed'])
            for field in ('control_setters_executed', 'complete_event_executed', 'actual_ui_state_proven', 'transport_used', 'live_write_enabled', 'ready_to_flash'):
                self.assertFalse(case[field])
            self.assertEqual(case['would_send'], [])

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned PCCS and Unicorn')
    def test_context_guards(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        for protocol in (None, [], True, 'j1850', 'unknown'):
            with self.assertRaises(ValueError):
                gate.run(data, protocol=protocol)


if __name__ == '__main__':
    unittest.main()
