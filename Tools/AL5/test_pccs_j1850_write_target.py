import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_j1850_write_target as target


class J1850WriteTargetTests(unittest.TestCase):
    def test_pin_before_layout(self):
        with self.assertRaisesRegex(ValueError, 'pin changed'):
            target.run(b'wrong source')

    def test_pc_coverage(self):
        for phase, (start, end) in target.RANGES.items():
            self.assertTrue(target.permitted_pc(phase, start, 1))
            for address, size in ((start-1, 1), (end-1, 2), (end, 1), (start, 0)):
                self.assertFalse(target.permitted_pc(phase, address, size))

    def test_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', 'missing.exe', '--output', str(output)]), patch.object(target, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    target.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned PCCS and Unicorn')
    def test_native_handoffs(self):
        report = target.audit(Path(os.environ['AL5_PCCS_EXE']).read_bytes())
        self.assertEqual([c['selected'] for c in report['cases']], [0, 3, 0x18, 255, 0x103])
        for case in report['cases']:
            selected = case['selected']
            self.assertFalse(case['continuous_execution'])
            caller = case['caller']
            self.assertEqual(caller['pending_arguments'], [0, 0, selected, 256])
            self.assertEqual(caller['source_bound_virtual_target'], '0x5b487c')
            self.assertEqual(len(case['forwards']), 3)
            for forward in case['forwards']:
                self.assertEqual(forward['pending_arguments'], [selected&255, int(forward['context']['wait_field'] != 0)])
                self.assertEqual(forward['pending_registers'], dict(eax=target.THIS, edx=5, ecx=500))
                self.assertEqual(forward['source_bound_virtual_target'], '0x724668')
            for stage in [caller, *case['forwards']]:
                for field in ('full_writer_executed', 'virtual_call_executed', 'mapping_before_slice_proven', 'programming_reachability_proven', 'transport_used', 'live_write_enabled', 'ready_to_flash'):
                    self.assertFalse(stage[field])
                self.assertEqual(stage['would_send'], [])
            envelope = case['synthetic_envelope_handoff']
            self.assertEqual(bytes.fromhex(envelope['constructed_buffer_hex']), bytes([1, 0x8c, selected&255, 0xf1, 0x10, 0x10]))
            self.assertFalse(envelope['send_call_executed'])

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned PCCS and Unicorn')
    def test_context_guards(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        for context in ({'phase': []}, {'phase': 'other'}, {'selected': True}, {'selected': -1}, {'selected': 0x100000000}, {'wait_field': None}):
            with self.assertRaises(ValueError):
                target.run(data, **context)


if __name__ == '__main__':
    unittest.main()
