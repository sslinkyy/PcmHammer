import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_route_reset as reset


class RouteResetTests(unittest.TestCase):
    def test_source_pin_before_layout(self):
        with patch.object(reset, 'executable_sections') as layout:
            with self.assertRaisesRegex(ValueError, 'pin changed'):
                reset.run(b'changed')
            layout.assert_not_called()

    def test_context_before_emulator(self):
        data = b'context'
        with patch.object(reset, 'SOURCE_SHA256', hashlib.sha256(data).hexdigest()):
            for prior in (-1, 2, True, None):
                with self.subTest(prior=prior), self.assertRaises(ValueError):
                    reset.run(data, prior=prior)

    def test_pc_and_sparse_object_write_bounds(self):
        self.assertTrue(reset.permitted_pc(reset.START, 1))
        self.assertFalse(reset.permitted_pc(reset.STOP-1, 2))
        for offset in (0x68c60, 0xb4, 0xb5, 2047*0xa4+0xb4,
                       2047*0xa4+0xb5, 0x72564, 0x72d63):
            self.assertTrue(reset.permitted_write(reset.THIS+offset, 1))
        for offset in (0x68c61, 0xb3, 0xb6, 2048*0xa4+0xb4, 0x72d64):
            self.assertFalse(reset.permitted_write(reset.THIS+offset, 1))
        self.assertFalse(reset.permitted_write(reset.THIS+0xb4, 2))
        self.assertFalse(reset.permitted_write(reset.STACK+0xffff, 2))
        self.assertFalse(reset.permitted_write(reset.STACK, 0))

    def test_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep'
            output.write_bytes(b'keep')
            with patch('sys.argv', ['tool', 'missing', '--output', str(output)]), \
                    patch('sys.stderr'), patch.object(reset, 'audit') as runner, \
                    self.assertRaises(SystemExit):
                reset.main()
            runner.assert_not_called()
            self.assertEqual(output.read_bytes(), b'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'),
                         'requires local pinned PCCS and Unicorn')
    def test_native_reset_and_independent_selection(self):
        report = reset.audit(Path(os.environ['AL5_PCCS_EXE']).read_bytes())
        self.assertEqual(len(report['reset_cases']), 2)
        self.assertEqual(len(report['selection_compositions']), 8)
        for case in report['reset_cases']:
            self.assertEqual(case['final_route_flag'], 0)
            self.assertTrue(case['indexed_marker_pairs_zero'])
            self.assertTrue(case['auxiliary_bytes_zero'])
            self.assertEqual(case['object_write_observations'], 6145)
            self.assertFalse(case['identification_executed'])
            self.assertFalse(case['transport_used'])
            self.assertFalse(case['live_write_enabled'])
            self.assertEqual(case['would_send'], [])
        for case in report['selection_compositions']:
            context = case['context']
            before = case['selection_without_reset']['final_route_flag']
            after = case['selection_after_reset']['final_route_flag']
            self.assertEqual(before, 1)
            enabled = not context['disabled'] and (context['index'] != 3 or context['identity'] >= 16)
            self.assertEqual(after, int(enabled), context)
        self.assertFalse(report['ready_to_flash'])
        self.assertEqual(report['would_send'], [])


if __name__ == '__main__':
    unittest.main()
