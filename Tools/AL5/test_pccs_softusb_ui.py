import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_softusb_ui as ui


class SoftusbUiTests(unittest.TestCase):
    def test_pin_before_layout(self):
        with self.assertRaisesRegex(ValueError, 'pin changed'):
            ui.run(b'wrong executable')

    def test_pc_bounds(self):
        self.assertTrue(ui.permitted_pc(ui.START, 3))
        self.assertFalse(ui.permitted_pc(ui.BYPASS-1, 2))
        self.assertFalse(ui.permitted_pc(ui.STOP, 1))
        self.assertFalse(ui.permitted_pc(ui.GETTER, 1))

    def test_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', 'missing.exe', '--output', str(output)]), patch.object(ui, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    ui.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned PCCS and Unicorn')
    def test_native_normalization(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        cases = ui.audit(data)['cases']
        self.assertEqual(len(cases), 5)
        for case in cases:
            ctx = case['context']
            if ctx['checked']:
                self.assertEqual(case['effective'], dict(library='SOFTUSB.DLL', protocol='IESCAN' if ctx['protocol'] == 'IESCAN' else 'CAN'))
                self.assertEqual(case['boundary'], hex(ui.STOP))
                self.assertEqual(case['device_word'], 1)
                self.assertEqual(case['timing_global'], 1)
            else:
                self.assertEqual(case['effective'], dict(library='prior.dll', protocol=ctx['protocol']))
                self.assertEqual(case['boundary'], hex(ui.BYPASS))
                self.assertEqual(case['synthetic_callbacks'], ['synthetic_checked_getter'])
            for key in ('actual_ui_executed', 'actual_string_runtime_executed', 'transport_used', 'live_write_enabled', 'ready_to_flash'):
                self.assertFalse(case[key])
            self.assertEqual(case['would_send'], [])

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned PCCS and Unicorn')
    def test_context_guards(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        for ctx in ({'checked': 1}, {'protocol': []}, {'protocol': 'unknown'}, {'protocol': None}):
            with self.assertRaises(ValueError):
                ui.run(data, **ctx)


if __name__ == '__main__':
    unittest.main()
