import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_fil_selection as selection


class FilSelectionTests(unittest.TestCase):
    def test_pin_before_layout(self):
        with self.assertRaisesRegex(ValueError, 'pin changed'):
            selection.run(b'wrong source')

    def test_pc_coverage(self):
        self.assertTrue(selection.permitted_pc(selection.START, 1))
        for address, size in ((selection.START-1, 1), (selection.END-1, 2), (selection.END, 1), (selection.START, 0)):
            self.assertFalse(selection.permitted_pc(address, size))

    def test_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', 'missing.exe', '--output', str(output)]), patch.object(selection, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    selection.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned PCCS and Unicorn')
    def test_native_selection_and_indexed_effects(self):
        report = selection.audit(Path(os.environ['AL5_PCCS_EXE']).read_bytes())
        self.assertEqual(len(report['cases']), 48)
        self.assertEqual(report['source_alias']['bytes_hex'], 'f4d08100')
        for case in report['cases']:
            c = case['context']
            active = c['action'] == 1 and c['interpreter_version'] >= 4 and c['subaction'] != 0
            effective = c['requested'] if active and c['selection_lock'] == 0 else c['selected']
            self.assertEqual(case['selected_after'], effective)
            expected_boundary = ('other_action_or_version' if c['action'] != 1 or c['interpreter_version'] < 4
                                 else 'zero_subaction' if c['subaction'] == 0 else 'selection_branch_complete')
            self.assertEqual(case['boundary'], expected_boundary)
            expected_writes = []
            if active:
                if c['selection_lock'] == 0:
                    expected_writes.append(dict(address='0x81d0f4', size=4, value=c['requested']))
                expected_writes += [dict(address=hex(selection.THIS+effective*0xa4+offset), size=1, value=value)
                                    for offset, value in ((0x80, 1), (0xb6, 7))]
            self.assertEqual(case['native_writes'], expected_writes)
            for fields in case['indexed_fields']:
                changed = active and fields['index'] == effective
                self.assertEqual((fields['family'], fields['version']), (1, 7) if changed else (9, 9))
            for field in ('lct_utility_reachability_proven', 'j1850_map_translation_proven', 'full_interpreter_executed', 'subsequent_restore_proven', 'programming_bypass_proven', 'transport_used', 'live_write_enabled', 'ready_to_flash'):
                self.assertFalse(case[field])
            self.assertEqual(case['would_send'], [])

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned PCCS and Unicorn')
    def test_context_guards_and_nonzero_lock(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        for context in ({'action': True}, {'interpreter_version': 65536}, {'subaction': -1}, {'selection_lock': None}, {'selected': 256}, {'requested': []}):
            with self.assertRaises(ValueError):
                selection.run(data, **context)
        case = selection.run(data, selected=255, requested=0x18, selection_lock=255, subaction=255, interpreter_version=65535)
        self.assertEqual(case['selected_after'], 255)
        self.assertEqual(case['indexed_fields'][-1], dict(index=255, family=1, version=7))


if __name__ == '__main__':
    unittest.main()
