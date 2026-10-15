import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_alternate_entry as entry


class AlternateEntryTests(unittest.TestCase):
    def test_pin_before_layout(self):
        with patch.object(entry, 'executable_sections') as layout:
            with self.assertRaisesRegex(ValueError, 'pin changed'):
                entry.run(b'changed')
            layout.assert_not_called()

    def test_context_validation(self):
        data = b'context'
        with patch.object(entry, 'SOURCE_SHA256', hashlib.sha256(data).hexdigest()):
            for context in ({'prior_alternate': -1}, {'prior_alternate': 256},
                            {'prior_alternate': True}, {'gmw_control': True}, {'gmw_control': 256}, {'prior_quick': 2}, {'prior_quick': False}):
                with self.subTest(context=context), self.assertRaises(ValueError):
                    entry.run(data, **context)

    def test_instruction_and_exact_store_bounds(self):
        self.assertTrue(entry.permitted_pc(entry.START, 7))
        self.assertFalse(entry.permitted_pc(entry.STOP-1, 2))
        for address in (*entry.GLOBALS, *(entry.THIS+o for o in range(0x72d90, 0x72d94))):
            self.assertTrue(entry.permitted_write(address, 1))
            self.assertFalse(entry.permitted_write(address, 2))
        for address in (entry.STACK, entry.THIS+0x68c60, entry.THIS+0x72d8f, entry.THIS+0x72d94):
            self.assertFalse(entry.permitted_write(address, 1))

    def test_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep'
            output.write_bytes(b'keep')
            with patch('sys.argv', ['tool', 'missing', '--output', str(output)]), \
                    patch('sys.stderr'), patch.object(entry, 'audit') as audit, \
                    self.assertRaises(SystemExit):
                entry.main()
            audit.assert_not_called()
            self.assertEqual(output.read_bytes(), b'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'),
                         'requires pinned local PCCS and Unicorn')
    def test_native_clear_preserves_quick_and_exposes_ordering(self):
        report = entry.audit(Path(os.environ['AL5_PCCS_EXE']).read_bytes())
        self.assertEqual(len(report['entry_cases']), 6)
        for case in report['entry_cases']:
            self.assertEqual(case['final_alternate'], 0)
            self.assertEqual(case['final_route_bytes'], '00000000')
            self.assertEqual(case['final_quick'], case['context']['prior_quick'])
            self.assertEqual(case['final_gmw_control'], case['context']['gmw_control'])
            self.assertTrue(all(v == 0 for v in case['final_globals'].values()))
            self.assertEqual(len(case['native_writes']), 10)
            self.assertFalse(case['full_identification_executed'])
            self.assertFalse(case['transport_used'])
            self.assertFalse(case['live_write_enabled'])
            self.assertEqual(case['would_send'], [])
        for composition in report['independent_poll_compositions']:
            for key in ('standard_lct_without_entry_clear', 'standard_lct_after_entry_clear'):
                self.assertEqual(composition[key]['final_family'], 1)
                self.assertEqual(composition[key]['final_version'], 0)
            self.assertEqual(composition['standard_lct_without_entry_clear']['final_alternate'],
                             composition['prior_alternate'])
            before = composition['poll_without_entry_clear']
            after = composition['poll_after_entry_clear']
            self.assertEqual(before['context']['alternate_route'], composition['prior_alternate'])
            self.assertEqual(before['identification_count'], int(composition['prior_alternate'] == 0))
            self.assertEqual(after['identification_count'], 1)
        self.assertFalse(report['ready_to_flash'])
        self.assertEqual(report['would_send'], [])


if __name__ == '__main__':
    unittest.main()
