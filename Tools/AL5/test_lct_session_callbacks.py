import importlib.util
import os
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from emulate_lct_session_callbacks import (CALLBACKS, EXIT, INITIAL_STATUS, STACK,
                                           STUB, THIS, audit, emulate_case,
                                           permitted_pc, permitted_write, main)


class SessionCallbackTests(unittest.TestCase):
    def test_cli_preserves_existing_output_before_reading_source(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'existing.json'
            output.write_text('preserve', encoding='utf-8')
            with patch('sys.argv', ['tool', str(output), '--output', str(output)]), \
                    patch('emulate_lct_session_callbacks.audit') as run, \
                    patch('sys.stderr'), self.assertRaises(SystemExit) as error:
                main()
            self.assertEqual(error.exception.code, 2)
            run.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'preserve')

    def test_changed_source_refused_before_reconstruction(self):
        with patch('emulate_lct_session_callbacks.reconstruct') as reconstruct:
            with self.assertRaisesRegex(ValueError, 'hash differs'):
                audit(b'not the pinned DLL')
            reconstruct.assert_not_called()

    def test_execution_cannot_escape_selected_callback_or_stub(self):
        for start, end in CALLBACKS.values():
            self.assertTrue(permitted_pc(start, 1, start, end))
            self.assertTrue(permitted_pc(end-1, 1, start, end))
            self.assertTrue(permitted_pc(STUB, 5, start, end))
            self.assertTrue(permitted_pc(STUB+5, 3, start, end))
            for address, size in ((start-1, 1), (end, 1), (end-1, 2),
                                  (STUB+7, 2), (EXIT, 1), (start, 0),
                                  (0x1001995a, 1), (0x1005d110, 1)):
                self.assertFalse(permitted_pc(address, size, start, end))
        a, b = CALLBACKS['group0']
        self.assertFalse(permitted_pc(CALLBACKS['group2'][0], 1, a, b))

    def test_writes_cannot_change_code_payload_events_or_other_object_state(self):
        self.assertTrue(permitted_write(STACK, 4))
        self.assertTrue(permitted_write(STACK+0xffff, 1))
        self.assertTrue(permitted_write(THIS+0xb4, 4))
        for address, size in ((THIS+0xb3, 1), (THIS+0xb7, 2),
                              (THIS+0x1a4, 2), (STACK+0xffff, 2),
                              (STACK, 0), (0x10071120, 4),
                              (0x1000d029, 1), (0x50000000, 1)):
            self.assertFalse(permitted_write(address, size))

    def test_invalid_context_is_rejected_before_optional_runtime_import(self):
        for kwargs in ({'callback': 'other'}, {'callback': 'group0', 'index': -1},
                       {'callback': 'group0', 'index': 3},
                       {'callback': 'group2', 'index': 0x10000},
                       {'callback': 'group0', 'first_byte': 256},
                       {'callback': 'group0', 'second_byte': -1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                emulate_case(None, **kwargs)

    @unittest.skipUnless(os.environ.get('AL5_LCT_DLL') and importlib.util.find_spec('unicorn'),
                         'Set AL5_LCT_DLL and provide optional Unicorn for pinned real input')
    def test_native_callbacks_with_synthetic_payload_and_event_matrix(self):
        result = audit(Path(os.environ['AL5_LCT_DLL']).read_bytes())
        self.assertEqual(len(result['cases']), 33)
        for case in result['cases']:
            self.assertTrue(case['returned_to_synthetic_exit'])
            self.assertLess(case['instruction_observations'], 2000)
            if case['callback'] == 'group0':
                second = bytes.fromhex(case['payload_hex'])[1]
                self.assertEqual(case['final_status'],
                                 {0: 0, 0x31: 1, 0x35: 2, 0x37: 0, 0xff: 4}[second])
                self.assertEqual(case['synthetic_events'], [0xa000+case['synthetic_index']])
                self.assertTrue(case['provider_defined_function'])
            else:
                self.assertEqual(case['final_status'], INITIAL_STATUS)
                self.assertEqual(case['synthetic_events'],
                                 [0xb000] if case['synthetic_index'] == 0 else [])
                self.assertFalse(case['provider_defined_function'])
        self.assertFalse(result['transport_used'])
        self.assertFalse(result['windows_apis_executed'])
        self.assertFalse(result['live_write_enabled'])
        self.assertFalse(result['ready_to_flash'])
        self.assertEqual(result['would_send'], [])


if __name__ == '__main__':
    unittest.main()
