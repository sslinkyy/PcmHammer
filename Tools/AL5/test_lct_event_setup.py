import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from emulate_lct_event_setup import (END, EVENT_SLOTS, STACK, START, STUB,
                                     THIS, audit, main, permitted_pc, permitted_write)


class EventSetupTests(unittest.TestCase):
    def test_changed_source_refused_before_reconstruction(self):
        with patch('emulate_lct_event_setup.reconstruct') as run:
            with self.assertRaisesRegex(ValueError, 'hash differs'):
                audit(b'changed')
            run.assert_not_called()

    def test_only_event_handle_fields_and_stack_are_writable(self):
        self.assertEqual(len(EVENT_SLOTS), 168)
        for address in EVENT_SLOTS:
            self.assertTrue(permitted_write(address, 4))
            self.assertFalse(permitted_write(address+1, 4))
        for address, size in ((THIS+0xb4, 4), (0x10073224, 4),
                              (STACK+0xffff, 2), (STACK, 0), (START, 4)):
            self.assertFalse(permitted_write(address, size))

    def test_execution_boundaries(self):
        self.assertTrue(permitted_pc(START, 1))
        self.assertTrue(permitted_pc(STUB, 3))
        for address, size in ((START-1, 1), (END-1, 2), (END, 1),
                              (STUB, 4), (STUB+3, 1), (START, 0)):
            self.assertFalse(permitted_pc(address, size))

    def test_existing_report_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'existing'
            path.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', str(path), '--output', str(path)]), \
                    patch('sys.stderr'), patch('emulate_lct_event_setup.audit') as run, \
                    self.assertRaises(SystemExit):
                main()
            run.assert_not_called()
            self.assertEqual(path.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_LCT_DLL') and importlib.util.find_spec('unicorn'),
                         'Set AL5_LCT_DLL and provide optional Unicorn for pinned real input')
    def test_pinned_event_creation_does_not_request_initial_activation(self):
        result = audit(Path(os.environ['AL5_LCT_DLL']).read_bytes())
        self.assertEqual(len(result['synthetic_create_event_calls']), 168)
        self.assertTrue(all(c['arguments'] == [0, 0, 0, 0]
                            for c in result['synthetic_create_event_calls']))
        self.assertEqual(result['groups'][2]['request_slot'], hex(THIS+0xdc))
        self.assertNotEqual(result['groups'][2]['request_handle'],
                            result['groups'][2]['done_handle'])
        self.assertTrue(result['request_descriptor_fields_preserved'])
        for flag in ('transport_used', 'windows_apis_executed', 'live_write_enabled', 'ready_to_flash'):
            self.assertFalse(result[flag])
        self.assertEqual(result['would_send'], [])


if __name__ == '__main__':
    unittest.main()
