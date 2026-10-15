import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from emulate_pccs_quick_write import (START, END, STUBS, STACK, THIS, INPUT,
                                      run, audit, main, permitted_pc, permitted_write)


class PccsQuickWriteTests(unittest.TestCase):
    def test_pin_before_layout(self):
        with patch('emulate_pccs_quick_write.executable_sections') as layout:
            with self.assertRaisesRegex(ValueError, 'pin changed'):
                run(b'changed')
            layout.assert_not_called()

    def test_context_before_optional_imports(self):
        data = b'context'
        with patch('emulate_pccs_quick_write.SOURCE_SHA256', hashlib.sha256(data).hexdigest()):
            for context in ({'payload': b''}, {'payload': bytes(257)}, {'address': -1},
                            {'address': 0xffffff}, {'statuses': ()}, {'statuses': [0]},
                            {'statuses': (65536,)}, {'initial_host_status': 256}):
                with self.subTest(context=context), self.assertRaises(ValueError):
                    run(data, **context)

    def test_pc_and_write_bounds(self):
        self.assertTrue(permitted_pc(START, 1))
        self.assertFalse(permitted_pc(END-1, 2))
        self.assertFalse(permitted_pc(START, 0))
        for address, code in STUBS.items():
            self.assertTrue(permitted_pc(address, len(code)))
            self.assertFalse(permitted_pc(address+1, len(code)))
        self.assertFalse(permitted_pc(0x5b487c, 1))
        for address, size in ((0, 4), (STACK, 4), (THIS+0x52250, 8), (THIS+0x52898, 2),
                              (THIS+0x528a4, 1), (THIS+0x52894, 4)):
            self.assertTrue(permitted_write(address, size))
        for address, size in ((1, 4), (THIS, 4), (INPUT, 1), (THIS+0x52257, 2),
                              (THIS+0x52898, 4), (THIS+0x528a4, 2), (STACK+0xffff, 2)):
            self.assertFalse(permitted_write(address, size))

    def test_output_preservation_before_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'keep'
            path.write_bytes(b'keep')
            with patch('sys.argv', ['tool', str(path), '--output', str(path)]), \
                    patch('sys.stderr'), patch('emulate_pccs_quick_write.audit') as runner, \
                    self.assertRaises(SystemExit):
                main()
            runner.assert_not_called()
            self.assertEqual(path.read_bytes(), b'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'),
                         'Set AL5_PCCS_EXE and provide optional Unicorn for pinned real input')
    def test_native_chunking_retry_and_status_retention(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        report = audit(data)
        self.assertEqual(len(report['cases']), 11)
        ordinary, short1, exact4, short5, stale, retried, notbusy126, error, busy11, busy137, maximum = report['cases']
        self.assertEqual([d['internal_buffer_hex'] for d in ordinary['dispatches']],
                         ['2312345600010203', '2312345a04050607', '2312345e08090a'])
        self.assertEqual([len(c['dispatches']) for c in (short1, exact4, short5, maximum)], [1, 1, 2, 64])
        self.assertEqual(stale['final_host_status'], 9)
        self.assertEqual(retried['final_host_status'], 0)
        self.assertEqual(len(retried['dispatches']), 3)
        self.assertEqual(len({d['internal_buffer_hex'] for d in retried['dispatches']}), 1)
        self.assertEqual(retried['synthetic_wait_milliseconds'], [10, 50])
        self.assertEqual(len(retried['prefix_calls']), 1)
        for case, status in ((notbusy126, 126), (error, 9), (busy11, 11), (busy137, 137)):
            self.assertEqual(case['final_host_status'], 12)
            self.assertEqual(case['final_transport_word'], status)
        for case in (notbusy126, error):
            self.assertEqual(len(case['dispatches']), 1)
            self.assertEqual(case['synthetic_wait_milliseconds'], [])
        for case in (busy11, busy137):
            self.assertEqual(len(case['dispatches']), 41)
            self.assertEqual(case['synthetic_wait_milliseconds'], [10]+[50]*39)
            self.assertEqual(len({d['internal_buffer_hex'] for d in case['dispatches']}), 1)
        for context in ({'statuses': (11,)}, {'statuses': (0,)}):
            with self.subTest(context=context), self.assertRaisesRegex(ValueError, 'exhausted'):
                run(data, **context)
        for case in report['cases']:
            self.assertFalse(case['transport_used'])
            self.assertFalse(case['windows_apis_executed'])
            self.assertFalse(case['ready_to_flash'])
            self.assertFalse(case['live_write_enabled'])
            self.assertEqual(case['would_send'], [])


if __name__ == '__main__':
    unittest.main()
