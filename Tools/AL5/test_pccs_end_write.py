import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from emulate_pccs_end_write import (START, END, THIS, STACK, PREFIX, INIT, STUBS,
                                    audit, main, permitted_pc, permitted_write, run)


class EndWriteTests(unittest.TestCase):
    def test_source_pin_precedes_layout(self):
        with patch('emulate_pccs_end_write.executable_sections') as layout:
            with self.assertRaisesRegex(ValueError, 'pin changed'):
                run(b'changed')
            with self.assertRaisesRegex(ValueError, 'pin changed'):
                audit(b'changed')
            layout.assert_not_called()

    def test_invalid_context_rejected_before_optional_import(self):
        data = b'context'
        with patch('emulate_pccs_end_write.SOURCE_SHA256', hashlib.sha256(data).hexdigest()):
            for context in ({'check': 1}, {'version': 5}, {'statuses': []}, {'statuses': ()},
                            {'statuses': (256,)}, {'statuses': (True,)}, {'boots': (1,)}):
                with self.subTest(context=context), self.assertRaises(ValueError):
                    run(data, **context)

    def test_native_execution_and_write_bounds(self):
        self.assertTrue(permitted_pc(START, 1))
        self.assertFalse(permitted_pc(END-1, 2))
        for address, stub in STUBS.items():
            self.assertTrue(permitted_pc(address, len(stub)))
            self.assertFalse(permitted_pc(address, len(stub)+1))
        self.assertFalse(permitted_pc(PREFIX+1, 1))
        self.assertFalse(permitted_pc(START, 0))
        for address, size in ((0, 4), (STACK, 4), (THIS+0x52250, 4),
                              (THIS+0x52894, 4), (THIS+0x528a4, 1), (0x81d104, 1)):
            self.assertTrue(permitted_write(address, size))
        for address, size in ((1, 4), (THIS, 4), (THIS+0x52253, 2), (0x81d104, 2),
                              (THIS+0x528a4, 2), (STACK+0xffff, 2), (STACK, 0)):
            self.assertFalse(permitted_write(address, size))

    def test_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'existing'
            path.write_bytes(b'keep')
            with patch('sys.argv', ['tool', str(path), '--output', str(path)]), \
                    patch('sys.stderr'), patch('emulate_pccs_end_write.audit') as runner, \
                    self.assertRaises(SystemExit):
                main()
            runner.assert_not_called()
            self.assertEqual(path.read_bytes(), b'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'),
                         'Set AL5_PCCS_EXE and provide optional Unicorn for pinned real input')
    def test_native_readiness_retries_failure_and_restoration(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        cases = audit(data)['cases']
        self.assertEqual(len(cases), 9)
        self.assertEqual([c['final_host_status'] for c in cases], [0, 0, 0, 9, 7, 0, 7, 0, 12])
        self.assertEqual([len(c['initialization_statuses']) for c in cases], [1, 0, 2, 3, 3, 2, 9, 1, 1])
        self.assertEqual([len(c['internal_requests']) for c in cases], [1, 1, 1, 1, 3, 2, 3, 1, 1])
        self.assertEqual(cases[1]['in_boot_results'], [])
        self.assertEqual(cases[7]['internal_requests'], ['11000000'])
        self.assertEqual(cases[4]['in_boot_results'], [True]*4)
        self.assertEqual(cases[0]['fake_sleep_arguments'], [2000])
        self.assertEqual(cases[2]['fake_sleep_arguments'], [2000, 2000])
        for case in cases:
            self.assertEqual(case['restored_globals_hex'], '3567')
            self.assertTrue(all(index == 1 for index in case['prefix_indices']))
            self.assertFalse(case['transport_used'])
            self.assertFalse(case['windows_apis_executed'])
            self.assertFalse(case['live_write_enabled'])
            self.assertFalse(case['ready_to_flash'])
            self.assertEqual(case['would_send'], [])
        for context in ({'statuses': (9,), 'boots': ()}, {'boots': ()}):
            with self.subTest(context=context), self.assertRaisesRegex(ValueError, 'exhausted'):
                run(data, **context)


if __name__ == '__main__':
    unittest.main()
