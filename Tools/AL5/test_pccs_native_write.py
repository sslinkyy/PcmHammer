import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from emulate_pccs_native_write import (START, END, GETTER, GETTER_END, COPY, SEND,
                                      STACK, THIS, INPUT, audit, main, permitted_pc,
                                      permitted_write, run)


class PccsNativeWriteTests(unittest.TestCase):
    def test_pin_before_layout(self):
        with patch('emulate_pccs_native_write.executable_sections') as layout:
            with self.assertRaisesRegex(ValueError, 'pin changed'):
                run(b'changed')
            layout.assert_not_called()

    def test_context_before_imports(self):
        data = b'context'
        with patch('emulate_pccs_native_write.SOURCE_SHA256', hashlib.sha256(data).hexdigest()):
            for context in ({'payload': b''}, {'payload': bytes(257)}, {'ccp': 1},
                            {'address': -1}, {'address': 0xffffff},
                            {'ccp': True, 'address': 0xffffffff},
                            {'quick': 1}, {'caller_flag': -1}, {'caller_flag': 256}, {'caller_flag': True},
                            {'statuses': ()}, {'responses': [0]}, {'statuses': (256,)}):
                with self.subTest(context=context), self.assertRaises(ValueError):
                    run(data, **context)

    def test_pc_and_native_write_bounds(self):
        for start, end in ((START, END), (GETTER, GETTER_END)):
            self.assertTrue(permitted_pc(start, 1))
            self.assertFalse(permitted_pc(end-1, 2))
        self.assertTrue(permitted_pc(COPY, 1))
        self.assertTrue(permitted_pc(SEND, 3))
        self.assertFalse(permitted_pc(SEND+1, 1))
        self.assertFalse(permitted_pc(0x5b3344, 1))
        self.assertFalse(permitted_pc(START, 0))
        for address, size in ((STACK, 4), (THIS+0x52250, 8), (THIS+0x52894, 4), (THIS+0x528a4, 1)):
            self.assertTrue(permitted_write(address, size))
        for address, size in ((THIS, 4), (INPUT, 4), (THIS+0x52257, 2), (THIS+0x528a4, 2), (STACK+0xffff, 2), (STACK, 0)):
            self.assertFalse(permitted_write(address, size))

    def test_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'existing'
            path.write_bytes(b'keep')
            with patch('sys.argv', ['tool', str(path), '--output', str(path)]), \
                    patch('sys.stderr'), patch('emulate_pccs_native_write.audit') as runner, \
                    self.assertRaises(SystemExit):
                main()
            runner.assert_not_called()
            self.assertEqual(path.read_bytes(), b'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'),
                         'Set AL5_PCCS_EXE and provide optional Unicorn for pinned real input')
    def test_quick_selection_and_ccp_precedence(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        for quick in (False, True):
            for flag in (0, 1, 255):
                for ccp in (False, True):
                    with self.subTest(quick=quick, caller_flag=flag, ccp=ccp):
                        case = run(data, quick=quick, caller_flag=flag, ccp=ccp)
                        selected = quick and flag == 0 and not ccp
                        self.assertEqual(len(case['quick_calls']), int(selected))
                        self.assertEqual(bool(case['dispatches']), not selected)
                        if selected:
                            self.assertFalse(case['quick_calls'][0]['body_executed'])
                        self.assertFalse(case['transport_used'])
                        self.assertEqual(case['would_send'], [])

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'),
                         'Set AL5_PCCS_EXE and provide optional Unicorn for pinned real input')
    def test_native_buffers_status_mapping_and_failures(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        report = audit(data)
        self.assertEqual(len(report['cases']), 12)
        ordinary, ccp, ordinary4, ccp5, fail, ccpfail, ccp_header_bad, ccp_data_bad, *mapped = report['cases']
        self.assertEqual([d['internal_buffer_hex'] for d in ordinary['dispatches']],
                         ['2212345600010203', '2212345a04050607', '2212345e08090a'])
        self.assertEqual([d['internal_buffer_hex'] for d in ccp['dispatches']],
                         ['027a000000123456', '037a050001020304', '037a050506070809', '037a010a'])
        self.assertEqual([d['internal_buffer_hex'] for d in ordinary4['dispatches']], ['2212345600000000'])
        self.assertEqual([d['internal_buffer_hex'] for d in ccp5['dispatches']], ['027a000000123456', '037a050000000000'])
        for case in (ordinary, ccp, ordinary4, ccp5):
            self.assertEqual(case['final_host_status'], 0)
        for case in (fail, ccpfail):
            self.assertEqual(case['final_host_status'], 9)
            self.assertEqual(len(case['dispatches']), 1)
        self.assertEqual(ccp_header_bad['final_host_status'], 2)
        self.assertEqual(len(ccp_header_bad['dispatches']), 1)
        self.assertEqual(ccp_data_bad['final_host_status'], 2)
        self.assertEqual(len(ccp_data_bad['dispatches']), 2)
        self.assertEqual([case['final_host_status'] for case in mapped], [4, 5, 6, 13])
        for case in mapped:
            self.assertEqual(len(case['dispatches']), 1)
        for case in report['cases']:
            self.assertFalse(case['ready_to_flash'])
            self.assertFalse(case['transport_used'])
            self.assertFalse(case['live_write_enabled'])
            self.assertEqual(case['would_send'], [])
        for context in ({'statuses': (0,)}, {'ccp': True, 'responses': (0,)}):
            with self.subTest(context=context), self.assertRaisesRegex(ValueError, 'exhausted'):
                run(data, **context)
        for ccp_flag in (False, True):
            case = run(data, payload=bytes(range(256)), ccp=ccp_flag)
            self.assertEqual(case['final_host_status'], 0)
            self.assertEqual(len(case['dispatches']), 53 if ccp_flag else 64)


if __name__ == '__main__':
    unittest.main()
