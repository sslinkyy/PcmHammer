import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from emulate_pccs_prepare import (START, STOP, STUB, STACK, THIS, audit,
                                   main, permitted_pc, permitted_write, run)


class PccsPrepareTests(unittest.TestCase):
    def test_pin_rejected_before_layout(self):
        with patch('emulate_pccs_prepare.executable_sections') as layout:
            for operation in (run, audit):
                with self.assertRaisesRegex(ValueError, 'pin changed'):
                    operation(b'changed')
            layout.assert_not_called()

    def test_invalid_context_rejected_before_layout(self):
        data = b'context'
        with patch('emulate_pccs_prepare.SOURCE_SHA256', hashlib.sha256(data).hexdigest()), \
                patch('emulate_pccs_prepare.executable_sections') as layout:
            for context in ({'version': -1}, {'selector': 256}, {'host_status': 1.5}, {'response_byte': True}):
                with self.subTest(context=context), self.assertRaises(ValueError):
                    run(data, **context)
            layout.assert_not_called()

    def test_execution_and_write_boundaries(self):
        self.assertTrue(permitted_pc(START, 1))
        self.assertTrue(permitted_pc(STUB+0x100, 3))
        for address, size in ((START-1, 1), (STOP-1, 2), (STOP, 1), (STUB+0x101, 1), (START, 0)):
            self.assertFalse(permitted_pc(address, size))
        for address, size in ((STACK, 4), (THIS+0x52250, 5), (THIS+0x528a4, 1)):
            self.assertTrue(permitted_write(address, size))
        for address, size in ((THIS, 4), (THIS+0x52679, 1), (THIS+0x52254, 2), (STACK+0xffff, 2), (STACK, 0)):
            self.assertFalse(permitted_write(address, size))

    def test_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'existing'
            path.write_bytes(b'keep')
            with patch('sys.argv', ['tool', str(path), '--output', str(path)]), \
                    patch('sys.stderr'), patch('emulate_pccs_prepare.audit') as runner, \
                    self.assertRaises(SystemExit):
                main()
            runner.assert_not_called()
            self.assertEqual(path.read_bytes(), b'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'),
                         'Set AL5_PCCS_EXE and provide optional Unicorn for pinned real input')
    def test_native_request_and_status_normalization(self):
        result = audit(Path(os.environ['AL5_PCCS_EXE']).read_bytes())
        cases = result['cases']
        self.assertEqual(len(cases), 7)
        self.assertEqual([c['final_host_status'] for c in cases[:4]], [0, 3, 0, 9])
        self.assertEqual(cases[1]['stop'], 'error_status_before_string_formatting')
        self.assertEqual(cases[2]['stop'], 'before_identification_poll')
        self.assertEqual([c['dispatches'][0]['internal_buffer_hex'] for c in cases],
                         ['10010001']*4+['10010001b0', '10010001bf', '10010001ac'])
        for case in cases:
            self.assertFalse(case['transport_used'])
            self.assertFalse(case['windows_apis_executed'])
            self.assertFalse(case['live_write_enabled'])
            self.assertFalse(case['ready_to_flash'])
            self.assertEqual(case['would_send'], [])


if __name__ == '__main__':
    unittest.main()
