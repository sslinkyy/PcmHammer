import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_fallback_request as request


class FallbackRequestTests(unittest.TestCase):
    def test_pin_before_layout(self):
        with self.assertRaisesRegex(ValueError, 'pin changed'):
            request.run(b'not the executable')

    def test_execution_boundaries(self):
        for start, stop in request.RANGES:
            self.assertTrue(request.permitted_pc(start, 1))
            self.assertFalse(request.permitted_pc(stop-1, 2))
        for address in (0x5aedc4, 0x5d7458, 0x5d9e23, 0x407208):
            self.assertFalse(request.permitted_pc(address, 1))
        self.assertFalse(request.permitted_pc(request.START, 0))

    def test_write_ownership(self):
        self.assertTrue(request.permitted_write(request.THIS+0x52894, 4))
        self.assertTrue(request.permitted_write(request.THIS+0x528a4, 1))
        for address, size in ((request.THIS+0x72d90, 1), (request.THIS+0x52894, 1),
                              (request.THIS+0x528a4, 4), (0x81d108, 1), (request.AUX, 4)):
            self.assertFalse(request.permitted_write(address, size))

    def test_existing_output_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', 'missing.exe', '--output', str(output)]), patch.object(request, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    request.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned local PCCS and Unicorn')
    def test_native_fallback_request_matrix(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        report = request.audit(data)
        self.assertEqual(len(report['cases']), 10)
        for position, case in enumerate(report['cases']):
            context = case['context']
            self.assertEqual(case['final_alternate'], context['alternate'])
            self.assertTrue(case['continuous_caller_slice'])
            self.assertFalse(case['dispatcher_executed'])
            self.assertFalse(case['transport_used'])
            self.assertFalse(case['live_write_enabled'])
            self.assertFalse(case['ready_to_flash'])
            self.assertEqual(case['would_send'], [])
            if position in (5, 6):
                self.assertEqual(case['boundary'], 'identified_or_other_exit')
                self.assertIsNone(case['dispatch'])
            elif position == 7:
                self.assertEqual(case['boundary'], 'caller_flag_skips_request')
                self.assertEqual(case['final_host_status'], 2)
            elif position == 8:
                self.assertEqual(case['boundary'], 'ccp_helper_selected')
                self.assertIsNone(case['dispatch'])
            else:
                self.assertEqual(case['boundary'], 'ordinary_dispatch')
                dispatch = case['dispatch']
                self.assertEqual(dispatch['request_hex'], '35')
                self.assertEqual(dispatch['pending_stack_arguments'], [3, 0])
                self.assertEqual(dispatch['request_length'], 1)
                self.assertEqual(dispatch['prefix_length'], 1)
                self.assertEqual(dispatch['maximum_response_length'], 2)
                self.assertEqual(dispatch['edx'], 1 if context['short_wait'] else 5)
                self.assertEqual(dispatch['timeout_parameter'], 200 if context['short_wait'] else 500)
                self.assertEqual(case['final_host_status'], context['host_status'])
        for context in ({'helper_flag': True}, {'alternate': 256}, {'identification_word': -1},
                        {'ccp_handle': 0x80000000}, {'caller_flag': 2}, {'short_wait': True}):
            with self.assertRaises(ValueError):
                request.run(data, **context)


if __name__ == '__main__':
    unittest.main()
