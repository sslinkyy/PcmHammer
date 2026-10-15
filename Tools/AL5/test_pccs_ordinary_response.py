import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_ordinary_response as response


class OrdinaryResponseTests(unittest.TestCase):
    def test_pin_before_loading(self):
        with self.assertRaisesRegex(ValueError, 'pin changed'):
            response.run(b'not the executable')

    def test_execution_bounds(self):
        self.assertTrue(response.permitted_pc(response.START, 7))
        self.assertTrue(response.permitted_pc(response.SWAP_START, 1))
        for address, size in ((response.START-1, 1), (response.STOP-1, 2),
                              (response.SWAP_STOP-1, 2), (0x404820, 1)):
            self.assertFalse(response.permitted_pc(address, size))

    def test_write_bounds(self):
        self.assertTrue(response.permitted_write(response.STACK, 4))
        self.assertTrue(response.permitted_write(response.THIS+0x528a4, 1))
        self.assertTrue(response.permitted_write(response.THIS+0x5288c, 4))
        for address, size in ((response.THIS+0x72d90, 1), (response.THIS+0x528a4, 2),
                              (response.THIS+0x52679, 1), (0x81d108, 1)):
            self.assertFalse(response.permitted_write(address, size))

    def test_existing_output_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', 'missing.exe', '--output', str(output)]), patch.object(response, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    response.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned local PCCS and Unicorn')
    def test_native_reply_matrix(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        report = response.audit(data)
        self.assertEqual(len(report['cases']), 12)
        zero, one, ff, stale_zero, stale_aa, oversized, empty, wrong_service, wrong_id, standard_frame, unknown_frame, sentinel_length = report['cases']
        for case in (zero, one, ff, stale_zero, stale_aa):
            self.assertEqual(case['boundary'], 'prefix_accepted')
            self.assertEqual(case['final_host_status'], 0)
        self.assertEqual(zero['response_identifier'], 0)
        self.assertTrue(zero['identifier_from_current_payload'])
        self.assertEqual(zero['classification']['family'], 1)
        self.assertEqual(zero['classification']['version'], 0)
        self.assertEqual(zero['classification']['alternate'], 1)
        self.assertTrue(zero['classification']['independent_phase_handoff'])
        self.assertFalse(zero['classification']['full_caller_executed'])
        self.assertEqual(one['response_identifier'], 1)
        self.assertEqual(ff['response_identifier'], 255)
        self.assertEqual(stale_zero['response_identifier'], 0)
        self.assertEqual(stale_aa['response_identifier'], 0xaa)
        self.assertFalse(stale_zero['identifier_from_current_payload'])
        self.assertFalse(stale_aa['identifier_from_current_payload'])
        self.assertEqual(oversized['boundary'], 'frame_or_length_not_selected')
        self.assertEqual(empty['boundary'], 'unusable_length')
        self.assertEqual(sentinel_length['boundary'], 'unusable_length')
        self.assertEqual(wrong_service['boundary'], 'prefix_not_matched')
        for case in (wrong_id, standard_frame, unknown_frame):
            self.assertEqual(case['boundary'], 'frame_or_length_not_selected')
            self.assertEqual(case['final_host_status'], 1)
        for case in report['cases']:
            self.assertEqual(case['final_alternate'], 1)
            self.assertFalse(case['full_dispatcher_executed'])
            self.assertFalse(case['transport_used'])
            self.assertEqual(case['would_send'], [])
        for context in ({'payload': []}, {'payload': bytes(530)}, {'frame_format': True},
                        {'received_id': -1}, {'stale_identifier': 256}, {'classify_zero': 1}):
            with self.assertRaises(ValueError):
                response.run(data, **context)
        with self.assertRaisesRegex(ValueError, 'accepted zero identifier'):
            response.run(data, payload=b'\x35\x01', classify_zero=True)


if __name__ == '__main__':
    unittest.main()
