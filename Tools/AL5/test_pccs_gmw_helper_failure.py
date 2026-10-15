import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_gmw_helper_failure as helper


class GmwHelperFailureTests(unittest.TestCase):
    def test_pin_before_layout(self):
        with patch.object(helper, 'executable_sections') as layout:
            with self.assertRaisesRegex(ValueError, 'pin changed'):
                helper.run(b'changed')
            with self.assertRaisesRegex(ValueError, 'pin changed'):
                helper.run_dispatch_entry(b'changed')
            layout.assert_not_called()

    def test_failure_only_context_guard(self):
        data = b'context'
        with patch.object(helper, 'SOURCE_SHA256', hashlib.sha256(data).hexdigest()):
            for context in ({'read_status': 0}, {'read_status': 256}, {'read_status': True},
                            {'recognized': 2}, {'identifier': -1}, {'identifier': 0x10000},
                            {'alternate': 256}, {'index': 7}, {'index': False}):
                with self.subTest(context=context), self.assertRaises(ValueError):
                    helper.run(data, **context)

    def test_execution_and_write_bounds(self):
        self.assertTrue(helper.permitted_dispatch_pc(helper.DISPATCH_START, 3))
        self.assertFalse(helper.permitted_dispatch_pc(helper.DISPATCH_STOP-1, 2))
        self.assertTrue(helper.permitted_dispatch_write(helper.THIS+0x528a4, 1))
        self.assertFalse(helper.permitted_dispatch_write(helper.THIS+0x528a4, 2))
        self.assertFalse(helper.permitted_dispatch_write(helper.THIS+0x72d90, 1))
        self.assertTrue(helper.permitted_pc(helper.START, 7))
        self.assertTrue(helper.permitted_pc(helper.TAIL, 7))
        self.assertTrue(helper.permitted_pc(helper.READ, 3))
        self.assertFalse(helper.permitted_pc(0x5d7b80, 1))
        self.assertFalse(helper.permitted_pc(helper.STOP-1, 2))
        self.assertFalse(helper.permitted_pc(helper.READ+1, 1))
        self.assertTrue(helper.permitted_write(helper.THIS+3*0xa4+0x80, 1, 3))
        for address, size in ((helper.THIS+0x72d90, 1), (0x81d118, 1),
                              (helper.THIS+3*0xa4+0x84, 2), (helper.STACK+0xffff, 2)):
            self.assertFalse(helper.permitted_write(address, size, 3))

    def test_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep'
            output.write_bytes(b'keep')
            with patch('sys.argv', ['tool', 'missing', '--output', str(output)]), \
                    patch('sys.stderr'), patch.object(helper, 'audit') as audit, \
                    self.assertRaises(SystemExit):
                helper.main()
            audit.assert_not_called()
            self.assertEqual(output.read_bytes(), b'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'),
                         'requires pinned local PCCS and Unicorn')
    def test_native_failure_and_terminal_gate(self):
        report = helper.audit(Path(os.environ['AL5_PCCS_EXE']).read_bytes())
        self.assertEqual(len(report['cases']), 8)
        for case in report['cases']:
            context = case['context']
            self.assertEqual(case['final_host_status'], context['read_status'])
            self.assertEqual(case['final_alternate'], context['alternate'])
            self.assertEqual(case['final_recognized'], context['recognized'])
            self.assertEqual(case['final_identifier'], context['identifier'])
            terminal_classifies = not context['recognized'] and context['identifier'] != 0
            self.assertEqual((case['final_family'], case['final_version']),
                             (1, 7) if terminal_classifies else (0x99, 0x99))
            self.assertEqual(len(case['requests']), 1)
            self.assertFalse(case['full_helper_executed'])
            self.assertFalse(case['success_response_parsing_executed'])
            self.assertFalse(case['transport_used'])
            self.assertFalse(case['live_write_enabled'])
            self.assertEqual(case['would_send'], [])
        pipeline = report['conditional_pipeline']
        self.assertFalse(pipeline['continuous_execution'])
        self.assertFalse(pipeline['actual_al5_reachability_proven'])
        self.assertFalse(pipeline['initial_identifier_copy']['reply_acceptance_proven'])
        self.assertEqual(pipeline['initial_identifier_copy']['identification_word'], 0)
        self.assertEqual(pipeline['post_helper_gate']['boundary'], 'ordinary_fallback')
        self.assertEqual(pipeline['dispatcher_entry']['final_host_status'], 1)
        for prior_status in (0, 1, 9, 255):
            entry = helper.run_dispatch_entry(Path(os.environ['AL5_PCCS_EXE']).read_bytes(),
                                             prior_status=prior_status)
            self.assertEqual(entry['final_host_status'], 1)
            self.assertFalse(entry['full_dispatcher_executed'])
        classification = pipeline['classification_if_assumptions_hold']
        self.assertEqual((classification['final_family'], classification['final_version'],
                          classification['final_alternate']), (1, 0, 1))
        self.assertEqual(pipeline['enter_write_if_assumptions_hold']['identification_count'], 0)
        self.assertEqual(len(pipeline['assumptions']), 4)
        self.assertFalse(report['ready_to_flash'])


if __name__ == '__main__':
    unittest.main()
