import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_retry_gates as gates


class RetryGateTests(unittest.TestCase):
    def test_pin_before_loading(self):
        with self.assertRaisesRegex(ValueError, 'pin changed'):
            gates.run(b'not the executable')

    def test_execution_and_write_bounds(self):
        self.assertTrue(gates.permitted_pc('initial', gates.GETTER_START, 7))
        self.assertTrue(gates.permitted_pc('dialog', 0x7be9df, 2))
        self.assertTrue(gates.permitted_write('initial', gates.STACK, 4))
        for stage, address, size in (('initial', 0x7be8a3, 1), ('dialog', gates.GETTER_START, 1),
                                    ('dialog', 0x7be9df, 3), ('tail', 0x7be9ff, 1), ('unknown', 0, 1)):
            self.assertFalse(gates.permitted_pc(stage, address, size))
        for stage, address, size in (('dialog', gates.STACK, 4), ('initial', gates.THIS+0x528a4, 1),
                                    ('initial', gates.STACK+0xfff, 2)):
            self.assertFalse(gates.permitted_write(stage, address, size))

    def test_existing_output_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', 'missing.exe', '--output', str(output)]), patch.object(gates, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    gates.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned local PCCS and Unicorn')
    def test_native_gates(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        result = gates.audit(data)
        self.assertEqual(len(result['cases']), 13)
        for case in result['cases']:
            context = case['context']
            stage = context['stage']
            if stage == 'initial':
                expected = {0: 'body_entry', 12: 'initialization_error_dialog_gate'}.get(context['status'], 'finish_gate')
                self.assertEqual(case['calls'], ['native_host_status_getter'])
                self.assertEqual(case['final_bl'], context['prior_bl'])
            elif stage == 'dialog':
                accepted = context['dialog_result'] == 4
                expected = 'accepted_retry' if accepted else 'declined_retry'
                self.assertEqual(case['final_bl'], 1 if accepted else context['prior_bl'])
            else:
                expected = 'repeat_initialization' if context['prior_bl'] else 'cleanup'
            self.assertEqual(case['boundary'], expected, context)
            self.assertFalse(case['full_wrapper_executed'])
            self.assertFalse(case['transport_used'])
            self.assertEqual(case['would_send'], [])
        for context in ({'stage': 'unknown'}, {'status': 256}, {'prior_bl': True}, {'dialog_result': -1}):
            with self.assertRaises(ValueError):
                gates.run(data, **context)


if __name__ == '__main__':
    unittest.main()
