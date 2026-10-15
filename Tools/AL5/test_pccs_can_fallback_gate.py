import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_can_fallback_gate as gate


class CanFallbackGateTests(unittest.TestCase):
    def test_pin_before_loading(self):
        with self.assertRaisesRegex(ValueError, 'pin changed'):
            gate.run(b'not the executable')

    def test_execution_bounds(self):
        self.assertTrue(gate.permitted_pc(gate.START, 7))
        for address, size in ((gate.START-1, 1), (gate.STOP-1, 2), (0x5d9ba9, 1), (0x5dc085, 1)):
            self.assertFalse(gate.permitted_pc(address, size))

    def test_native_writes_all_forbidden(self):
        for address, size in ((gate.THIS+0x72d90, 1), (gate.THIS+0x528a4, 1), (gate.STACK, 4), (0x81d118, 1)):
            self.assertFalse(gate.permitted_write(address, size))

    def test_existing_output_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', 'missing.exe', '--output', str(output)]), patch.object(gate, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    gate.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned local PCCS and Unicorn')
    def test_native_gate_matrix(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        report = gate.audit(data)
        self.assertEqual(len(report['cases']), 12)
        for case in report['cases']:
            context = case['context']
            expected = 'ordinary_fallback' if context['helper_flag'] == 0 and context['identification_word'] == 0 else 'identified_or_other_exit'
            self.assertEqual(case['boundary'], expected, context)
            self.assertEqual(case['final_host_status'], context['host_status'])
            self.assertEqual(case['final_alternate'], context['alternate'])
            self.assertFalse(case['helper_executed'])
            self.assertFalse(case['transport_used'])
            self.assertEqual(case['would_send'], [])
        for case in report['identifier_producer_cases']:
            self.assertEqual(case['identification_word'], case['context']['response_byte'])
            self.assertEqual(case['instruction_observations'], 3)
            self.assertFalse(case['reply_acceptance_proven'])
        for context in ({'response_byte': True}, {'response_byte': 256}, {'index': -1}):
            with self.assertRaises(ValueError):
                gate.run_identifier_producer(data, **context)
        for context in ({'host_status': 256}, {'alternate': True}, {'helper_flag': -1}, {'identification_word': 0x10000}):
            with self.assertRaises(ValueError):
                gate.run(data, **context)


if __name__ == '__main__':
    unittest.main()
