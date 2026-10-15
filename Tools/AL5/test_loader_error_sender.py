"""Native error-to-sender-timeout continuity cannot qualify wire delivery."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import emulate_loader_error_sender as model


class ErrorSenderGuards(unittest.TestCase):
    def test_source_and_context_pins(self):
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            model.ErrorSenderSession(b'wrong')
        for value in (True, -1, 0, 7, '1'):
            with self.assertRaisesRegex(ValueError, 'timeout byte'):
                model.ErrorSenderSession(b'wrong', timeout_at_byte=value)

    def test_owned_instruction_spans(self):
        self.assertTrue(model.executable_span(model.BASE+0x5E8, 6))
        self.assertFalse(model.executable_span(model.BASE+0x5FA, 4))
        self.assertFalse(model.executable_span(model.BASE+0x60C, 2))
        self.assertFalse(model.executable_span(model.BASE+0x236, 2))
        self.assertFalse(model.executable_span(0x8000, 2))

    def test_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'keep.json'
            path.write_text('keep', encoding='utf-8')
            with patch.object(model, 'audit') as audit, patch('sys.stderr'):
                with self.assertRaises(SystemExit):
                    model.main(['--loader', 'absent', '--output', str(path)])
                audit.assert_not_called()
            self.assertEqual('keep', path.read_text(encoding='utf-8'))


@unittest.skipUnless(os.environ.get('AL5_CAPTURED_LOADER') and importlib.util.find_spec('unicorn'),
                     'requires pinned loader and Unicorn')
class NativeErrorSender(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code = Path(os.environ['AL5_CAPTURED_LOADER']).read_bytes()
        cls.report = model.audit(cls.code)
        cls.cases = {c['name']: c['steps'][-1] for c in cls.report['cases']}

    def test_returning_sender_preserves_nonlocal_error_frames(self):
        program = self.cases['program_error_sender_ready']
        erase = self.cases['erase_error_sender_ready']
        self.assertEqual(-4, program['stack_delta'])
        self.assertEqual(-12, erase['stack_delta'])
        self.assertEqual(['0xff91be'], program['pending_stack_words'])
        self.assertEqual(['0xff9370', '0xff9358', '0xff9256'], erase['pending_stack_words'])
        for result in (program, erase):
            self.assertEqual(1, result['native_sender_returns'])
            self.assertEqual(6, result['synthetic_ready_reads'])
            self.assertEqual([], result['sender_timeout_jumps'])
            self.assertEqual([20, 4, 4, 4, 4, 12], result['synthetic_control_values'])

    def test_first_byte_timeout_executes_native_jump_and_stack_setup(self):
        program = self.cases['program_error_first_byte_timeout']
        erase = self.cases['erase_error_first_byte_timeout']
        self.assertEqual(-16, program['sender_timeout_jumps'][0]['stack_delta'])
        self.assertEqual(-24, erase['sender_timeout_jumps'][0]['stack_delta'])
        self.assertEqual(['0xff953c', '0xff952c', '0xff9512', '0xff9370',
                          '0xff9358', '0xff9256'], erase['sender_timeout_jumps'][0]['pending_words'])
        for result in (program, erase):
            self.assertEqual([0x6D], result['staged_fifo_bytes'])
            self.assertEqual(0, result['native_sender_returns'])
            self.assertEqual(0, result['stack_delta'])
            self.assertEqual([], result['pending_stack_words'])
            self.assertEqual(255, result['receive_budget'])
            self.assertEqual(1, result['suppressed_setup_stores'])
            self.assertEqual(4095, result['synthetic_ready_reads'])
        self.assertEqual('0x40', program['d7'])
        self.assertEqual('12350000', program['synthetic_flash_hex'])
        self.assertEqual('0x4', erase['d7'])

    def test_last_byte_timeout_stages_error_without_normal_sender_return(self):
        result = self.cases['erase_error_last_byte_timeout']
        self.assertEqual([0x6D, 0xF0, 0x18, 0x76, 0, 0x85], result['staged_fifo_bytes'])
        self.assertEqual(0, result['native_sender_returns'])
        self.assertEqual(-28, result['sender_timeout_jumps'][0]['stack_delta'])
        self.assertEqual('0xff95bc', result['sender_timeout_jumps'][0]['pending_words'][0])
        self.assertEqual(4100, result['synthetic_ready_reads'])
        self.assertEqual(0, result['stack_delta'])

    def test_program_success_status_can_also_timeout_before_cleanup(self):
        result = self.cases['program_success_last_byte_timeout']
        self.assertEqual(['760073'], result['responses'])
        self.assertEqual([0x6D, 0xF0, 0x18, 0x76, 0, 0x73], result['staged_fifo_bytes'])
        self.assertEqual('12345678', result['synthetic_flash_hex'])
        self.assertEqual(0, result['native_sender_returns'])
        self.assertEqual(['0xff95bc', '0xff954e', '0xff952c', '0xff91c6'],
                         result['sender_timeout_jumps'][0]['pending_words'])
        self.assertNotIn('0xff9550', result['synthetic_helper_calls'])

    def test_fresh_frame_after_timeout_is_explicit_and_not_recovery(self):
        session = model.ErrorSenderSession(self.code, timeout_at_byte=1)
        session.start()
        failed = session.erase(patterns=('persistent_toggle', 'stable'))
        self.assertEqual(0, failed['stack_delta'])
        session.timeout_at_byte = None
        result = session.frame(readback='synthetic')
        self.assertEqual(['760073'], result['responses'])
        self.assertEqual(1, result['native_sender_returns'])
        self.assertEqual(0, result['stack_delta'])
        self.assertFalse(result['physical_recovery_verified'])

    def test_no_transport_or_recovery_promotion(self):
        self.assertFalse(self.report['physical_transport_verified'])
        for case in self.report['cases']:
            for result in case['steps']:
                for field in ('transport_used', 'flash_commands_executed',
                              'physical_recovery_verified', 'automatic_retry_allowed',
                              'live_write_enabled', 'ready_to_flash'):
                    self.assertFalse(result[field])
                self.assertEqual([], result['would_send'])


if __name__ == '__main__':
    unittest.main()
