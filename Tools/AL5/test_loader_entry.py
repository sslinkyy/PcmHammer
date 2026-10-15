"""Native entry/parser/program continuity and nonlocal error-stack evidence."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import emulate_loader_entry as model


class LoaderEntryGuards(unittest.TestCase):
    def test_source_pin_precedes_runtime(self):
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            model.LoaderSession(b'wrong')

    def test_owned_instruction_and_write_spans(self):
        for a, b in model.RANGES:
            self.assertTrue(model.executable_span(a, 2))
            self.assertFalse(model.executable_span(b-1, 2))
        for pc in (model.BASE+0x252, model.BASE+0x236, model.BASE+0x60C, 0x8000):
            self.assertFalse(model.executable_span(pc, 2))
        self.assertTrue(model.writable_span(model.ENTRY_STACK-4, 4))
        self.assertTrue(model.writable_span(0xFFFF9A82, 1))
        for address, size in ((0x8000, 2), (model.BASE, 2), (model.RX, 1),
                              (0xFFFFFA4E, 2), (model.ENTRY_STACK, 2), (0xFFFF9A82, 2)):
            self.assertFalse(model.writable_span(address, size))

    def test_cli_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'keep.json'
            path.write_text('keep', encoding='utf-8')
            with patch.object(model, 'audit') as audit, patch('sys.stderr'):
                with self.assertRaises(SystemExit):
                    model.main(['--loader', 'absent', '--output', str(path)])
                audit.assert_not_called()
            self.assertEqual('keep', path.read_text(encoding='utf-8'))


@unittest.skipUnless(os.environ.get('AL5_CAPTURED_LOADER') and importlib.util.find_spec('unicorn'),
                     'requires pinned captured loader and Unicorn')
class NativeLoaderEntry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code = Path(os.environ['AL5_CAPTURED_LOADER']).read_bytes()
        cls.report = model.audit(cls.code)
        cls.cases = {c['name']: c['steps'] for c in cls.report['cases']}

    def test_actual_entry_resets_stack_budget_and_retains_uninitialized_state(self):
        for case in self.report['cases']:
            entry = case['steps'][0]
            self.assertEqual('receive_boundary', entry['stop'])
            self.assertEqual(0, entry['stack_delta'])
            self.assertEqual(255, entry['receive_budget'])
            self.assertEqual(hex(model.RX), entry['a0'])
            self.assertEqual(7, entry['interrupt_mask'])
            self.assertEqual('0xa5', entry['d7'])
            self.assertEqual('a5'*16, entry['receive_prefix_hex'])
            self.assertEqual(1, entry['suppressed_setup_stores'])
            self.assertEqual({'0xff961a': 1}, entry['synthetic_helper_calls'])

    def test_continuous_receive_parser_stops_before_flash(self):
        result = self.cases['entry_to_program_command'][-1]
        self.assertEqual('before_flash_command', result['stop'])
        self.assertEqual('0xff940e', result['stop_pc'])
        self.assertEqual(-4, result['stack_delta'])
        self.assertEqual(17, result['events_consumed'])
        self.assertEqual('00000000', result['synthetic_flash_hex'])
        self.assertEqual([], result['responses'])
        self.assertEqual(0, result['suppressed_flash_stores'])

    def test_modeled_word_success_uses_native_status_and_returns(self):
        result = self.cases['modeled_program_success'][-1]
        self.assertEqual('receive_boundary', result['stop'])
        self.assertEqual(['760073'], result['responses'])
        self.assertEqual('12345678', result['synthetic_flash_hex'])
        self.assertEqual(0, result['stack_delta'])
        self.assertEqual(2, len(result['modeled_words']))
        self.assertEqual(10, result['suppressed_flash_stores'])
        self.assertIn('0xff9550', result['synthetic_helper_calls'])
        self.assertEqual(2, result['native_poll_reads'])

    def test_bad_sum_and_delay_success_never_enter_word_program(self):
        for name, response in (('bad_sum_before_program', '760077'),
                               ('delay_subtype_without_program', '760073')):
            result = self.cases[name][-1]
            self.assertEqual([response], result['responses'])
            self.assertEqual([], result['modeled_words'])
            self.assertEqual('00000000', result['synthetic_flash_hex'])
            self.assertEqual('0xa5', result['d7'])
            self.assertEqual(0, result['stack_delta'])

    def test_destructive_routes_trapped_before_entry(self):
        self.assertEqual('erase_entry', self.cases['erase_dispatch_trapped'][-1]['stop'])
        self.assertEqual('finalize_entry', self.cases['finalize_dispatch_trapped'][-1]['stop'])
        for case in self.report['cases']:
            for result in case['steps']:
                for field in ('flash_commands_executed', 'physical_loader_execution_verified',
                              'transport_used', 'physical_recovery_verified', 'automatic_retry_allowed',
                              'live_write_enabled', 'ready_to_flash'):
                    self.assertFalse(result[field])
                self.assertEqual([], result['would_send'])

    def test_error_then_success_does_not_unwind_pending_program_frame(self):
        entry, failed, success = self.cases['failure_then_success_keeps_pending_frame']
        self.assertEqual(['7600f8'], failed['responses'])
        self.assertEqual('12345679', failed['synthetic_flash_hex'])
        self.assertEqual('0x40', failed['d7'])
        self.assertEqual(-4, failed['stack_delta'])
        self.assertNotIn('0xff9550', failed['synthetic_helper_calls'])
        self.assertEqual(['760073'], success['responses'])
        self.assertEqual('12345678', success['synthetic_flash_hex'])
        self.assertEqual(-4, success['stack_delta'])
        self.assertEqual('0x0', success['d7'])

    def test_repeated_error_accumulates_frames_reentry_only_resets_stack(self):
        entry, first, second, restart = self.cases['repeated_failure_then_software_reentry']
        self.assertEqual([0, -4, -8, 0], [s['stack_delta'] for s in (entry, first, second, restart)])
        self.assertEqual(first['synthetic_flash_hex'], restart['synthetic_flash_hex'])
        self.assertEqual(second['receive_prefix_hex'], restart['receive_prefix_hex'])
        self.assertEqual('0x40', restart['d7'])
        self.assertEqual(255, restart['receive_budget'])
        self.assertFalse(restart['physical_recovery_verified'])

    def test_context_and_terminal_guards(self):
        session = model.LoaderSession(self.code)
        with self.assertRaises(RuntimeError):
            session.frame()
        session.start()
        with self.assertRaises(RuntimeError):
            session.start()
        for args in ({'subtype': True}, {'subtype': 1}, {'fail_word': True},
                     {'fail_word': 2}, {'corrupt_sum': 1}, {'readback': 'physical'}):
            with self.assertRaises(ValueError):
                session.frame(**args)
        session.frame()
        with self.assertRaises(RuntimeError):
            session.frame()
        with self.assertRaises(RuntimeError):
            session.restart()


if __name__ == '__main__':
    unittest.main()
