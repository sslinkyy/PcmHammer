"""Erase error caller stacks remain distinct from qualified physical recovery."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import emulate_loader_erase_failures as model


class EraseGuards(unittest.TestCase):
    def test_source_pin(self):
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            model.EraseSession(b'wrong')

    def test_owned_code_spans(self):
        for a, b in model.ERASE_RANGES:
            self.assertTrue(model.executable_span(a, 2))
        for pc, size in ((model.BASE+0x25A, 2), (model.BASE+0x236, 2),
                         (model.BASE+0x60C, 2), (model.BASE+0x4A7, 2), (0x8000, 2)):
            self.assertFalse(model.executable_span(pc, size))

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
class NativeEraseFailures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code = Path(os.environ['AL5_CAPTURED_LOADER']).read_bytes()
        cls.report = model.audit(cls.code)
        cls.cases = {c['name']: c['steps'] for c in cls.report['cases']}

    def test_success_uses_two_original_sector_calls_and_balanced_returns(self):
        result = self.cases['both_sectors_stable'][-1]
        self.assertEqual(['7600ee'], result['responses'])
        self.assertEqual(['0x8000', '0x10000'], [s['address'] for s in result['sectors']])
        self.assertEqual([2, 2], [s['reset_stores_suppressed'] for s in result['sectors']])
        self.assertEqual(12, result['suppressed_erase_command_stores'])
        self.assertEqual(3, result['suppressed_id_command_stores'])
        self.assertEqual(1, result['suppressed_id_reset_stores'])
        self.assertEqual(0, result['stack_delta'])
        self.assertEqual([], result['pending_stack_words'])

    def test_id_failure_cleanup_depends_on_which_comparison_failed(self):
        manufacturer = self.cases['manufacturer_mismatch'][-1]
        device = self.cases['device_mismatch'][-1]
        self.assertEqual(0, manufacturer['suppressed_id_reset_stores'])
        self.assertEqual(1, device['suppressed_id_reset_stores'])
        self.assertEqual(1, manufacturer['synthetic_id_reads'])
        self.assertEqual(2, device['synthetic_id_reads'])
        for result in (manufacturer, device):
            self.assertEqual(['760089'], result['responses'])
            self.assertEqual(-4, result['stack_delta'])
            self.assertEqual(['0xff9256'], result['pending_stack_words'])
            self.assertEqual([], result['sectors'])

    def test_sector_failures_leave_distinct_top_return_addresses(self):
        first = self.cases['first_sector_failure'][-1]
        second = self.cases['second_sector_failure'][-1]
        self.assertEqual(['0xff9370', '0xff9358', '0xff9256'], first['pending_stack_words'])
        self.assertEqual(['0xff9378', '0xff9358', '0xff9256'], second['pending_stack_words'])
        self.assertEqual(1, len(first['sectors']))
        self.assertEqual(2, len(second['sectors']))
        for result in (first, second):
            self.assertEqual(['760085'], result['responses'])
            self.assertEqual(-12, result['stack_delta'])
            self.assertEqual(0, result['sectors'][-1]['reset_stores_suppressed'])
            self.assertEqual('0x4', result['d7'])

    def test_bit5_recheck_can_reach_stable_path(self):
        result = self.cases['toggle_then_stable_recheck'][-1]
        self.assertEqual(['7600ee'], result['responses'])
        self.assertEqual(7, result['synthetic_poll_reads'])
        self.assertEqual(2, result['sectors'][0]['reset_stores_suppressed'])
        self.assertEqual(0, result['stack_delta'])

    def test_busy_guard_is_terminal_and_not_a_native_timeout(self):
        session = model.EraseSession(self.code)
        session.start()
        result = session.erase(patterns=('busy', 'stable'), poll_budget=2)
        self.assertEqual('synthetic_poll_budget', result['stop'])
        self.assertEqual(2, result['sectors'][0]['poll_iterations'])
        self.assertEqual([], result['responses'])
        self.assertEqual(-12, result['stack_delta'])
        with self.assertRaises(RuntimeError):
            session.erase()
        with self.assertRaises(RuntimeError):
            session.restart()

    def test_mixed_failures_and_success_retain_old_stack_words(self):
        steps = self.cases['mixed_failures_and_success_do_not_unwind']
        self.assertEqual([0, -12, -16, -16, -16, 0], [s['stack_delta'] for s in steps])
        words = ['0xff91be', '0xff9370', '0xff9358', '0xff9256']
        for result in steps[2:5]:
            self.assertEqual(words, result['pending_stack_words'])
        self.assertEqual(['7600f8'], steps[2]['responses'])
        self.assertEqual(['7600ee'], steps[3]['responses'])
        self.assertEqual(['760073'], steps[4]['responses'])
        self.assertEqual([], steps[-1]['pending_stack_words'])
        self.assertEqual(steps[-2]['synthetic_flash_hex'], steps[-1]['synthetic_flash_hex'])

    def test_repeated_erase_and_id_failures_accumulate(self):
        steps = self.cases['repeated_erase_then_id_failure']
        self.assertEqual([0, -12, -24, -28, -28, 0], [s['stack_delta'] for s in steps])
        self.assertEqual(['0xff9256', '0xff9378', '0xff9358', '0xff9256',
                          '0xff9370', '0xff9358', '0xff9256'], steps[3]['pending_stack_words'])

    def test_repeated_failures_fail_closed_at_model_stack_guard(self):
        session = model.EraseSession(self.code)
        session.start()
        completed = 0
        for _ in range(32):
            try:
                result = session.erase(patterns=('persistent_toggle', 'stable'))
            except RuntimeError as error:
                self.assertRegex(str(error), 'stack escaped|write escaped')
                break
            completed += 1
            self.assertEqual(-12*completed, result['stack_delta'])
        else:
            self.fail('model stack ownership guard did not stop repeated errors')
        self.assertGreater(completed, 1)
        self.assertTrue(session.closed)
        with self.assertRaises(RuntimeError):
            session.frame(readback='synthetic')

    def test_invalid_context_and_unopted_erase_remain_blocked(self):
        session = model.EraseSession(self.code)
        session.start()
        for args in ({'manufacturer': True}, {'device': -1}, {'device': 65536},
                     {'patterns': []}, {'patterns': ('unknown', 'stable')},
                     {'poll_budget': True}, {'poll_budget': 0}, {'poll_budget': 9}):
            with self.assertRaises(ValueError):
                session.erase(**args)
        result = session.frame(subtype=0xEE)
        self.assertEqual('erase_entry', result['stop'])

    def test_no_physical_qualification(self):
        for case in self.report['cases']:
            for result in case['steps']:
                for field in ('physical_erase_mode_verified', 'erased_contents_modeled',
                              'flash_commands_executed', 'physical_loader_execution_verified',
                              'transport_used', 'physical_recovery_verified', 'automatic_retry_allowed',
                              'live_write_enabled', 'ready_to_flash'):
                    self.assertFalse(result[field])
                self.assertEqual([], result['would_send'])


if __name__ == '__main__':
    unittest.main()
