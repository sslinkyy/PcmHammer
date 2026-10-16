"""Integrated interruption/retry tests preserve unknowns and hardware gates."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import emulate_al5_interruptions as model


class InterruptionGuards(unittest.TestCase):
    def test_snapshot_requires_explicit_exact_bytes_and_optional_backup(self):
        for data in (b'', bytearray(model.FLASH_LENGTH)):
            with self.assertRaises(ValueError):
                model.ModelSnapshot(data, None)
        with self.assertRaises(ValueError):
            model.ModelSnapshot(bytes(model.FLASH_LENGTH), b'')
        self.assertIsNone(model.ModelSnapshot(bytes(model.FLASH_LENGTH), None).collateral_backup)

    def test_fault_bounds_and_closed_state(self):
        session = model.InterruptionSession.__new__(model.InterruptionSession)
        session.closed = False
        for kind, count in (('unknown', 1), ('after_word', True), ('after_word', 0),
                            ('after_word', 129), ('before_marker', 2), ('after_sector_erase', 3)):
            with self.assertRaises(ValueError):
                session.arm_interruption(kind, occurrence=count)
        session.closed = True
        with self.assertRaises(RuntimeError):
            session.arm_interruption('after_word')

    def test_cli_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'keep.json'
            path.write_text('keep', encoding='utf-8')
            with patch.object(model, 'audit') as audit, patch('sys.stderr'):
                with self.assertRaises(SystemExit):
                    model.main(['--low', 'absent', '--loader', 'absent', '--output', str(path)])
                audit.assert_not_called()
            self.assertEqual('keep', path.read_text(encoding='utf-8'))


@unittest.skipUnless(os.environ.get('AL5_LOW_DUMP') and os.environ.get('AL5_CAPTURED_LOADER') and
                     importlib.util.find_spec('unicorn'), 'requires pinned LOW/loader and Unicorn')
class NativeInterruptionMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.low = Path(os.environ['AL5_LOW_DUMP']).read_bytes()
        cls.code = Path(os.environ['AL5_CAPTURED_LOADER']).read_bytes()
        cls.report = model.audit(cls.low, cls.code)
        cls.cases = {c['name']: c for c in cls.report['cases']}

    def test_interrupted_sector_closes_original_session_and_preserves_partial_model(self):
        session = model.InterruptionSession(self.low, self.code)
        model.enter_loader(session)
        session.arm_interruption('after_sector_erase')
        result = session.erase()
        self.assertEqual('modeled_interruption', result['stop'])
        self.assertEqual(-12, result['stack_delta'])
        self.assertTrue(session.closed)
        self.assertEqual(b'\xFF'*4, bytes(session.uc.mem_read(model.START, 4)))
        self.assertEqual(b'\x5A'*4, bytes(session.uc.mem_read(0x10000, 4)))
        with self.assertRaises(RuntimeError):
            session.program_block(model.START, b'12')

    def test_fresh_instance_copies_flash_and_optional_backup_but_no_cpu_ram(self):
        session = model.InterruptionSession(self.low, self.code)
        model.enter_loader(session)
        session.uc.mem_write(0xFF8200, b'RAM!')
        snapshot = session.snapshot(include_backup=False)
        fresh = model.InterruptionSession(self.low, self.code, snapshot=snapshot)
        self.assertEqual(snapshot.flash, bytes(fresh.uc.mem_read(model.START, model.FLASH_LENGTH)))
        self.assertEqual(bytes(4), bytes(fresh.uc.mem_read(0xFF8200, 4)))
        self.assertEqual('boot', fresh.phase)
        self.assertIsNone(fresh.collateral_before)
        self.assertEqual(bytes(len(self.code)), bytes(fresh.uc.mem_read(model.BASE, len(self.code))))

    def test_reconstruction_after_erase_requires_external_collateral_baseline(self):
        kept = self.cases['erase_interruption_with_backup']['result']['verification']
        lost = self.cases['erase_interruption_backup_missing']['result']['verification']
        self.assertTrue(kept['offline_verification_pass'])
        self.assertTrue(kept['collateral_backup_available'])
        self.assertFalse(lost['collateral_backup_available'])
        self.assertIsNone(lost['collateral_before_sha256'])
        self.assertIsNone(lost['collateral_matches'])
        self.assertTrue(lost['exact_calibration_match'])
        self.assertFalse(lost['offline_verification_pass'])

    def test_partial_word_sequence_retry_is_idempotent_only_under_model(self):
        case = self.cases['partial_block_retry']
        self.assertEqual(-4, case['interrupted_stack_delta'])
        self.assertEqual(['760073'], case['retry_responses'])
        self.assertEqual(0, case['retry_stack_delta'])
        self.assertTrue(case['result']['verification']['offline_verification_pass'])

    def test_unwanted_cleared_bit_blocks_retry_and_reerase_retains_new_pending_frame(self):
        case = self.cases['overprogrammed_word_requires_reerase']
        self.assertEqual('0x0', case['interruption']['detail']['chosen_fault_word'])
        self.assertEqual('0x1', case['interruption']['detail']['requested'])
        self.assertEqual(['7600f8'], case['retry_responses'])
        self.assertEqual(-4, case['retry_stack_delta'])
        self.assertEqual(-4, case['result']['final_stack_delta'])
        self.assertTrue(case['result']['verification']['offline_verification_pass'])

    def test_lost_ack_duplicate_and_conflicting_retries(self):
        case = self.cases['lost_ack_duplicate_and_conflicting_retry']
        self.assertEqual(0, case['lost_ack_sender_returns'])
        self.assertEqual(1, len(case['sender_timeout_jumps']))
        self.assertEqual(['760073'], case['duplicate_responses'])
        self.assertEqual(['7600f8'], case['conflicting_responses'])
        self.assertEqual(-4, case['conflicting_stack_delta'])
        self.assertEqual(-4, case['result']['final_stack_delta'])
        self.assertTrue(case['result']['verification']['offline_verification_pass'])

    def test_before_marker_interruption_needs_completion_word(self):
        case = self.cases['interruption_before_marker']
        self.assertEqual([], case['final_status_before_interruption'])
        self.assertTrue(case['verification_before_restart']['native_checksum_valid'])
        self.assertFalse(case['verification_before_restart']['completion_marker_matches'])
        self.assertFalse(case['verification_before_restart']['offline_verification_pass'])
        self.assertEqual(['760086'], case['final_responses'])
        self.assertTrue(case['verification_after_restart']['offline_verification_pass'])

    def test_after_marker_image_can_match_without_finalize_ack(self):
        case = self.cases['interruption_after_marker']
        self.assertEqual([], case['final_status_before_interruption'])
        self.assertTrue(case['verification_before_restart']['offline_verification_pass'])
        self.assertTrue(case['verification_after_restart']['offline_verification_pass'])

    def test_interruption_and_recovery_are_not_physically_qualified(self):
        for field in ('physical_recovery_verified', 'physical_interruption_verified',
                      'automatic_retry_allowed', 'live_write_enabled', 'ready_to_flash'):
            self.assertFalse(self.report[field])
        self.assertEqual([], self.report['would_send'])
        for case in self.report['cases']:
            if 'interruption' in case:
                self.assertFalse(case['interruption']['physical_interruption_observed'])
            if 'old_ram_not_copied' in case:
                self.assertTrue(case['old_ram_not_copied'])
                self.assertTrue(case['fresh_emulator_selected_boot_entry'])


if __name__ == '__main__':
    unittest.main()
