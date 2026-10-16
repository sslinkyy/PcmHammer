"""Integrated synthetic flash reconstruction must independently verify output."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import emulate_al5_program_session as model


class ProgramSessionGuards(unittest.TestCase):
    def test_source_and_image_guards(self):
        with self.assertRaises(ValueError):
            model.ProgramSession(b'wrong', b'wrong')
        with self.assertRaises(ValueError):
            model.run_case(b'wrong', b'wrong', b'wrong')
        self.assertTrue(model.checksum_valid(model.fixture()))

    def test_finalizer_instruction_ownership(self):
        self.assertTrue(model.executable_span(model.BASE+0x1D6, 6))
        self.assertTrue(model.executable_span(model.BASE+0x232, 4))
        self.assertFalse(model.executable_span(model.BASE+0x236, 2))
        self.assertFalse(model.executable_span(0x8000, 2))

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
class NativeProgramSession(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.low = Path(os.environ['AL5_LOW_DUMP']).read_bytes()
        cls.code = Path(os.environ['AL5_CAPTURED_LOADER']).read_bytes()
        cls.report = model.audit(cls.low, cls.code)
        cls.cases = {c['name']: c for c in cls.report['cases']}

    def test_dense_complete_calibration_and_preserved_collateral(self):
        result = self.cases['complete_dense_calibration']
        self.assertEqual(['6df0187444'], result['boot_arm_response'])
        self.assertEqual(1590, result['handoff']['native_uploaded_bytes'])
        self.assertEqual([{'start': '0x8000', 'exclusive_end': '0x10000'},
                          {'start': '0x10000', 'exclusive_end': '0x20000'}], result['erase_ranges'])
        self.assertEqual(224, result['calibration']['blocks_completed'])
        self.assertEqual(model.LENGTH, result['calibration']['native_program_bytes'])
        self.assertEqual(0, result['calibration']['blocks_skipped_erased'])
        self.assertEqual(40998, result['collateral']['bytes_reconstructed'])
        self.assertEqual(['760086'], result['finalization']['responses'])
        self.assertEqual('reset_exit', result['finalization']['stop'])
        self.assertEqual(0, result['finalization']['stack_delta'])
        self.assertTrue(result['verification']['offline_verification_pass'])
        self.assertTrue(result['verification']['collateral_matches'])
        self.assertEqual(result['calibration']['expected_sha256'], result['verification']['readback_sha256'])

    def test_zero_sum_bad_crc_is_rejected_despite_finalize_success(self):
        result = self.cases['zero_sum_bad_crc_rejected']
        self.assertEqual(['760086'], result['finalization']['responses'])
        verification = result['verification']
        self.assertTrue(verification['exact_calibration_match'])
        self.assertTrue(verification['be16_sum_zero'])
        self.assertTrue(verification['completion_marker_matches'])
        self.assertFalse(verification['native_checksum_valid'])
        self.assertFalse(verification['offline_verification_pass'])

    def test_missing_collateral_restore_rejects_otherwise_valid_image(self):
        result = self.cases['collateral_not_restored_rejected']
        self.assertEqual(['760086'], result['finalization']['responses'])
        verification = result['verification']
        self.assertTrue(verification['native_checksum_valid'])
        self.assertTrue(verification['exact_calibration_match'])
        self.assertFalse(verification['collateral_matches'])
        self.assertFalse(verification['offline_verification_pass'])

    def test_marker_failure_returns_with_pending_frame_and_rejects(self):
        result = self.cases['marker_failure_rejected']
        self.assertEqual(['7600f8'], result['finalization']['responses'])
        self.assertEqual('receive_boundary', result['finalization']['stop'])
        self.assertEqual(-4, result['finalization']['stack_delta'])
        self.assertFalse(result['verification']['completion_marker_matches'])
        self.assertFalse(result['verification']['offline_verification_pass'])

    def test_post_finalization_fault_is_detected(self):
        result = self.cases['complete_dense_calibration']
        failed = result['post_finalization_fault_check']
        self.assertTrue(result['verification']['offline_verification_pass'])
        self.assertTrue(failed['completion_marker_matches'])
        self.assertFalse(failed['exact_calibration_match'])
        self.assertFalse(failed['native_checksum_valid'])
        self.assertFalse(failed['offline_verification_pass'])

    def test_region_and_lifecycle_guards(self):
        session = model.ProgramSession(self.low, self.code)
        with self.assertRaises(RuntimeError):
            session.program_region(model.START, b'\xFF\xFF', sparse=True)
        session.boot_interrupt(model.frame_events(bytes.fromhex('6d18f034')))
        session.boot_interrupt(model.captured_upload_events(self.code))
        for address, payload in ((model.START+1, b'12'), (model.MARKER, b'12'),
                                 (0, b'12'), (model.START, b''), (model.START, b'1'),
                                 (model.START, b'1'*(model.BLOCK_BYTES+2))):
            with self.assertRaises(ValueError):
                session.program_block(address, payload)
        with self.assertRaises(ValueError):
            session.program_region(model.START, b'')
        with self.assertRaises(RuntimeError):
            session.program_region(model.START, b'\xFF\xFF', sparse=True)
        with self.assertRaises(ValueError):
            session.verify(b'wrong')
        with self.assertRaises(ValueError):
            session.finalize(marker_matches=1)

    def test_native_program_model_requires_erase_for_zero_to_one_bits(self):
        session = model.ProgramSession(self.low, self.code)
        session.boot_interrupt(model.frame_events(bytes.fromhex('6d18f034')))
        session.boot_interrupt(model.captured_upload_events(self.code))
        failed = session.program_block(model.START, b'\xFF\xFF')
        self.assertEqual(['7600f8'], failed['responses'])
        self.assertEqual(b'\x5A\x5A', bytes(session.uc.mem_read(model.START, 2)))
        self.assertEqual(-4, failed['stack_delta'])

    def test_physical_qualification_remains_false(self):
        for result in self.report['cases']:
            self.assertTrue(result['same_native_session'])
            self.assertFalse(result['physical_programming_verified'])
            self.assertFalse(result['verification']['physical_readback_verified'])
            self.assertFalse(result['ready_to_flash'])
            self.assertFalse(result['live_write_enabled'])
            self.assertEqual([], result['would_send'])
        for field in ('physical_programming_verified', 'physical_readback_verified',
                      'physical_recovery_verified', 'automatic_retry_allowed', 'ready_to_flash', 'live_write_enabled'):
            self.assertFalse(self.report[field])


if __name__ == '__main__':
    unittest.main()
