"""Public file reconciliation and native-model interruption boundary checks."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from al5_segment import START, LENGTH, ANCHORS, sha256
from checksum import native_field
import reconcile_al5_snapshot as tool


def candidate():
    data = bytearray(b'\xff'*LENGTH)
    for address, value in ANCHORS.items():
        data[address-START:address-START+len(value)] = value
    data[0x1000:0x1100] = bytes(range(256))
    data[-4:] = native_field(data)
    return bytes(data)


class ReconciliationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = candidate()
        cls.backup = b'\xa5\x5a'*(tool.COLLATERAL_LENGTH//2)
        cls.snapshot = cls.image+cls.backup+bytes.fromhex('4afc')

    def test_complete_file_does_not_prove_operation_or_session(self):
        report = tool.reconcile(self.image, self.snapshot, self.backup)
        self.assertTrue(report['exact_saved_image_match'])
        self.assertFalse(report['observed_zero_to_one_conflict'])
        self.assertEqual('unknown', report['loader_session_state'])
        self.assertEqual('unknown_without_current_physical_evidence', report['operation_outcome'])
        for key in ('physical_readback_verified', 'recovery_verified', 'automatic_retry_enabled',
                    'live_writes_enabled', 'ready_to_flash'):
            self.assertIs(False, report[key])
        self.assertEqual([], report['would_send'])

    def test_absent_snapshot_cannot_be_replaced_by_ack(self):
        report = tool.reconcile(self.image)
        self.assertIsNone(report['calibration'])
        self.assertIsNone(report['completion_marker'])
        self.assertFalse(report['exact_saved_image_match'])

    def test_missing_backup_preserves_unknown_even_for_exact_calibration(self):
        report = tool.reconcile(self.image, self.snapshot)
        self.assertTrue(report['calibration']['exact_match'])
        self.assertIsNone(report['collateral'])
        self.assertFalse(report['exact_saved_image_match'])

    def test_partial_and_overprogrammed_words_differ(self):
        partial = bytearray(self.snapshot)
        partial[0x1000:0x1100] = b'\xff'*256
        report = tool.reconcile(self.image, bytes(partial), self.backup)
        self.assertEqual('one_to_zero_compatible_only', report['calibration']['classification'])
        self.assertEqual(128, report['calibration']['additional_clear_words'])
        partial[0x1000:0x1002] = b'\x00\x00'  # Desired word is 0x0001.
        report = tool.reconcile(self.image, bytes(partial), self.backup)
        self.assertTrue(report['observed_zero_to_one_conflict'])
        self.assertEqual('0x9000', report['calibration']['first_requires_set_address'])

    def test_marker_and_collateral_cannot_hide_behind_calibration_match(self):
        partial = bytearray(self.snapshot)
        partial[-2:] = b'\xff\xff'
        partial[LENGTH:LENGTH+2] = bytes(2)
        report = tool.reconcile(self.image, bytes(partial), self.backup)
        self.assertTrue(report['calibration']['exact_match'])
        self.assertEqual('one_to_zero_compatible_only', report['completion_marker']['classification'])
        self.assertEqual('requires_zero_to_one', report['collateral']['classification'])
        self.assertFalse(report['exact_saved_image_match'])

    def test_invalid_inputs_rejected(self):
        for args in ((b'',), (bytearray(self.image),), (self.image, b''),
                     (self.image, self.snapshot, b''), (self.image[:-4]+bytes(4),)):
            with self.subTest(args_lengths=[len(a) for a in args]):
                with self.assertRaises(ValueError):
                    tool.reconcile(*args)
        with self.assertRaises(ValueError):
            tool.compare_words(b'1', b'1', START)

    def run_cli(self, directory, *extra):
        path = Path(directory)/'candidate.bin'
        path.write_bytes(self.image)
        return subprocess.run([sys.executable, str(Path(tool.__file__)),
            '--candidate', str(path), '--candidate-sha256', sha256(self.image),
            '--output', str(Path(directory)/'report.json'), *extra], capture_output=True, text=True)

    def test_cli_pins_sources_and_emits_only_new_json(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory)/'snapshot.bin'
            snapshot.write_bytes(self.snapshot)
            result = self.run_cli(directory, '--snapshot', str(snapshot),
                                  '--snapshot-sha256', sha256(self.snapshot))
            self.assertEqual(0, result.returncode, result.stderr)
            report = json.loads((Path(directory)/'report.json').read_text(encoding='utf-8'))
            self.assertEqual(str(snapshot.resolve()), report['input_paths']['snapshot'])
            self.assertEqual(sha256(self.snapshot), report['snapshot_sha256'])
            self.assertEqual([], report['would_send'])
            self.assertEqual(self.snapshot, snapshot.read_bytes())

    def test_cli_rejects_missing_pin_wrong_pin_and_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            for extra in (('--snapshot', 'absent'),
                          ('--candidate-sha256', '0'*64)):
                self.assertNotEqual(0, self.run_cli(directory, *extra).returncode)
                self.assertFalse((Path(directory)/'report.json').exists())
            output = Path(directory)/'report.json'
            output.write_bytes(b'keep')
            self.assertNotEqual(0, self.run_cli(directory).returncode)
            self.assertEqual(b'keep', output.read_bytes())

    def test_pinned_reader_bounds_allocation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'large.bin'
            path.write_bytes(bytes(0x20001))
            with self.assertRaises(ValueError):
                tool.pinned_file(path, sha256(path.read_bytes()))

    def test_write_plan_binds_reconciler_without_granting_authority(self):
        from write_plan import plan
        report = plan(self.image, self.image, sha256(self.image), 'AL5', 15184109)
        recovery = report['calibration_recovery_assessment']
        self.assertEqual(sha256(Path(tool.__file__).read_bytes()),
                         recovery['implementations']['reconcile_al5_snapshot.py'])
        self.assertFalse(recovery['saved_snapshot_reconciliation']['physical_state_or_retry_authority'])
        self.assertEqual([], report['would_send'])
        self.assertEqual([], report['erase_packets'])
        self.assertEqual([], report['program_packets'])


@unittest.skipUnless(os.environ.get('AL5_LOW_DUMP') and os.environ.get('AL5_CAPTURED_LOADER') and
                     importlib.util.find_spec('unicorn'), 'requires pinned native inputs and Unicorn')
class NativeReconciliation(unittest.TestCase):
    def test_native_lost_ack_partial_and_conflict_snapshots(self):
        from emulate_al5_interruptions import InterruptionSession, enter_loader
        low = Path(os.environ['AL5_LOW_DUMP']).read_bytes()
        code = Path(os.environ['AL5_CAPTURED_LOADER']).read_bytes()
        image = candidate()
        for kind in ('lost_ack', 'after_word', 'overprogrammed_word'):
            with self.subTest(kind=kind):
                session = InterruptionSession(low, code)
                enter_loader(session)
                session.erase()
                if kind == 'lost_ack':
                    session.timeout_at_byte = 6
                else:
                    session.arm_interruption(kind, occurrence=1)
                result = session.program_block(START+0x1000, image[0x1000:0x1100])
                snapshot = session.snapshot()
                report = tool.reconcile(image, snapshot.flash, snapshot.collateral_backup)
                comparison = tool.compare_words(snapshot.flash[0x1000:0x1100],
                                                image[0x1000:0x1100], START+0x1000)
                if kind == 'lost_ack':
                    self.assertEqual(0, result['native_sender_returns'])
                    self.assertEqual('exact', comparison['classification'])
                elif kind == 'after_word':
                    self.assertEqual('one_to_zero_compatible_only', comparison['classification'])
                else:
                    self.assertEqual('requires_zero_to_one', comparison['classification'])
                    self.assertTrue(report['observed_zero_to_one_conflict'])
                self.assertFalse(report['automatic_retry_enabled'])
                self.assertEqual('unknown', report['loader_session_state'])


if __name__ == '__main__':
    unittest.main()
