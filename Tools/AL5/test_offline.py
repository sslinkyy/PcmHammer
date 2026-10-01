"""Run with python -m unittest discover -s Tools/AL5 -p test_offline.py."""
import unittest
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from al5_segment import START, LENGTH, ANCHORS, sha256, validate, diff_ranges, word_sum
from write_plan import plan
from checksum import native_field, crc16, checksum_valid


def fixture():
    data = bytearray(LENGTH)
    for a, expected in ANCHORS.items():
        data[a-START:a-START+len(expected)] = expected
    data[-4:] = native_field(data)
    return bytes(data)


class OfflineSafetyTests(unittest.TestCase):
    def test_short_and_editor_images_rejected(self):
        self.assertTrue(validate(bytes(LENGTH-1)))
        self.assertTrue(validate(bytes(1024*1024)))

    def test_identity_and_high_address_anchors_required(self):
        self.assertFalse(validate(fixture()))
        bad = bytearray(fixture())
        bad[0x158A8-START] ^= 1
        self.assertTrue(validate(bad))

    def test_unchanged_input_cannot_enable_write(self):
        data = fixture()
        report = plan(data, data, sha256(data), 'AL5', 15184109)
        self.assertEqual([], report['input_errors'])
        self.assertFalse(report['ready_to_flash'])
        self.assertFalse(report['live_write_enabled'])
        self.assertEqual([], report['would_send'])
        self.assertTrue(report['blockers'])

    def test_hash_and_context_rejected(self):
        data = fixture()
        report = plan(data, data, '0'*64, 'E54', 1)
        self.assertTrue(any('SHA256' in e for e in report['input_errors']))
        self.assertTrue(any('context' in e for e in report['input_errors']))

    def test_boot_emulation_evidence_cannot_enable_live_session_or_packets(self):
        data = fixture()
        report = plan(data, data, sha256(data), 'AL5', 15184109)
        boot = report['boot_loader_assessment']
        self.assertTrue(boot['offline_cases_pass'])
        evidence = Path(__file__).resolve().parents[2]/boot['evidence']
        self.assertEqual(sha256(evidence.read_bytes()), boot['evidence_sha256'])
        self.assertFalse(boot['application_entry_verified'])
        self.assertFalse(boot['live_session_authorized'])
        self.assertFalse(report['ready_to_flash'])
        self.assertIsNone(report['program_block_size'])
        for key in ('would_send', 'erase_packets', 'program_packets'):
            self.assertEqual([], report[key])

    def test_collateral_inference_never_becomes_executable_erase_scope(self):
        data = fixture()
        report = plan(data, data, sha256(data), 'AL5', 15184109)
        preservation = report['preservation_assessment']
        self.assertEqual(41000, preservation['outside_calibration_bytes_inferred'])
        self.assertIn('unverified', preservation['confidence'])
        self.assertFalse(preservation['preservation_verified'])
        self.assertFalse(preservation['current_collateral_backup_supplied'])
        self.assertIsNone(report['erase_scope'])
        self.assertFalse(report['ready_to_flash'])
        self.assertEqual([], report['erase_packets'])
        self.assertTrue(any('collateral' in b for b in report['blockers']))

    def test_cli_valid_input_still_returns_blocked_exit_code(self):
        data = fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'current.bin'
            path.write_bytes(data)
            result = subprocess.run([sys.executable, str(Path(__file__).with_name('write_plan.py')),
                '--current', str(path), '--candidate', str(path),
                '--expected-current-sha256', sha256(data), '--controller', 'AL5',
                '--os-id', '15184109'], capture_output=True, text=True, check=False)
        self.assertEqual(2, result.returncode, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual([], report['input_errors'])
        self.assertFalse(report['ready_to_flash'])
        self.assertEqual([], report['would_send'])
        self.assertFalse(report['preservation_assessment']['preservation_verified'])

    def test_unknown_code_and_checksum_edits_rejected(self):
        data = fixture()
        bad = bytearray(data)
        bad[0x10A24-START] = 0x40
        bad[-1] ^= 1
        report = plan(data, bad, sha256(data), 'AL5', 15184109)
        self.assertTrue(any('0x10A24' in e for e in report['input_errors']))
        self.assertTrue(any('checksum invalid' in e for e in report['input_errors']))
        self.assertEqual([], report['program_packets'])

    def test_allowlisted_address_does_not_allow_arbitrary_values(self):
        data = fixture()
        bad = bytearray(data)
        bad[0x821C-START] = 1
        report = plan(data, bad, sha256(data), 'AL5', 15184109)
        self.assertTrue(any('supplied target' in e for e in report['input_errors']))

    def test_diff_includes_first_and_last_bytes(self):
        data = bytes(LENGTH)
        bad = bytearray(data)
        bad[0] = bad[-1] = 1
        ranges = diff_ranges(data, bad)
        self.assertEqual(['0x08000', '0x15FD7'], [r['start'] for r in ranges])

    def test_crc_known_vector(self):
        self.assertEqual(0xBB3D, crc16(b'123456789'))

    def test_zero_sum_is_not_native_checksum_validation(self):
        data = bytearray(fixture())
        data[-4] ^= 1
        data[-2:] = b'\x00\x00'
        data[-2:] = ((-word_sum(data)) & 0xFFFF).to_bytes(2, 'big')
        self.assertEqual(0, word_sum(data))
        self.assertFalse(checksum_valid(data))
        report = plan(data, data, sha256(data), 'AL5', 15184109)
        self.assertTrue(any('native' in e for e in report['input_errors']))

    def test_checksum_correction_changes_only_field(self):
        data = bytearray(fixture())
        data[0x821C-START] ^= 1
        corrected = data[:-4] + native_field(data)
        self.assertEqual(corrected[:-4], data[:-4])
        self.assertEqual(0, word_sum(corrected))
        self.assertTrue(checksum_valid(corrected))


if __name__ == '__main__':
    unittest.main()
