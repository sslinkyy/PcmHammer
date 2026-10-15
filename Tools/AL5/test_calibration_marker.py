"""Offline calibration-marker ownership guards and optional pinned native cases."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import emulate_calibration_marker as marker


class CalibrationMarkerTests(unittest.TestCase):
    def test_source_identity_rejected_before_emulator(self):
        with self.assertRaises(ValueError):
            marker.audit(b'', b'')
        with self.assertRaises(ValueError):
            marker.marker_case(bytes(0x20000), bytes(0xE0000))

    def test_execution_owner_excludes_flash_and_transport(self):
        self.assertTrue(marker.executable_address(0xA9704))
        self.assertTrue(marker.executable_address(0xA95D0))
        self.assertTrue(marker.executable_address(0xA9668))
        self.assertFalse(marker.executable_address(0xA97E0))
        self.assertFalse(marker.executable_address(0x2A24))
        self.assertFalse(marker.executable_address(0x3B7C))
        self.assertFalse(marker.executable_address(0xFF9100))
        self.assertFalse(marker.executable_span(0xA97DE, 4))
        self.assertFalse(marker.executable_span(0xA95D0, 0))

    def test_write_owner_excludes_flash_and_mmio(self):
        self.assertTrue(marker.writable_span(marker.BASE, 2))
        self.assertTrue(marker.writable_span(marker.BASE + 0x106, 2))
        self.assertTrue(marker.writable_span(marker.BASE + 0x1F7C, 4))
        self.assertFalse(marker.writable_span(0x1FFFE, 2))
        self.assertFalse(marker.writable_span(0x8000, 2))
        self.assertFalse(marker.writable_span(0xFFE800, 1))
        self.assertFalse(marker.writable_span(marker.BASE + 0x103, 2))
        self.assertFalse(marker.writable_span(marker.BASE + 0x108, 1))
        self.assertFalse(marker.writable_span(marker.BASE, 0))

    def test_existing_report_preserved_before_sources_or_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'existing.json'
            output.write_text('keep', encoding='utf-8')
            with mock.patch.object(marker, 'audit') as audit, mock.patch('sys.stderr'):
                with self.assertRaises(SystemExit):
                    marker.main(['--low', 'absent-low', '--high', 'absent-high', '--output', str(output)])
                audit.assert_not_called()
            self.assertEqual('keep', output.read_text(encoding='utf-8'))

    def test_context_bounds_before_optional_runtime(self):
        with mock.patch.object(marker, 'validate_source'):
            for context in ({'marker': -1}, {'marker': 0x10000}, {'initial_check': 1},
                            {'marker': True}, {'calibration': b''}, {'calibration': 100000000},
                            {'crc_seed': 0x10000}, {'crc_seed': True}, {'stride': 0}, {'stride': True},
                            {'current_start': True}, {'current_end': True},
                            {'current_start': 0x7FFF}, {'current_end': 0x15FD5}):
                with self.subTest(context=context), self.assertRaises(ValueError):
                    marker.marker_case(bytes(0x20000), b'', **context)

    @unittest.skipUnless(os.environ.get('AL5_LOW_DUMP') and os.environ.get('AL5_HIGH_DUMP') and
                         importlib.util.find_spec('unicorn'), 'pinned dumps and optional Unicorn required')
    def test_native_marker_crc_and_selected_reset_routes(self):
        report = marker.audit(Path(os.environ['AL5_LOW_DUMP']).read_bytes(),
                              Path(os.environ['AL5_HIGH_DUMP']).read_bytes())
        self.assertTrue(report['all_pass'])
        self.assertEqual(9, len(report['cases']))
        cases = {case['name']: case for case in report['cases']}
        self.assertEqual('0xcc8b', cases['erased_marker']['observed']['reset_marker'])
        self.assertEqual('0x3e91', cases['payload_bit_fault']['selected_reset_branch']['marker_after'])
        self.assertEqual('0xc12a', cases['crc_correct_identifier_fault']['selected_reset_branch']['marker_after'])
        self.assertEqual('returned', cases['compensation_only_fault']['observed']['stop'])
        self.assertEqual(0, cases['clear_initial_flag_erased_marker']['observed']['marker_reads'])
        self.assertEqual('returned', cases['clear_initial_flag_erased_marker']['observed']['stop'])
        for case in report['cases']:
            self.assertFalse(case['observed']['ready_to_flash'])
            self.assertFalse(case['observed']['live_write_enabled'])
            self.assertFalse(case['observed']['physical_recovery_verified'])
        self.assertFalse(report['physical_recovery_verified'])
        self.assertEqual([], report['would_send'])


if __name__ == '__main__':
    unittest.main()
