"""Startup ROM-copy provenance and explicitly partial marker handoff tests."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import emulate_calibration_startup as startup


class CalibrationStartupTests(unittest.TestCase):
    def test_sources_rejected_before_optional_runtime(self):
        with self.assertRaises(ValueError):
            startup.audit(b'', b'')

    def test_exact_rom_to_ram_mapping(self):
        self.assertEqual(0xC5F46, startup.FLAG_SOURCE)
        self.assertEqual(0xC5F48, startup.SEED_SOURCE)
        self.assertEqual(0x138, startup.PREFIX_END - startup.PREFIX_START)
        self.assertEqual(0x3670, startup.CLEAR_END - startup.PREFIX_END)

    def test_narrow_execution_and_write_ownership(self):
        self.assertTrue(startup.executable_span(0xBE4F4, 2))
        self.assertFalse(startup.executable_span(0xBE53E, 4))
        self.assertFalse(startup.executable_span(0x5B8EC, 2))
        self.assertFalse(startup.executable_span(0x22B18, 2))
        self.assertTrue(startup.writable_span(0xFF8104, 4))
        self.assertTrue(startup.writable_span(0xFFFA27, 1))
        self.assertFalse(startup.writable_span(0xFFFA27, 2))
        self.assertFalse(startup.writable_span(0xFFB7B0, 1))
        self.assertFalse(startup.writable_span(0xFF8000, 2))
        self.assertFalse(startup.writable_span(0x1FFFE, 2))

    def test_fill_rejected_before_optional_runtime(self):
        with mock.patch.object(startup, 'validate_source'):
            for fill in (True, -1, 256, 'A5'):
                with self.subTest(fill=fill), self.assertRaises(ValueError):
                    startup.copied_initial_state(b'', b'', fill=fill)

    def test_existing_report_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'existing.json'
            output.write_text('keep', encoding='utf-8')
            with mock.patch.object(startup, 'audit') as audit, mock.patch('sys.stderr'):
                with self.assertRaises(SystemExit):
                    startup.main(['--low', 'absent', '--high', 'absent', '--output', str(output)])
                audit.assert_not_called()
            self.assertEqual('keep', output.read_text(encoding='utf-8'))

    @unittest.skipUnless(os.environ.get('AL5_LOW_DUMP') and os.environ.get('AL5_HIGH_DUMP') and
                         importlib.util.find_spec('unicorn'), 'pinned dumps and optional Unicorn required')
    def test_native_copy_produces_flag_and_seed(self):
        report = startup.audit(Path(os.environ['AL5_LOW_DUMP']).read_bytes(),
                               Path(os.environ['AL5_HIGH_DUMP']).read_bytes())
        self.assertTrue(report['all_pass'])
        self.assertEqual(2, len(report['initialization_cases']))
        self.assertEqual(6, len(report['linked_cases']))
        for case in report['initialization_cases']:
            self.assertEqual(1, case['initial_check_flag'])
            self.assertEqual(0, case['crc_seed'])
            self.assertEqual(312, case['copied_unique_bytes'])
            self.assertEqual(13936, case['cleared_unique_bytes'])
            self.assertTrue(case['flag_native_writes'])
            self.assertTrue(case['prefix_matches_pinned_rom'])
            self.assertFalse(case['intervening_initializers_executed'])
        for case in report['linked_cases']:
            self.assertEqual(1, case['observed_marker_check']['marker_reads'])
            self.assertFalse(case['intervening_initializers_executed'])
        self.assertFalse(report['complete_startup_verified'])
        self.assertFalse(report['physical_recovery_verified'])
        self.assertFalse(report['ready_to_flash'])
        self.assertEqual([], report['would_send'])


if __name__ == '__main__':
    unittest.main()
