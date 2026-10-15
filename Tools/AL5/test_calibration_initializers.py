"""Guard ownership and optional actual pre-marker initializer preservation."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import emulate_calibration_initializers as initializers


class CalibrationInitializerTests(unittest.TestCase):
    def test_source_hashes_rejected_before_runtime(self):
        with self.assertRaises(ValueError):
            initializers.audit(b'', b'')

    def test_execution_stops_before_calibration_check(self):
        self.assertTrue(initializers.initializer_executable_span(0xC5B54, 8))
        self.assertTrue(initializers.initializer_executable_span(0x21D26, 4))
        self.assertFalse(initializers.initializer_executable_span(0xC5B66, 4))
        self.assertFalse(initializers.initializer_executable_span(0xA96F8, 2))
        self.assertFalse(initializers.initializer_executable_span(0x22B18, 2))
        self.assertFalse(initializers.initializer_executable_span(0x994D0, 0))

    def test_native_writes_cannot_touch_timer_mmio_or_flag_seed(self):
        self.assertTrue(initializers.initializer_writable_span(0xFF8000, 2))
        self.assertTrue(initializers.initializer_writable_span(0xFF8134, 4))
        self.assertFalse(initializers.initializer_writable_span(0xFF8104, 1))
        self.assertFalse(initializers.initializer_writable_span(0xFF8106, 2))
        self.assertFalse(initializers.initializer_writable_span(0xFFFA22, 2))
        self.assertFalse(initializers.initializer_writable_span(0xFFFA24, 2))
        self.assertFalse(initializers.initializer_writable_span(0x1FFFE, 2))

    def test_synthetic_control_bounds_precede_runtime(self):
        with mock.patch.object(initializers, 'validate_source'):
            for value in (True, -1, 0x10000, '0'):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    initializers.pre_marker_initializers(b'', b'', synthetic_timer_control=value)

    def test_report_cannot_overwrite_source_or_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'keep.json'
            path.write_text('keep', encoding='utf-8')
            with mock.patch.object(initializers, 'audit') as audit, mock.patch('sys.stderr'):
                with self.assertRaises(SystemExit):
                    initializers.main(['--low', str(path), '--high', 'absent', '--output', str(path)])
                audit.assert_not_called()
            self.assertEqual('keep', path.read_text(encoding='utf-8'))

    @unittest.skipUnless(os.environ.get('AL5_LOW_DUMP') and os.environ.get('AL5_HIGH_DUMP') and
                         importlib.util.find_spec('unicorn'), 'pinned dumps and optional Unicorn required')
    def test_actual_initializers_preserve_copied_flag_seed(self):
        report = initializers.audit(Path(os.environ['AL5_LOW_DUMP']).read_bytes(),
                                    Path(os.environ['AL5_HIGH_DUMP']).read_bytes())
        self.assertTrue(report['all_pass'])
        self.assertEqual(3, len(report['initializer_cases']))
        self.assertEqual(3, len(report['linked_cases']))
        for case in report['initializer_cases']:
            self.assertEqual('0x994f8', case['stop_pc'])
            self.assertEqual(1, case['initial_check_flag_after_initializers'])
            self.assertEqual(0, case['crc_seed_after_initializers'])
            self.assertEqual('0x20410', case['vector_base_write_source'])
            self.assertTrue(case['movec_instruction_executed'])
            self.assertFalse(case['vector_base_register_readback_verified'])
            self.assertEqual(5, case['interrupt_mask_after_actual_helper'])
            self.assertEqual('0x595', case['application_ram_marker_before_check'])
            self.assertEqual('0xc5a88', case['dynamic_initializer_pointer'])
            self.assertEqual(2, len(case['suppressed_timer_mmio_instructions']))
            self.assertGreater(case['suppressed_startup_watchdog_instruction_count'], 0)
            self.assertEqual([], case['hidden_instruction_substitutions'])
            for effect in case['suppressed_timer_mmio_instructions']:
                self.assertFalse(effect['instruction_executed'])
                self.assertFalse(effect['physical_effect_verified'])
        self.assertFalse(report['complete_hardware_startup_verified'])
        self.assertFalse(report['physical_recovery_verified'])
        self.assertFalse(report['ready_to_flash'])
        self.assertEqual([], report['would_send'])
        success = report['linked_cases'][0]['observed_marker_check']
        self.assertEqual('0x595', success['initial_ram_marker'])
        self.assertEqual('0x595', success['reset_marker'])
        fault = report['linked_cases'][1]['observed_marker_check']
        self.assertEqual('0x595', fault['initial_ram_marker'])
        self.assertEqual('0xcc8b', fault['reset_marker'])


if __name__ == '__main__':
    unittest.main()
