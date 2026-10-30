"""Offline distinctions between the native polling and VM setup producers."""
import unittest

from inspect_autocal_speed_configuration import logging_setup_payloads


class LoggingSetupProjectionTests(unittest.TestCase):
    def test_named_poll_setting_and_fixed_call_parameter(self):
        self.assertEqual(logging_setup_payloads(1, 1500, 0, 0), [
            {'command': '0x8603', 'payload_hex': '0100f401', 'host_call_argument4': 100},
            {'command': '0x8604', 'payload_hex': '010000000000', 'host_call_argument4': 1500},
        ])
        self.assertEqual(logging_setup_payloads(6, 0, 0, 0), [
            {'command': '0x8604', 'payload_hex': '060000000000', 'host_call_argument4': 1500},
        ])

    def test_signed_nonpositive_input_skips_interval_command(self):
        for value in (-0x80000000, -1, 0):
            self.assertEqual(len(logging_setup_payloads(0, value, 0, 0)), 1)

    def test_native_poll_producer_narrows_instead_of_vm_range_check(self):
        self.assertEqual(logging_setup_payloads(1, 65535999, 0, 0)[0]['payload_hex'], 'ffffe703')
        self.assertEqual(logging_setup_payloads(1, 65536000, 0, 0)[0]['payload_hex'], '00000000')
        self.assertEqual(logging_setup_payloads(0x101, 0, 0x100, 0x12345678)[0]['payload_hex'], '010078563412')

    def test_analysis_input_widths_are_explicit(self):
        for args in ((1, 0x80000000, 0, 0), (1, -0x80000001, 0, 0),
                     (-1, 0, 0, 0), (1, 0, 0, 0x100000000), (1, True, 0, 0)):
            with self.assertRaises(ValueError):
                logging_setup_payloads(*args)


if __name__ == '__main__':
    unittest.main()
