"""Boundary tests for saved speed/setup timeline; never opens a device."""
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

from checksum import crc16
from decode_trace_containers import SIGNATURE
import inspect_autocal_speed_trace as tool


def wrapper(payload, channel=1, command=0x8a00):
    raw = bytes.fromhex('0154' if channel == 1 else '0152')
    raw += command.to_bytes(2, 'little') + bytes.fromhex('070010000000')
    raw += len(payload).to_bytes(2, 'little') + payload
    return raw + crc16(raw, 0).to_bytes(2, 'little') + (b'\x19' if channel == 2 else b'')


def encoded(rows):
    body = b''.join(struct.pack('<dBHHBI', date, channel, 7, 2, 0x42, len(raw)) + raw
                    for date, channel, raw in rows)
    decoded = SIGNATURE + bytes(1024 - len(SIGNATURE)) + body
    return bytes(((((b ^ 0xa5) >> 3) | ((b ^ 0xa5) << 5)) + 0x87) & 255 for b in zlib.compress(decoded))


class SavedSpeedTimelineTests(unittest.TestCase):
    def test_marker_interval_preserves_file_order_raw_time_and_unknown_local_command(self):
        raw = encoded([(46325.0, 1, wrapper(bytes.fromhex('6cfef0a0'))),
                       (46325.0 + 1 / 86400, 1, wrapper(b'opaque', command=0x9999)),
                       (46325.0 + .5 / 86400, 1, wrapper(bytes.fromhex('6cfef0a1')))])
        report = tool.analyze_bytes(raw)
        interval = report['between_markers'][0]
        self.assertEqual([1], interval['intervening_nonbus_tx_record_ordinals'])
        self.assertEqual([2], report['timestamp_regression_record_ordinals'])
        self.assertAlmostEqual(500, interval['saved_log_delta_ms'], places=2)
        self.assertEqual(struct.pack('<d', 46325.0).hex(), report['marker_windows'][0]['marker']['saved_date_f64_le_hex'])
        self.assertFalse(report['speed_change_verified'])

    def test_rx_groups_are_not_tx_commands_and_nearby_is_not_pairing(self):
        raw = encoded([(1., 1, wrapper(bytes.fromhex('6cfef0a1'))),
                       (1., 2, wrapper(bytes.fromhex('6cf01060'), 2, 0x10))])
        report = tool.analyze_bytes(raw)
        window = report['marker_windows'][0]
        rx = window['nearby_binary_records_in_file_order'][1]
        self.assertIsNone(rx['tx_command_le16'])
        self.assertTrue(rx['bus_context_candidate'])
        self.assertIsNone(rx['response_pairing'])
        self.assertFalse(window['nearby_is_request_response_pairing'])

    def test_setup_exact_shapes_crc_failure_and_large_payload_remain_visible(self):
        damaged = bytearray(wrapper(bytes.fromhex('010010000000'), command=0x8604))
        damaged[-1] ^= 1
        private = b'private-tune-data' + bytes.fromhex('6cfef0a1')
        raw = encoded([(1., 1, bytes(damaged)), (1., 1, wrapper(private, command=0x8415)),
                       (1., 1, wrapper(bytes(7), command=0x8604))])
        report = tool.analyze_bytes(raw)
        self.assertEqual([0], report['outer_crc_failed_record_ordinals'])
        self.assertEqual('010010000000', report['setup_envelopes_in_file_order'][0]['literal_small_setup_payload_hex'])
        self.assertIsNone(report['setup_envelopes_in_file_order'][1]['literal_small_setup_payload_hex'])
        self.assertEqual([], report['marker_windows'])
        self.assertNotIn(private.hex(), json.dumps(report))
        self.assertIn(tool.sha256(private), json.dumps(report))

    def test_last_data_is_prefix_only_and_cleanup_is_retained(self):
        raw = encoded([(1., 2, wrapper(bytes.fromhex('6df01036') + b'data', 2, 0)),
                       (1., 1, wrapper(bytes(6), command=0x8604)),
                       (1., 2, wrapper(b'x' + bytes.fromhex('6df01036'), 2, 0))])
        report = tool.analyze_bytes(raw)
        self.assertEqual(0, report['last_observed_e54_36_data_record'])
        self.assertEqual([1, 2], [e['record_ordinal_zero_based'] for e in report['after_last_observed_e54_36_data_binary_records']])
        self.assertEqual(0, report['setup_tx_counts']['8800'])

    def test_unsupported_wrappers_and_incomplete_container_are_not_silently_accepted(self):
        malformed = bytearray(wrapper(b'x', command=0x9999)); malformed[10] = 7
        raw = encoded([(1., 1, bytes(malformed))])
        report = tool.analyze_bytes(raw)
        self.assertEqual([0], report['unsupported_wrapper_record_ordinals'])
        self.assertIsNone(report['all_nonbus_tx_in_file_order'][0]['outer_crc_matches'])
        with self.assertRaises(ValueError):
            tool.analyze_bytes(raw[:-1])

    def test_private_corpus_selects_context_explicitly_and_does_not_decode_01_as_success(self):
        frame = wrapper(b'\x01', 2, 0x8b01)
        raw = encoded([(1., 1, wrapper(bytes(4), command=0x8b01)), (1., 2, frame)])
        case = tool.setup_reply_corpus(raw)[0]
        self.assertEqual(frame.hex(), case['wrapper_hex'])
        self.assertEqual('0x8B01', case['requested_command_context'])
        self.assertEqual(1, case['expected']['received_payload_bytes'])
        self.assertIsNone(case['expected']['device_success'])
        self.assertIsNone(case['response_pairing'])
        with self.assertRaisesRegex(ValueError, 'small observed'):
            tool.setup_reply_corpus(encoded([(1., 2, wrapper(b'private', 2, 0x8604))]))

    def test_canonical_corpus_cli_schema_and_exact_payload_digests(self):
        frame = wrapper(b'\x01', 2, 0x8b01)
        raw = encoded([(1., 2, frame)])
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            path, output, corpus = directory / 'input.htx', directory / 'report.json', directory / 'corpus.json'
            path.write_bytes(raw)
            tool.main(['--trace', str(path), tool.sha256(raw), '--output', str(output), '--private-setup-corpus', str(corpus)])
            report = json.loads(corpus.read_text())
            self.assertEqual(1, report['schema_version'])
            self.assertEqual(1, report['receive_cases'])
            self.assertTrue(report['rx_context_assumed_for_projection_tests'])
            self.assertFalse(report['rx_request_pairing_established'])
            self.assertFalse(report['physical_protocol_validation'])
            case = report['cases'][0]
            self.assertEqual('device_to_host', case['direction'])
            self.assertEqual(tool.sha256(frame), case['wrapper_sha256'])
            self.assertEqual(tool.sha256(b'\x01'), case['payload_sha256'])
            self.assertEqual(frame[4:10].hex(), case['opaque_header_4_9_hex'])
            self.assertEqual(1, case['payload_bytes'])
            self.assertTrue(case['outer_crc_matches'])

    def test_file_pins_stability_and_exclusive_output(self):
        raw = encoded([(1., 1, wrapper(b'x'))])
        with tempfile.TemporaryDirectory() as directory:
            path, output = Path(directory) / 'trace.htx', Path(directory) / 'out.json'
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
                tool.inspect([(path, '0' * 64)])
            report = tool.inspect([(path, tool.sha256(raw))])
            self.assertFalse(report['adapter_opened'])
            self.assertFalse(report['ready_to_flash'])
            output.write_text('existing')
            with self.assertRaises(SystemExit):
                tool.main(['--trace', str(path), tool.sha256(raw), '--output', str(output)])
            self.assertEqual('existing', output.read_text())
            original = tool.analyze_bytes
            def mutate(data):
                result = original(data); path.write_bytes(data + b'x'); return result
            with patch.object(tool, 'analyze_bytes', side_effect=mutate):
                with self.assertRaisesRegex(ValueError, 'changed'):
                    tool.inspect([(path, tool.sha256(raw))])


if __name__ == '__main__':
    unittest.main()
