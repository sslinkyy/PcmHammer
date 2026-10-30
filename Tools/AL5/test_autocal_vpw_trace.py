"""Boundary tests for file-only setup inventory; no physical capability claims."""
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

import inspect_autocal_vpw_trace as tool
from checksum import crc16
from decode_trace_containers import SIGNATURE


def wrapper(payload, channel=1, group='008a', metadata='070010000000'):
    head = bytes.fromhex('0154' if channel == 1 else '0152') + bytes.fromhex(group + metadata)
    head += len(payload).to_bytes(2, 'little') + payload
    return head + crc16(head, 0).to_bytes(2, 'little') + (b'\x19' if channel == 2 else b'')


def encoded(items):
    body = b''.join(struct.pack('<dBHHBI', 46325.0, channel, 7, 2, 0x42, len(raw)) + raw
                    for channel, raw in items)
    decoded = SIGNATURE + bytes(1024 - len(SIGNATURE)) + body
    return bytes(((((b ^ 0xa5) >> 3) | ((b ^ 0xa5) << 5)) + 0x87) & 255 for b in zlib.compress(decoded))


class SavedVpwTraceTests(unittest.TestCase):
    def test_local_payload_never_scanned_or_exported(self):
        private = b'private-tune-bytes' + bytes.fromhex('6cfef0a1')
        report, bus = tool.analyze_bytes(encoded([(1, wrapper(private, group='1584'))]))
        self.assertEqual([], bus)
        self.assertEqual([], report['speed_marker_candidates'])
        self.assertNotIn(private.hex(), json.dumps(report))
        self.assertEqual(tool.sha256(private), report['binary_records'][0][7])

    def test_offsets_rx_raw_groups_and_no_pairing(self):
        payload = bytes.fromhex('6cf010750154')
        raw = wrapper(payload, 2, '1000', '000007000000')
        report, bus = tool.analyze_bytes(encoded([(2, raw)]))
        row = report['binary_records'][0]
        self.assertEqual(1024, row[1])
        self.assertEqual(raw[:12].hex(), row[3])
        self.assertEqual(tool.sha256(raw), row[5])
        self.assertEqual('10000000', bus[0]['word2'])
        self.assertFalse(report['rx_route_verified'])
        self.assertFalse(report['rx_request_context_supplied'])
        self.assertIsNone(report['response_pairing'])

    def test_setup_shapes_are_exact_and_crc_failures_retained(self):
        small = wrapper(bytes.fromhex('010010000000'), group='0486', metadata='070000000000')
        damaged = bytearray(small); damaged[-1] ^= 1
        oversized = wrapper(bytes(7), group='0486')
        report, _ = tool.analyze_bytes(encoded([(1, small), (1, bytes(damaged)), (1, oversized)]))
        self.assertEqual(2, len(report['small_setup_events']))
        self.assertEqual([1], report['outer_crc_failed_record_ordinals'])
        self.assertTrue(report['small_setup_events'][0]['outer_crc_matches'])
        self.assertFalse(report['small_setup_events'][1]['outer_crc_matches'])
        self.assertEqual(1054, report['small_setup_events'][0]['payload_decoded_offset'])

    def test_a1_marker_does_not_invent_speed_or_flags(self):
        messages = [bytes.fromhex(s) for s in ('6cfef0a0', '6cfef0a1', '6c10f03f')]
        report, _ = tool.analyze_bytes(encoded([(1, wrapper(m)) for m in messages]))
        split = report['same_tx_header_field_across_a1']
        self.assertEqual({'10000000': 1}, split['before_a1_tx_bytes_6_through_9'])
        self.assertEqual({'10000000': 2}, split['a1_and_later_tx_bytes_6_through_9'])
        self.assertFalse(split['physical_speed_or_flag_meaning_proven'])

    def test_wrong_group_or_noninitial_prefix_never_becomes_bus_header(self):
        report, bus = tool.analyze_bytes(encoded([
            (2, wrapper(bytes.fromhex('6cf010750154'), 2, 'ff00')),
            (2, wrapper(bytes.fromhex('006cf010750154'), 2, '1000'))]))
        self.assertEqual(1, len(bus))
        self.assertFalse(bus[0]['header_ok'])
        self.assertIsNone(report['binary_records'][1][-1])

    def test_unsupported_wrapper_and_truncated_record_preserve_failure(self):
        bad = bytearray(wrapper(b'x')); bad[10] = 2
        report, _ = tool.analyze_bytes(encoded([(1, bytes(bad))]))
        self.assertEqual([0], report['unsupported_wrapper_record_ordinals'])
        self.assertIsNone(report['binary_records'][0][8])
        with self.assertRaises(ValueError):
            tool.analyze_bytes(encoded([(1, wrapper(b'x'))])[:-1])

    def test_file_hash_gate_source_stability_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path, output = Path(directory) / 'saved.htx', Path(directory) / 'out.json'
            raw = encoded([(1, wrapper(b'x'))]); path.write_bytes(raw)
            with self.assertRaises(ValueError):
                tool.inspect([(path, '0' * 64)])
            report = tool.inspect([(path, tool.sha256(raw))])
            self.assertFalse(report['adapter_opened'])
            output.write_text('existing')
            with self.assertRaises(SystemExit):
                tool.main(['--trace', str(path), tool.sha256(raw), '--output', str(output)])
            self.assertEqual('existing', output.read_text())
            analyze_original = tool.analyze_bytes
            def mutate(data):
                answer = analyze_original(data)
                path.write_bytes(data + b'x')
                return answer
            with patch.object(tool, 'analyze_bytes', side_effect=mutate):
                with self.assertRaisesRegex(ValueError, 'changed'):
                    tool.inspect([(path, tool.sha256(raw))])

    def test_gt_report_must_bind_exact_decoded_sequence(self):
        raw = encoded([(1, wrapper(bytes.fromhex('6cfef0a1'))), (2, wrapper(bytes.fromhex('6cf01060'), 2, '1000'))])
        report, bus = tool.analyze_bytes(raw)
        gt = {'sources': [{'sha256': tool.sha256(raw)}],
              'trace_window': {'decoded_trace_sha256': '0' * 64}}
        with self.assertRaisesRegex(ValueError, 'does not match'):
            tool.correlate_saved_gt(tool.sha256(raw), report, bus, gt)
        self.assertIsNone(tool.correlate_saved_gt('1' * 64, report, bus, gt))

    def test_shared_payload_cannot_be_counted_as_exclusive_in_both_directions(self):
        message = bytes.fromhex('6cf01060')
        raw = encoded([(1, wrapper(bytes.fromhex('6cfef0a1'))),
                       (1, wrapper(message)), (2, wrapper(message, 2, '1000'))])
        report, bus = tool.analyze_bytes(raw)
        gt = {
            'sources': [{'sha256': tool.sha256(raw)}],
            'trace_window': {'decoded_trace_sha256': report['decoded_sha256'],
                             'a1_record_ordinal_zero_based': 0, 'final_data_record_ordinal_zero_based': 2},
            'literal_comparison': {'expected_count': 2,
                                   'expected_sequence_sha256': tool.sequence_sha256([message, message]),
                                   'missing_count': 1, 'extra_count': 0},
            'all_frames': [{'message_without_crc': {'bytes': len(message), 'sha256': tool.sha256(message)},
                            'physical_crc_valid': True}],
            'valid_crc_frame_count': 1, 'invalid_or_absent_crc_frame_count': 0,
            'qualification_passed': False,
            'baseline_htx_comparison': {'ordered_trace_messages_identical': True, 'observed_data_equal': True},
        }
        result = tool.correlate_saved_gt(tool.sha256(raw), report, bus, gt)
        self.assertEqual(1, result['matching_occurrences'])
        self.assertFalse(result['htx_channel_payload_digests_disjoint'])
        self.assertEqual(1, len(result['shared_channel_payloads']))
        self.assertEqual(1, result['shared_channel_payloads'][0]['valid_gt_occurrences'])
        for channel in result['valid_gt_body_matches_by_htx_channel']:
            self.assertEqual(1, channel['matching_valid_crc_gt_body_occurrences_upper_bound'])
            self.assertEqual(0, channel['exclusive_channel_matching_occurrences'])


if __name__ == '__main__':
    unittest.main()
