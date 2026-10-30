"""Offline input-boundary tests for exact E54/AutoCal capture comparison."""
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

import compare_vpw_read_capture as comparison
from decode_trace_containers import SIGNATURE
from obdx_capture import SETTINGS, packet


def block(address, body):
    message = comparison.DATA_HEADER + b'\x00' + len(body).to_bytes(2, 'big')
    message += address.to_bytes(3, 'big') + body
    return message + (sum(message[4:]) & 0xffff).to_bytes(2, 'big')


def wrap(message, channel, route=None):
    wrapper = (b'\x01\x54' if channel == 1 else b'\x01\x52')
    wrapper += route if route is not None else (b'\x00\x8a' if channel == 1 else b'\x10\x00')
    wrapper += bytes(6) + struct.pack('<H', len(message)) + message
    wrapper += bytes(2 if channel == 1 else 3)
    return struct.pack('<dBHHBI', 46282.5, channel, 7, 2, 0x42, len(wrapper)) + wrapper


def encode_trace(frames):
    raw = SIGNATURE + bytes(1024 - len(SIGNATURE))
    raw += b''.join(wrap(frame[1], frame[0], *frame[2:]) for frame in frames)
    return bytes(((((b ^ 0xa5) >> 3) | ((b ^ 0xa5) << 5)) + 0x87) & 255
                 for b in zlib.compress(raw))


def network(message, bad_crc=False):
    payload = message + bytes([comparison.crc8_j1850(message) ^ int(bad_crc)])
    width = 1 if len(payload) <= 255 else 2
    raw = bytes([8 if width == 1 else 9]) + len(payload).to_bytes(width, 'big') + payload
    return raw + bytes([~sum(raw) & 255])


def checked_setting(command, payload):
    return [
        {'kind': 'adapter_tx', 'raw_hex': packet(command, payload).hex()},
        {'kind': 'serial_rx', 'raw_hex': packet(command + 0x10, payload).hex()},
        {'kind': 'adapter_tx', 'raw_hex': packet(command, payload[:1]).hex()},
        {'kind': 'serial_rx', 'raw_hex': packet(command + 0x10, payload).hex()},
    ]


def capture_rows(messages, source_id):
    # Raw input is authoritative. Deliberately misleading decoded source rows
    # must not replace replay of the bytes actually recorded from the adapter.
    setup = []
    for command, payload in (
            (0x31, b'\x01\x01'), (0x31, b'\x02\x00'),
            (0x33, b'\x00\x00\x00'), (0x33, b'\x02\x00\x00\x00'),
            (0x33, b'\x03\x00\x00\x00'), (0x33, b'\x04\x00\x00\x00\x00'),
            (0x33, bytes([1, source_id, 1])), (0x33, b'\x06\x01'),
            (0x33, b'\x07\x01'), (0x33, b'\x08\x01'), (0x31, b'\x02\x02')):
        setup.extend(checked_setting(command, payload))
    return [
        {'kind': 'transport', 'api': 'dvi'},
        *setup,
        {'kind': 'capture_started', 'fixed_speed': '4x', 'source_filter': source_id,
         'receive_scope': 'exact_source', 'crc_in_payload': True,
         'automatic_speed_tracking': False},
        {'kind': 'network', 'payload_hex': 'this decoded row is not replay input'},
        *[{'kind': 'serial_rx', 'raw_hex': network(m).hex()} for m in messages],
        *checked_setting(0x31, b'\x02\x00'),
        {'kind': 'cleanup', 'network_off_acknowledged': True},
        {'kind': 'settings_restored', 'success': True},
        {'kind': 'result', 'success': True},
    ]


def first_network_row(rows):
    return next(i for i, row in enumerate(rows)
                if row['kind'] == 'serial_rx' and row['raw_hex'][:2] in ('08', '09'))


def all_source_rows(messages):
    profile = (b'\x00\x00\x01', b'\x01\x10\x01', b'\x02\x00\x00\x00',
               b'\x03\x00\x00\x00', b'\x04\x00\x00\x00\x01')
    rows = [{'kind': 'transport', 'api': 'dvi'}]
    saved = ['0300', '000000', '010000', '02000000', '03000000',
             '0400000000', '0600', '0700', '0800']
    for (command, _, _, label), value in zip(SETTINGS, saved):
        rows.extend(checked_setting(command, bytes.fromhex(value))[2:])
        rows.append({'kind': 'saved_setting', 'label': label, 'command': command,
                     'payload_hex': value})
    for command, payload in (
            (0x31, b'\x01\x01'), (0x31, b'\x02\x00'),
            (0x33, b'\x00\x00\x00'), (0x33, b'\x02\x00\x00\x00'),
            (0x33, b'\x03\x00\x00\x00'), (0x33, b'\x04\x00\x00\x00\x00'),
            (0x33, b'\x01\x10\x01'), (0x33, b'\x04\x00\x00\x00\x01'),
            (0x33, b'\x06\x01'), (0x33, b'\x07\x01'), (0x33, b'\x08\x01')):
        rows.extend(checked_setting(command, payload))
    for payload in profile:
        rows.extend(checked_setting(0x33, payload)[2:])  # GET-only final whole-profile audit.
    rows.extend(checked_setting(0x31, b'\x02\x02'))
    rows.append({'kind': 'capture_started', 'fixed_speed': '4x', 'source_filter': None,
                 'receive_scope': 'experimental_mask_all', 'crc_in_payload': True,
                 'automatic_speed_tracking': False, 'live_receive_verified': False})
    rows.extend({'kind': 'serial_rx', 'raw_hex': network(m).hex()} for m in messages)
    rows.extend(checked_setting(0x31, b'\x02\x00'))
    rows.append({'kind': 'cleanup', 'network_off_acknowledged': True})
    restore = list(zip(SETTINGS, saved))
    restore.sort(key=lambda pair: pair[0][:2] == (0x33, 4))
    for (command, _, _, _), value in restore:
        rows.extend(checked_setting(command, bytes.fromhex(value)))
    for (command, _, _, _), value in zip(SETTINGS, saved):
        rows.extend(checked_setting(command, bytes.fromhex(value))[2:])
    rows.extend(checked_setting(0x31, b'\x02\x00')[2:])
    rows.extend([
        {'kind': 'settings_readback_restoration', 'success': True,
         'observable_readbacks_match_original': True, 'hidden_setting_state_restored': None,
         'expected_readbacks': saved, 'observed_readbacks': list(saved)},
        {'kind': 'result', 'success': True},
    ])
    return rows


class ComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frames = [(1, comparison.A1)]
        for address in range(0, comparison.TRANSFER_END, 4096):
            length = min(4096, comparison.TRANSFER_END - address)
            cls.frames.append((1, bytes.fromhex('6c10f035') + address.to_bytes(3, 'big')))
            cls.frames.append((2, block(address, bytes([address // 4096]) * length)))
        cls.trace_bytes = encode_trace(cls.frames)
        cls.responses = [m for ch, m in cls.frames if ch == 2]
        cls.requests = [m for ch, m in cls.frames[1:] if ch == 1]

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.trace = self.folder / 'read.htx'
        self.capture = self.folder / 'capture.jsonl'
        self.trace.write_bytes(self.trace_bytes)

    def compare(self, rows, source_id=0xf0, *, all_sources=False):
        self.capture.write_text(''.join(json.dumps(r) + '\n' for r in rows), encoding='utf8')
        with patch('obdx_capture.WindowsSerial', side_effect=AssertionError('No hardware allowed')):
            return comparison.compare(self.capture, self.trace, source_id, all_sources=all_sources)

    def test_exact_ecm_capture_and_explicit_partial_coverage(self):
        self.assertEqual(0x4b, comparison.crc8_j1850(b'123456789'))
        result = self.compare(capture_rows(self.responses, 0x10), 0x10)
        self.assertTrue(result['comparison_passed'], result['issues'])
        self.assertEqual(128, result['observed_network_frame_count'])
        self.assertEqual(comparison.TRANSFER_END, result['capture_blocks']['covered_bytes'])
        self.assertEqual(result['trace_blocks']['reconstructed_partial_sha256'],
                         result['capture_blocks']['reconstructed_partial_sha256'])
        self.assertFalse(result['capture_blocks']['full_512kib_image'])
        self.assertEqual({'start': 524286, 'end_exclusive': 524288},
                         result['capture_blocks']['untransferred_tail'])
        self.assertFalse(result['live_write_enabled'])
        self.assertFalse(result['ready_to_flash'])
        self.assertEqual([], result['would_send'])
        self.assertEqual(comparison.sha256(self.trace_bytes), result['inputs'][1]['sha256'])

    def test_request_direction_is_supported_without_claiming_captured_image(self):
        result = self.compare(capture_rows(self.requests, 0xf0))
        self.assertTrue(result['comparison_passed'], result['issues'])
        self.assertEqual('host_tx_candidate', result['expected_window']['direction_inference'])
        self.assertFalse(result['capture_blocks']['available'])
        self.assertTrue(result['trace_blocks']['complete_observed_e54_read_range'])

    def test_missing_extra_and_reordered_requests_cannot_pass(self):
        cases = [self.requests[:-1], self.requests + self.requests[-1:],
                 [self.requests[1], self.requests[0]] + self.requests[2:]]
        for messages in cases:
            with self.subTest(messages=len(messages)):
                result = self.compare(capture_rows(messages, 0xf0))
                self.assertFalse(result['comparison_passed'])
                self.assertFalse(result['ordered_messages_equal'])
                self.assertIsNotNone(result['first_mismatch_ordinal_zero_based'])
        self.assertEqual(0, result['missing_frame_count'])
        self.assertEqual(0, result['extra_frame_count'])  # Order still matters.

    def test_valid_dvi_checksum_does_not_hide_bad_physical_vpw_crc(self):
        rows = capture_rows(self.requests, 0xf0)
        rows[first_network_row(rows)]['raw_hex'] = network(self.requests[0], bad_crc=True).hex()
        result = self.compare(rows)
        self.assertFalse(result['comparison_passed'])
        self.assertTrue(result['ordered_messages_equal'])
        self.assertEqual([0], result['vpw_crc']['failed_frame_ordinals_zero_based'])

    def test_declared_4x_cannot_override_correlated_raw_1x_readback(self):
        rows = capture_rows(self.requests, 0xf0)
        index = first_network_row(rows)
        rows[index:index] = [
            {'kind': 'adapter_tx', 'raw_hex': packet(0x33, b'\x06').hex()},
            {'kind': 'serial_rx', 'raw_hex': packet(0x43, b'\x06\x00').hex()},
        ]
        result = self.compare(rows)
        self.assertTrue(result['ordered_messages_equal'])
        self.assertFalse(result['comparison_passed'])
        self.assertEqual(128, result['strict_replay']['speed_analysis']['qualification']
                         ['frames_by_adapter_readback']['1x'])
        self.assertEqual(0, result['raw_capture_context']['frames_with_matching_context'])
        self.assertIn('speed_4x', result['raw_capture_context']['frame_context_failures'][0]
                      ['missing_or_contradictory_settings'])

    def test_set_echo_unsolicited_status_or_missing_setup_cannot_establish_context(self):
        rows = capture_rows(self.requests, 0xf0)
        start = next(i for i, row in enumerate(rows) if row['kind'] == 'capture_started')
        missing = rows[:1] + rows[start:]
        self.assertFalse(self.compare(missing)['raw_capture_context']['verified'])
        rows = capture_rows(self.requests, 0xf0)
        get_index = next(i for i, row in enumerate(rows)
                         if row['kind'] == 'adapter_tx' and row['raw_hex'] == packet(0x33, b'\x06').hex())
        del rows[get_index:get_index + 2]  # SET acknowledgment remains intact.
        result = self.compare(rows)
        self.assertFalse(result['comparison_passed'])
        self.assertIsNone(result['raw_capture_context']['first_frame_readbacks']['speed_4x'])
        rows = capture_rows(self.requests, 0xf0)
        rows.insert(first_network_row(rows), {'kind': 'serial_rx',
                                            'raw_hex': packet(0x43, b'\x06\x01').hex()})
        result = self.compare(rows)
        self.assertFalse(result['comparison_passed'])
        self.assertEqual('uncorrelated_setting_status',
                         result['raw_capture_context']['correlation_errors'][0]['reason'])

    def test_context_change_during_receive_invalidates_remaining_frames(self):
        for command, payload, setting in (
                (0x31, b'\x02\x00', 'listen_only'), (0x31, b'\x01\x00', 'vpw_protocol'),
                (0x33, b'\x08\x00', 'crc_display_on'), (0x33, b'\x07\x00', 'crc_validation_on'),
                (0x33, b'\x01\x10\x01', 'exact_source'),
                (0x33, b'\x00\x00\x00', 'last_filter_write_is_not_the_checked_exact_source')):
            with self.subTest(setting=setting):
                rows = capture_rows(self.requests, 0xf0)
                index = first_network_row(rows) + 1
                # A GET-only conflicting protocol reply is valid replay input,
                # even though the capture guard forbids setting non-VPW mode.
                change = checked_setting(command, payload)
                if setting == 'vpw_protocol':
                    change = change[2:]
                rows[index:index] = change
                result = self.compare(rows)
                self.assertTrue(result['ordered_messages_equal'])
                self.assertFalse(result['comparison_passed'])
                self.assertEqual(1, result['raw_capture_context']['frames_with_matching_context'])
                self.assertIn(setting, result['raw_capture_context']['frame_context_failures'][0]
                              ['missing_or_contradictory_settings'])

    def test_interleaved_f0_frames_are_diagnostic_subsequence_extras_not_a_pass(self):
        extra = bytes.fromhex('8cfef03f')
        observed = [m for request in self.requests for m in (request, extra)]
        observed.append(bytes.fromhex('6c10f03c55'))
        result = self.compare(capture_rows(observed, 0xf0))
        self.assertFalse(result['comparison_passed'])
        self.assertFalse(result['ordered_messages_equal'])
        self.assertEqual(0, result['missing_frame_count'])
        self.assertEqual(129, result['extra_frame_count'])
        diagnostic = result['ordered_subsequence_analysis']
        self.assertTrue(diagnostic['expected_is_subsequence'])
        self.assertEqual(128, diagnostic['matched_expected_message_count'])
        self.assertEqual(list(range(0, 256, 2)), diagnostic['matched_observed_ordinals_zero_based'])
        self.assertEqual(list(range(1, 256, 2)) + [256], diagnostic['unmatched_observed_ordinals_zero_based'])
        self.assertFalse(diagnostic['changes_strict_comparison_result'])

    def test_all_sources_matches_both_trace_directions_without_bus_completeness_claim(self):
        messages = [m for _, m in self.frames[1:]]
        result = self.compare(all_source_rows(messages), None, all_sources=True)
        self.assertTrue(result['comparison_passed'], result['issues'])
        self.assertTrue(result['raw_capture_context']['verified'])
        self.assertEqual({'10': 128, 'f0': 128}, result['observed_header_source_counts'])
        self.assertEqual(result['expected_header_source_counts'], result['observed_header_source_counts'])
        self.assertTrue(result['capture_blocks']['complete_observed_e54_read_range'])
        self.assertFalse(result['complete_bus_capture_proven'])
        self.assertTrue(result['raw_observable_restoration']['verified'])
        self.assertEqual('host_tx_or_device_rx_candidate', result['expected_window']['direction_inference'])

    def test_all_sources_keeps_f1_extras_and_does_not_hide_missing_data(self):
        messages = [m for _, m in self.frames[1:]]
        extra = bytes.fromhex('8cfef13f')
        with_extras = [m for message in messages for m in (message, extra)]
        result = self.compare(all_source_rows(with_extras), None, all_sources=True)
        self.assertFalse(result['comparison_passed'])
        self.assertEqual(256, result['observed_header_source_counts']['f1'])
        self.assertEqual(256, result['extra_frame_count'])
        self.assertEqual(0, result['missing_frame_count'])
        self.assertTrue(result['ordered_subsequence_analysis']['expected_is_subsequence'])
        result = self.compare(all_source_rows(messages[:-1]), None, all_sources=True)
        self.assertFalse(result['comparison_passed'])
        self.assertEqual(1, result['missing_frame_count'])
        self.assertFalse(result['capture_blocks']['complete_observed_e54_read_range'])

    def test_all_sources_requires_full_profile_gets_immediately_before_listen(self):
        messages = [m for _, m in self.frames[1:]]
        for fault in ('intervening_get', 'later_exact_filter_set', 'missing_filter_get', 'reused_listen_proof'):
            with self.subTest(fault=fault):
                rows = all_source_rows(messages)
                listen = next(i for i, row in enumerate(rows) if row['kind'] == 'adapter_tx'
                              and row['raw_hex'] == packet(0x31, b'\x02\x02').hex())
                if fault == 'intervening_get':
                    rows[listen:listen] = checked_setting(0x33, b'\x06\x01')[2:]
                elif fault == 'later_exact_filter_set':
                    # Perfect-looking GETs cannot hide a later exact SET that
                    # changes the shared mask. Recheck it before network bytes.
                    index = first_network_row(rows)
                    rows[index:index] = checked_setting(0x33, b'\x01\x10\x01')
                elif fault == 'reused_listen_proof':
                    update = checked_setting(0x33, b'\x01\x10\x01')
                    update += checked_setting(0x33, b'\x04\x00\x00\x00\x01')
                    for value in (b'\x00\x00\x01', b'\x01\x10\x01', b'\x02\x00\x00\x00',
                                  b'\x03\x00\x00\x00', b'\x04\x00\x00\x00\x01'):
                        update += checked_setting(0x33, value)[2:]
                    index = first_network_row(rows) + 1
                    rows[index:index] = update
                else:
                    del rows[listen - 2:listen]  # Remove final mask GET/response.
                result = self.compare(rows, None, all_sources=True)
                self.assertFalse(result['comparison_passed'])
                self.assertFalse(result['raw_capture_context']['verified'])
                self.assertTrue(result['ordered_messages_equal'])

    def test_all_sources_requires_observable_restoration_record_and_exclusive_scope(self):
        messages = [m for _, m in self.frames[1:]]
        for key, value in (('kind', 'settings_restored'), ('hidden_setting_state_restored', True),
                           ('observable_readbacks_match_original', False), ('observed_readbacks', [])):
            rows = all_source_rows(messages)
            rows[-2][key] = value
            self.assertFalse(self.compare(rows, None, all_sources=True)['comparison_passed'])
        with self.assertRaises(ValueError):
            self.compare(all_source_rows(messages), 0x10, all_sources=True)
        output = self.folder / 'must_not_exist.json'
        args = ['--capture', str(self.capture), '--trace', str(self.trace),
                '--source-id', '0x10', '--all-sources', '--output', str(output)]
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            comparison.main(args)
        self.assertFalse(output.exists())

    def test_all_sources_restoration_summary_cannot_replace_raw_snapshots(self):
        messages = [m for _, m in self.frames[1:]]
        for fault in ('missing_original', 'missing_final', 'contradictory_final', 'post_receipt_mutation'):
            rows = all_source_rows(messages)
            cleanup = next(i for i, r in enumerate(rows) if r['kind'] == 'cleanup')
            if fault == 'missing_original':
                rows = [r for r in rows if r['kind'] != 'saved_setting']
            elif fault == 'missing_final':
                rows = rows[:cleanup + 1] + rows[-2:]
            elif fault == 'post_receipt_mutation':
                rows[-1:-1] = checked_setting(0x33, b'\x08\x01')
            else:
                gets = [i for i, r in enumerate(rows) if i > cleanup and r['kind'] == 'adapter_tx'
                        and r['raw_hex'] == packet(0x33, b'\x06').hex()]
                rows[gets[-1] + 1]['raw_hex'] = packet(0x43, b'\x06\x01').hex()
            result = self.compare(rows, None, all_sources=True)
            self.assertFalse(result['comparison_passed'])
            self.assertFalse(result['raw_observable_restoration']['verified'])
            self.assertTrue(result['ordered_messages_equal'])

    def test_scope_cleanup_failure_and_missing_terminal_result_fail_closed(self):
        cases = [
            (None, 'source_filter', 0x10), (None, 'fixed_speed', '1x'),
            (None, 'crc_in_payload', False), (None, 'automatic_speed_tracking', True),
            (-3, 'network_off_acknowledged', False), (-2, 'success', False),
            (-1, 'success', False),
        ]
        for index, key, value in cases:
            with self.subTest(key=key, value=value):
                rows = capture_rows(self.requests, 0xf0)
                if index is None:
                    index = next(i for i, r in enumerate(rows) if r['kind'] == 'capture_started')
                rows[index][key] = value
                self.assertFalse(self.compare(rows)['comparison_passed'])
        self.assertFalse(self.compare(capture_rows(self.requests, 0xf0)[:-1])['comparison_passed'])

    def test_forbidden_tx_corrupt_dvi_and_trailing_source_records_fail_closed(self):
        rows = capture_rows(self.requests, 0xf0)
        rows.insert(2, {'kind': 'adapter_tx', 'raw_hex': packet(0x10, b'\x01').hex()})
        result = self.compare(rows)
        self.assertFalse(result['comparison_passed'])
        self.assertEqual(1, result['strict_replay']['outgoing_guard_violations'])
        rows = capture_rows(self.requests, 0xf0)
        index = first_network_row(rows)
        wire = bytearray.fromhex(rows[index]['raw_hex'])
        wire[-1] ^= 1
        rows[index]['raw_hex'] = wire.hex()
        result = self.compare(rows)
        self.assertFalse(result['comparison_passed'])
        self.assertFalse(result['strict_replay']['replay_complete'])
        rows = capture_rows(self.requests, 0xf0) + [{'kind': 'anything'}]
        self.assertFalse(self.compare(rows)['comparison_passed'])

    def test_missing_trace_tail_or_ambiguous_a1_cannot_qualify_shorter_capture(self):
        self.trace.write_bytes(encode_trace(self.frames[:-2]))
        result = self.compare(capture_rows(self.requests[:-1], 0xf0))
        self.assertTrue(result['ordered_messages_equal'])
        self.assertFalse(result['comparison_passed'])
        self.assertFalse(result['trace_blocks']['complete_observed_e54_read_range'])
        self.trace.write_bytes(encode_trace([(1, comparison.A1)] + self.frames))
        result = self.compare(capture_rows(self.requests, 0xf0))
        self.assertFalse(result['comparison_passed'])
        self.assertIsNone(result['expected_window'])

    def test_unknown_wrapper_and_contradictory_direction_are_not_skipped(self):
        for frames in ([*self.frames, (3, b'unknown')],
                       [*self.frames[:1], (2, self.requests[0]), *self.frames[2:]]):
            self.trace.write_bytes(encode_trace(frames))
            result = self.compare(capture_rows(self.requests, 0xf0))
            self.assertFalse(result['comparison_passed'])
            self.assertIsNone(result['expected_window'])

    def test_known_local_queries_are_recorded_but_unknown_routes_fail_closed(self):
        local = [(1, b'', b'\x03\x82'), (2, b'\x02\x08\x09', b'\x03\x82')]
        self.trace.write_bytes(encode_trace(self.frames[:1] + local + self.frames[1:]))
        result = self.compare(capture_rows(self.requests, 0xf0))
        self.assertTrue(result['comparison_passed'], result['issues'])
        self.assertEqual(2, len(result['expected_window']['excluded_local_wrapper_records']))
        for route, message in ((b'\x99\x99', b''), (b'\x03\x82', self.requests[0])):
            self.trace.write_bytes(encode_trace(self.frames[:1] + [(1, message, route)] + self.frames[1:]))
            result = self.compare(capture_rows(self.requests, 0xf0))
            self.assertFalse(result['comparison_passed'])
            self.assertIsNone(result['expected_window'])

    def test_block_retries_retain_conflicts_and_checksums(self):
        summary = comparison.blocks_summary(self.responses + self.responses[-1:])
        self.assertTrue(summary['complete_observed_e54_read_range'])
        self.assertEqual(1, summary['duplicate_address_count'])
        conflicting = block(0, bytes([0xee]) * 4096)
        summary = comparison.blocks_summary(self.responses + [conflicting])
        self.assertFalse(summary['complete_observed_e54_read_range'])
        self.assertEqual([128], summary['conflicting_block_ordinals_zero_based'])
        corrupt = self.responses[0][:-1] + bytes([self.responses[0][-1] ^ 1])
        summary = comparison.blocks_summary([corrupt] + self.responses[1:])
        self.assertEqual([0], summary['checksum_failed_block_ordinals_zero_based'])
        self.assertFalse(summary['complete_observed_e54_read_range'])

    def test_cli_exit_status_and_exclusive_receipt(self):
        rows = capture_rows(self.requests, 0xf0)
        self.compare(rows)
        output = self.folder / 'receipt.json'
        args = ['--capture', str(self.capture), '--trace', str(self.trace),
                '--source-id', '0xF0', '--output', str(output)]
        with contextlib.redirect_stdout(io.StringIO()), patch(
                'obdx_capture.WindowsSerial', side_effect=AssertionError('No hardware allowed')):
            self.assertEqual(0, comparison.main(args))
        original = output.read_bytes()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            comparison.main(args)
        self.assertEqual(2, error.exception.code)
        self.assertEqual(original, output.read_bytes())
        self.compare(rows[:-1])
        args[-1] = str(self.folder / 'failed.json')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(1, comparison.main(args))
        self.assertFalse(json.loads(Path(args[-1]).read_text())['comparison_passed'])


if __name__ == '__main__':
    unittest.main()
