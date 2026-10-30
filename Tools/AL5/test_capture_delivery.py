"""Byte-level delivery provenance tests; no transport access is permitted."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import analyze_capture_delivery as delivery
import obdx_capture as capture
import test_obdx_capture as transport_fixtures
from obdx_capture import packet
from test_obdx_capture import network
from test_compare_vpw_read_capture import block


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'capture.jsonl'

    def analyze(self, chunks, times=None, *, tail=None, **selectors):
        times = times if times is not None else list(range(100, 100 + len(chunks)))
        rows = [{'kind': 'transport', 'api': 'dvi'},
                {'kind': 'capture_started', 'crc_in_payload': True},
                # Stored decoded rows are intentionally not replay inputs.
                {'kind': 'network', 'raw_hex': '0000', 'payload_hex': 'deadbeef'}]
        rows += [{'kind': 'serial_rx', 'raw_hex': chunk.hex(), 'host_monotonic_ns': time}
                 for chunk, time in zip(chunks, times)]
        rows += tail if tail is not None else [{'kind': 'result', 'success': True}]
        self.path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf8')
        with patch('obdx_capture.WindowsSerial', side_effect=AssertionError('No hardware')):
            return delivery.analyze(self.path, **selectors)

    def test_fragmented_timestamped_long_frame_maps_exact_chunk_offsets(self):
        message = block(0x25000, bytes(range(256)) * 16)
        payload = message + bytes([delivery.crc8_j1850(message)])
        control = packet(0x34, b'\x03\x01')
        short = network(b'\x6c\xf0\x10\x60\x00', stamp=b'\x11\x22\x33\x44')
        long = network(payload, large=True, stamp=b'\x01\x02\x03\x04')
        wire = control + short + long
        split = len(control) + len(short) + 7
        chunks = [wire[:split], wire[split:split + 1024], wire[split + 1024:]]
        result = self.analyze(chunks, [100, 125, 200], addresses=[0x25000], radius=1)
        self.assertTrue(result['analysis_complete'], result['issues'])
        self.assertEqual(len(wire), result['byte_accounting']['mapped_dvi_bytes'])
        self.assertEqual(3, result['byte_accounting']['mapped_dvi_frames'])
        frame = result['network_frame_mappings'][1]
        self.assertEqual('01020304', frame['adapter_timestamp_raw_hex'])
        self.assertEqual(100, frame['assembly_host_span_ns'])
        self.assertEqual([4, 5, 6], [s['source_line'] for s in frame['serial_chunk_spans']])
        self.assertEqual(len(control) + len(short), frame['serial_chunk_spans'][0]['chunk_offset_start'])
        self.assertEqual(7, frame['serial_chunk_spans'][0]['chunk_offset_end_exclusive']
                         - frame['serial_chunk_spans'][0]['chunk_offset_start'])
        self.assertEqual(1, result['extended_length_frames']['fragmented_across_chunks'])
        self.assertEqual([0, 1], result['selections'][0]['neighbor_ordinals'])
        self.assertEqual(0x25000, frame['e54_block_address_candidate'])
        self.assertFalse(result['complete_bus_capture_proven'])

    def test_coalesced_frames_empty_chunks_and_embedded_header_are_not_dropped_or_split(self):
        embedded = network(bytes.fromhex('6cf010750154'))
        first = network(b'\x6d\xf0\x10\x36' + embedded, large=True)
        second = network(bytes.fromhex('6cf01060'))
        result = self.analyze([b'', first + second, b''], ordinals=[0, 1], radius=0)
        self.assertTrue(result['analysis_complete'], result['issues'])
        self.assertEqual(2, len(result['network_frame_mappings']))
        self.assertEqual([5, 5], [f['serial_chunk_spans'][0]['source_line']
                                for f in result['network_frame_mappings']])
        self.assertEqual(len(first), result['network_frame_mappings'][1]['raw_stream_start'])
        self.assertEqual(2, result['serial_delivery']['chunk_size_histogram'][0])

    def test_request_address_requires_request_mode_one_and_valid_crc(self):
        request = bytes.fromhex('6d10f03501100002d000')
        payload = request + bytes([delivery.crc8_j1850(request)])
        result = self.analyze([network(payload)], addresses=[0x2d000], radius=0)
        self.assertTrue(result['requested_selection_complete'])
        self.assertEqual(0x2d000, result['network_frame_mappings'][0]['e54_block_address_candidate'])
        malformed = request[:4] + b'\x00' + request[5:]
        bad_mode = malformed + bytes([delivery.crc8_j1850(malformed)])
        self.assertIsNone(delivery.e54_address(bad_mode, True))
        self.assertIsNone(delivery.e54_address(payload[:-1] + bytes([payload[-1] ^ 1]), True))

    def test_legacy_logs_do_not_imply_zero_driver_errors(self):
        result = self.analyze([network(bytes.fromhex('6cf01060'))])
        diag = result['serial_diagnostics']
        self.assertFalse(diag['available'])
        self.assertFalse(diag['coverage_complete_for_logged_reads'])
        self.assertIsNone(diag['observed_error_mask_or'])
        self.assertIsNone(diag['max_observed_input_queue_bytes'])

    def test_crc_forensics_preserve_invalid_payload_without_promoting_it(self):
        ack = bytes.fromhex('6df010750154')
        valid = ack + bytes([delivery.crc8_j1850(ack)])
        # Observed retained-CRC bench frame: first header byte differs from
        # the reference ACK, but the received trailing CRC is unchanged.
        invalid = bytes.fromhex('6cf01075015456')
        result = self.analyze([network(valid) + network(invalid)])
        self.assertTrue(result['analysis_complete'], result['issues'])
        self.assertEqual(2, result['physical_crc']['checked_frames'])
        self.assertEqual(1, result['physical_crc']['matching_frames'])
        self.assertEqual([1], result['physical_crc']['mismatching_network_ordinals'])
        evidence = result['network_frame_mappings'][1]
        self.assertEqual(delivery.sha256(invalid), evidence['payload_sha256'])
        self.assertFalse(evidence['physical_crc']['matches'])
        self.assertEqual('56', evidence['physical_crc']['observed_crc_hex'])
        self.assertEqual('10', evidence['physical_crc']['calculated_crc_hex'])
        self.assertFalse(result['complete_bus_capture_proven'])
        self.assertIsNone(delivery.physical_crc(valid, False)['matches'])
        self.assertIsNone(delivery.physical_crc(b'', True)['matches'])
        rows = [json.loads(line) for line in self.path.read_text().splitlines()]
        rows[1].pop('crc_in_payload')
        self.path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf8')
        unknown = delivery.analyze(self.path)
        self.assertEqual(0, unknown['physical_crc']['checked_frames'])
        self.assertEqual(2, unknown['physical_crc']['unchecked_frames'])

    def test_optional_diagnostics_preserve_error_flags_and_sampled_queue_limits(self):
        status = {'success': True, 'host_monotonic_ns': 10, 'error_mask_raw': 0,
                  'comstat_flags_raw': 0, 'cb_in_que': 14, 'cb_out_que': 0, 'win32_error': None}
        observation = {'kind': 'serial_read_diagnostics', 'read_sequence': 1,
                       'read_start_monotonic_ns': 20, 'read_end_monotonic_ns': 100,
                       'read_succeeded': True, 'bytes_returned': 2, 'read_error': None,
                       'before': status, 'after': dict(status, host_monotonic_ns=110, error_mask_raw=3, cb_in_que=64),
                       'polling_clears_error_flags': True}
        rows = [(1, {'kind': 'transport', 'serial_diagnostics_enabled': True}),
                (2, {'kind': 'serial_rx', 'read_sequence': 1, 'raw_hex': 'aabb', 'host_monotonic_ns': 120}),
                (3, observation)]
        result = delivery.serial_diagnostics(rows)
        self.assertTrue(result['coverage_complete_for_logged_reads'], result['issues'])
        self.assertEqual(3, result['observed_error_mask_or'])
        self.assertEqual(1, result['snapshots_reporting_rx_overflow_or_overrun'])
        self.assertEqual(64, result['max_observed_input_queue_bytes'])
        self.assertEqual(80, result['read_durations_ns']['maximum'])
        missing = delivery.serial_diagnostics(rows[:2])
        self.assertFalse(missing['coverage_complete_for_logged_reads'])
        self.assertIsNone(missing['observed_error_mask_or'])
        wrong = delivery.serial_diagnostics([*rows[:2], (3, dict(observation, bytes_returned=1))])
        self.assertFalse(wrong['coverage_complete_for_logged_reads'])
        failed = delivery.serial_diagnostics([rows[0], (2, dict(observation, bytes_returned=0,
                   read_succeeded=False, read_error={'win32_error': 5, 'message': 'denied'},
                   before={'success': False, 'win32_error': 5}))])
        self.assertEqual(1, failed['failed_read_count'])
        self.assertFalse(failed['coverage_complete_for_logged_reads'])
        invalid = [
            dict(observation, before=dict(status, host_monotonic_ns=None)),
            dict(observation, after=dict(status, host_monotonic_ns=10)),
            dict(observation, read_succeeded=False, read_error={'message': 'failure'}),
            dict(observation, read_error={'message': 'unexpected on success'}),
        ]
        for bad in invalid:
            result = delivery.serial_diagnostics([*rows[:2], (3, bad)])
            self.assertFalse(result['coverage_complete_for_logged_reads'], bad)
        result = delivery.serial_diagnostics([rows[0], (2, dict(rows[1][1], host_monotonic_ns=5)), rows[2]])
        self.assertFalse(result['coverage_complete_for_logged_reads'])
        second = dict(observation, read_sequence=2, read_start_monotonic_ns=140,
                      read_end_monotonic_ns=150, before=dict(status, host_monotonic_ns=130),
                      after=dict(status, host_monotonic_ns=160))
        result = delivery.serial_diagnostics([*rows[:2],
            (3, dict(rows[1][1], read_sequence=2, host_monotonic_ns=170)),
            (4, observation), (5, second)])
        self.assertFalse(result['coverage_complete_for_logged_reads'])

    def test_native_session_diagnostics_round_trip_with_status_and_read_failures(self):
        wire = network(bytes.fromhex('6cf01060'))
        cases = (
            ('valid', wire, [{}, {}, {'errors': 3, 'in': 64}, {}], True, 4),
            ('status_failure', wire, [{}, {}, {'failure': 5}, {}], False, 3),
            ('read_and_status_failure', {'failure': 123, 'reported_count': 7},
             [{}, {}, {}, {'failure': 6}], False, 3),
        )
        for name, final_read, statuses, complete, samples in cases:
            with self.subTest(case=name):
                api = transport_fixtures.FakeWin32Api([b'', final_read], statuses)
                # This shared fixture replaces the complete Win32 boundary before
                # constructing the production port; no native handle is opened.
                port = transport_fixtures.WindowsSerialDiagnosticsTests.native_port(self, api)
                output = io.StringIO()
                emit = lambda row: output.write(json.dumps(row) + '\n')
                emit({'kind': 'transport', 'api': 'dvi', 'serial_diagnostics_enabled': True})
                session = capture.Session(port, emit)
                self.assertEqual(b'', session.read())
                if isinstance(final_read, dict):
                    with self.assertRaises(OSError):
                        session.read()
                else:
                    self.assertEqual(wire, session.read())
                rows = list(enumerate((json.loads(line) for line in output.getvalue().splitlines()), 1))
                result = delivery.serial_diagnostics(rows)
                self.assertEqual(complete, result['coverage_complete_for_logged_reads'], result['issues'])
                self.assertEqual(2, result['read_observation_count'])
                self.assertEqual(samples, result['status_snapshot_count'])
                self.assertEqual(int(isinstance(final_read, dict)), result['failed_read_count'])
                rx = [row for _, row in rows if row['kind'] == 'serial_rx']
                diagnostics = [row for _, row in rows if row['kind'] == 'serial_read_diagnostics']
                self.assertEqual([1, 2], [row['read_sequence'] for row in diagnostics])
                if complete:
                    self.assertEqual([], result['issues'])
                    self.assertEqual(3, result['observed_error_mask_or'])
                    self.assertEqual(64, result['max_observed_input_queue_bytes'])
                else:
                    self.assertTrue(any('Unavailable' in issue for issue in result['issues']))
                if isinstance(final_read, dict):
                    self.assertEqual([], rx)
                    self.assertEqual(0, diagnostics[-1]['bytes_returned'])
                    self.assertEqual(7, diagnostics[-1]['bytes_reported_by_readfile'])
                    self.assertEqual(123, diagnostics[-1]['read_error']['win32_error'])
                else:
                    self.assertEqual([wire.hex()], [row['raw_hex'] for row in rx])
                    self.assertEqual([2], [row['read_sequence'] for row in rx])
                self.assertNotIn('WriteFile', api.calls)

    def test_corrupt_or_truncated_suffix_keeps_verified_prefix_without_complete_claim(self):
        first = network(bytes.fromhex('6cf01060'))
        valid = network(bytes.fromhex('6cf010750154'))
        for bad in (valid[:-1], valid[:-1] + bytes([valid[-1] ^ 1])):
            result = self.analyze([first + bad])
            self.assertFalse(result['analysis_complete'])
            self.assertEqual(1, result['byte_accounting']['mapped_network_frames'])
            self.assertEqual(len(bad), result['byte_accounting']['unaccounted_bytes'])
            self.assertFalse(result['byte_accounting']['all_logged_rx_bytes_accounted_for'])

    def test_raw_host_clock_values_are_preserved_without_bus_timing_claim(self):
        wire = network(bytes.fromhex('6cf01060'))
        result = self.analyze([wire[:2], wire[2:]], [100, 90])
        self.assertTrue(result['analysis_complete'])
        self.assertEqual([100, 90], [c['host_monotonic_ns'] for c in result['serial_chunks']])
        self.assertIsNone(result['network_frame_mappings'][0]['assembly_host_span_ns'])
        self.assertEqual(1, result['serial_delivery']['host_clock_regressions'])
        result = self.analyze([wire[:2], wire[2:]], [None, 100])
        self.assertIsNone(result['network_frame_mappings'][0]['assembly_host_span_ns'])
        self.assertEqual(1, result['serial_delivery']['missing_or_noninteger_host_timestamps'])

    def test_incomplete_source_and_unsupported_transport_fail_closed(self):
        result = self.analyze([network(bytes.fromhex('6cf01060'))], tail=[])
        self.assertFalse(result['analysis_complete'])
        self.path.write_text(json.dumps({'kind': 'transport', 'api': 'elm'}) + '\n'
                             + json.dumps({'kind': 'result', 'success': True}) + '\n')
        with patch('obdx_capture.WindowsSerial', side_effect=AssertionError('No hardware')):
            result = delivery.analyze(self.path)
        self.assertFalse(result['analysis_complete'])
        self.assertTrue(any('explicit DVI' in issue for issue in result['issues']))
        self.path.write_bytes(b'{"kind":"transport","api":"dvi"}\n{"kind":')
        with patch('obdx_capture.WindowsSerial', side_effect=AssertionError('No hardware')):
            result = delivery.analyze(self.path)
        self.assertFalse(result['analysis_complete'])
        self.assertTrue(any('Source JSONL invalid at line 2' in issue for issue in result['issues']))

    def test_cli_selected_miss_and_existing_output_are_explicit(self):
        result = self.analyze([network(bytes.fromhex('6cf01060'))], ordinals=[7])
        self.assertTrue(result['analysis_complete'])
        self.assertFalse(result['requested_selection_complete'])
        self.assertEqual([], result['selected_frame_evidence'])
        output = self.path.with_name('receipt.json')
        args = ['--capture', str(self.path), '--ordinal', '7', '--output', str(output)]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(1, delivery.main(args))
        saved = output.read_bytes()
        self.assertNotIn(b'\r\n', saved)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            delivery.main(args)
        self.assertEqual(saved, output.read_bytes())


if __name__ == '__main__':
    unittest.main()
