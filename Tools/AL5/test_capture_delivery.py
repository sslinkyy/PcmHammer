"""Byte-level delivery provenance tests; no transport access is permitted."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import analyze_capture_delivery as delivery
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
