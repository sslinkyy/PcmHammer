"""File-boundary tests for literal, window-scoped PcmHammer/USB comparison."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pcmhammer_usb_capture as capture
from test_usb_serial_capture import pcap, exchange, usb


def dvi(body, command=8, timestamp=b''):
    width = 2 if command == 9 else 1
    wire = bytes([command]) + timestamp + len(body).to_bytes(width, 'big') + body
    return wire + bytes([255 - (sum(wire) & 255)])


class PcmHammerUsbCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.pcap = self.folder / 'capture.pcap'
        self.log = self.folder / 'operation.log'

    def files(self, payload, log, records=None):
        if records is None:
            records = exchange(payload[:3]) + exchange(payload[3:], irp=2)
        self.pcap.write_bytes(pcap(records))
        self.log.write_text(log, encoding='utf-8')

    def analyze(self, windows=None, **kwargs):
        return capture.analyze(self.pcap, self.log, bus=2, device=7, endpoint=0x81,
                               windows=windows or [(0, None)], **kwargs)

    def test_chunk_independent_exact_rx_agreement_and_short_ack_provenance(self):
        ack = bytes.fromhex('6cf0107600')
        payload = dvi(ack) + dvi(ack)
        self.files(payload, '[DEBUG] Received: 6C F0 10 76 00\n' * 2)
        result = self.analyze()
        self.assertTrue(result['selected_window_rx_agreement_qualified'])
        self.assertEqual(2, result['dvi']['short_network_count'])
        first = result['dvi']['short_network_examples'][0]
        self.assertEqual([2, 4], [s['record'] for s in first['pcap_spans']])
        self.assertEqual('upload_ack_shaped', first['protocol']['kind'])
        self.assertFalse(result['hardware_access_performed'])
        self.assertFalse(result['vpw_losslessness_proven'])
        self.assertFalse(result['physical_flash_success_proven'])
        self.assertFalse(result['usb_tx_verified'])

    def test_literal_malformed_ack_not_repaired(self):
        actual = bytes.fromhex('6cf01075015456')
        self.files(dvi(actual), '[DEBUG] Received: 6D F0 10 75 01 54 56\n')
        result = self.analyze()
        self.assertEqual(1, result['comparison']['missing_usb_occurrences'])
        self.assertEqual(1, result['comparison']['extra_usb_occurrences'])
        self.assertFalse(result['selected_window_rx_agreement_qualified'])
        self.assertEqual(actual.hex(), result['dvi']['short_network_examples'][0]['payload']['literal_hex_if_short'])

    def test_duplicates_and_reordered_messages_do_not_pass(self):
        a, b = bytes.fromhex('6cf0107600'), bytes.fromhex('6cf0107d0500')
        self.files(dvi(a) + dvi(b), '[DEBUG] Received: 6C F0 10 7D 05 00\n[DEBUG] Received: 6C F0 10 76 00\n')
        result = self.analyze()
        self.assertFalse(result['comparison']['literal_ordered_rx_agreement'])
        self.assertEqual(0, result['comparison']['missing_usb_occurrences'])
        self.files(dvi(a), '[DEBUG] Received: 6C F0 10 76 00\n' * 2)
        self.assertEqual(1, self.analyze()['comparison']['missing_usb_occurrences'])

    def test_explicit_bootstrap_and_interwindow_gaps_are_preserved(self):
        a = dvi(bytes.fromhex('6cf0107600'))
        stream = b'ELM\r>' + a + b'RESET\r>' + a + b'END'
        start = 5
        second = start + len(a) + 7
        self.files(stream, '[DEBUG] Received: 6C F0 10 76 00\n' * 2)
        result = self.analyze([(start, start + len(a)), (second, second + len(a))])
        self.assertTrue(result['selected_window_rx_agreement_qualified'])
        gaps = result['dvi']['skipped_stream_spans']
        self.assertEqual([b'ELM\r>'.hex(), b'RESET\r>'.hex(), b'END'.hex()],
                         [g['data']['literal_hex_if_short'] for g in gaps])
        self.assertFalse(self.analyze()['selected_window_rx_agreement_qualified'])

    def test_invalid_or_overlapping_windows_rejected(self):
        self.files(dvi(b'1234'), '')
        for windows in ([], [(0, 0)], [(0, 999)], [(-1, 3)], [(3, 6), (2, 5)]):
            with self.subTest(windows=windows), self.assertRaises(ValueError):
                capture.analyze(self.pcap, self.log, bus=2, device=7, endpoint=0x81, windows=windows)

    def test_checksum_failure_retains_unparsed_bytes_and_stops_without_resync(self):
        ack = bytes.fromhex('6cf0107600')
        good = dvi(ack)
        bad = good[:-1] + bytes([good[-1] ^ 1])
        self.files(good + bad + good, '[DEBUG] Received: 6C F0 10 76 00\n' * 3)
        result = self.analyze()
        self.assertEqual(1, result['dvi']['network_count'])
        self.assertEqual(len(good), result['dvi']['issues'][0]['unparsed_start'])
        self.assertEqual((bad + good).hex(), result['dvi']['issues'][0]['unparsed']['literal_hex_if_short'])
        self.assertFalse(result['selected_window_analysis_complete'])

    def test_timestamp_reply_changes_following_framing(self):
        ack = bytes.fromhex('6cf0107600')
        setup = dvi(b'\x03\x01', command=0x34)
        self.files(setup + dvi(ack, timestamp=b'\x01\x02\x03\x04'), '[DEBUG] Received: 6C F0 10 76 00\n')
        result = self.analyze(timestamps=False)
        self.assertTrue(result['selected_window_rx_agreement_qualified'])
        self.assertEqual('01020304', result['dvi']['short_network_examples'][0]['adapter_timestamp_raw_hex'])

    def test_long_network_frame_compared_without_copying_payload_to_report(self):
        data = bytes(range(256)) * 2
        self.files(dvi(data, command=9), '[DEBUG] Received: ' + data.hex(' ') + '\n')
        result = self.analyze()
        self.assertTrue(result['selected_window_rx_agreement_qualified'])
        self.assertIsNone(result['dvi']['frame_examples'][0]['payload']['literal_hex_if_short'])

    def test_usb_failure_or_unpaired_completion_prevents_qualification(self):
        data = dvi(bytes.fromhex('6cf0107600'))
        log = '[DEBUG] Received: 6C F0 10 76 00\n'
        for records in ([usb(data)], exchange(data) + [usb(info=0, irp=2), usb(info=1, irp=2, status=0xC0010000)]):
            with self.subTest(records=records):
                self.files(data, log, records=records)
                result = self.analyze()
                self.assertTrue(result['comparison']['literal_ordered_rx_agreement'])
                self.assertFalse(result['selected_window_rx_agreement_qualified'])

    def test_tx_distinguishes_test_copy_execute_and_erase_without_claiming_success(self):
        log = '\n'.join([
            '[DEBUG] TX: 6D 10 F0 36 44 00 01 01 00 00 AB 00 00',
            '[DEBUG] TX: 6D 10 F0 36 00 00 01 FF 80 00 AB 00 00',
            '[DEBUG] TX: 6D 10 F0 36 80 00 01 FF 80 00 AB 00 00',
            '[DEBUG] TX: 6C 10 F0 3D 05 01 00 00',
            'Retry count for this block: 2'])
        report, tx, rx = capture.parse_log(log.encode())
        self.assertEqual(4, len(tx))
        self.assertFalse(rx)
        self.assertEqual({'tx:test_write_request': 1, 'tx:copy_ram_or_flash_request': 1,
                          'tx:copy_and_execute_request': 1, 'tx:erase_request': 1}, report['protocol_counts'])
        self.assertEqual(1, len(report['retry_text_observations']))

    def test_malformed_log_hex_and_no_rx_prevent_qualification(self):
        self.files(dvi(b'1234'), '[DEBUG] Received: 6C 0GG\n')
        result = self.analyze()
        self.assertFalse(result['selected_window_rx_agreement_qualified'])
        self.assertEqual('malformed_hex_message', result['log']['issues'][0]['reason'])

    def test_input_and_expanded_frame_resource_limits_fail_closed(self):
        self.files(dvi(b'1234') * 2, '')
        with self.assertRaisesRegex(ValueError, 'memory limit'):
            self.analyze(max_input_bytes=3)
        with patch.object(capture, 'MAX_FRAMES', 1):
            result = self.analyze()
        self.assertFalse(result['selected_window_analysis_complete'])
        self.assertIn('resource limit', result['dvi']['issues'][0]['error'])

    def test_bounded_malformed_log_examples_retain_total_counts(self):
        report, _, _ = capture.parse_log(b'[DEBUG] Received: not hex\n' * 1005)
        self.assertEqual({'malformed_hex_message': 1005}, report['issue_counts'])
        self.assertEqual(1000, len(report['issues']))
        self.assertEqual(5, report['omitted_issue_examples'])

    def test_late_adapter_error_and_unknown_command_remain_visible(self):
        prefix = dvi(b'\x01', command=0x32) * 1001
        self.files(prefix + dvi(b'\x55', command=0x7f) + dvi(b'\x66', command=0x66), '')
        result = self.analyze()
        self.assertEqual({'32': 1001, '7f': 1, '66': 1}, result['dvi']['command_counts'])
        self.assertEqual('55', result['dvi']['adapter_error_examples'][0]['payload']['literal_hex_if_short'])

    def test_cli_exclusive_receipt_and_utf16_log(self):
        self.files(dvi(bytes.fromhex('6cf0107600')), '')
        self.log.write_text('[DEBUG] Received: 6C F0 10 76 00\n', encoding='utf-16')
        output = self.folder / 'result.json'
        args = ['--pcap', str(self.pcap), '--log', str(self.log), '--bus', '2', '--device', '7',
                '--endpoint', '0x81', '--window', '0:', '--timestamps', 'off', '--log-encoding', 'utf-16',
                '--output', str(output)]
        self.assertEqual(0, capture.main(args))
        result = json.loads(output.read_text())
        self.assertEqual(capture.digest(self.log.read_bytes()), result['inputs']['debug_log']['sha256'])
        with self.assertRaises(FileExistsError):
            capture.main(args)


if __name__ == '__main__':
    unittest.main()
