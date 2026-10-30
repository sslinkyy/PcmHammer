"""Synthetic classic-PCAP fixtures exercise the actual offline file/CLI boundary."""
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

import compare_usb_serial_capture as compare


def usb(data=b'', *, irp=1, info=1, bus=2, device=7, endpoint=0x81,
        transfer=3, function=9, status=0, header_length=27, declared=None):
    # Deliberately independent literal format, not the production packer.
    return (struct.pack('<HQIHBHHBBI', header_length, irp, status, function, info,
                        bus, device, endpoint, transfer, len(data) if declared is None else declared)
            + data)


def pcap(records, *, endian='<', nanoseconds=False, snaplen=65535, linktype=249):
    magic = 0xa1b23c4d if nanoseconds else 0xa1b2c3d4
    value = struct.pack(endian + 'IHHIIII', magic, 2, 4, 0, 0, snaplen, linktype)
    for number, record in enumerate(records):
        if isinstance(record, tuple):
            data, original = record
        else:
            data, original = record, len(record)
        value += struct.pack(endian + 'IIII', 1761850000, number, len(data), original) + data
    return value


def exchange(data, **kwargs):
    return [usb(info=0, **kwargs), usb(data, info=1, **kwargs)]


class UsbSerialCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.pcap_path = self.folder / 'usb.pcap'
        self.serial_path = self.folder / 'capture.jsonl'

    def inputs(self, records, chunks, **pcap_options):
        self.pcap_path.write_bytes(pcap(records, **pcap_options))
        rows = [{'kind': 'transport', 'api': 'dvi'}]
        rows += [{'kind': 'serial_rx', 'raw_hex': item.hex(), 'host_monotonic_ns': index,
                  'read_sequence': index + 1} for index, item in enumerate(chunks)]
        # Decoded rows are not raw bytes and must not be included a second time.
        rows += [{'kind': 'network', 'payload_hex': 'deadbeef'}, {'kind': 'result', 'success': True}]
        self.serial_path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf8')

    def analyze(self):
        return compare.analyze(self.pcap_path, self.serial_path, bus=2, device=7, endpoint=0x81)

    def test_literal_chunk_independent_equality_and_allowed_irp_reuse(self):
        payload = bytes.fromhex('0802aabb550001020304')
        self.inputs(exchange(payload[:3]) + exchange(payload[3:]), [payload[:1], b'', payload[1:7], payload[7:]])
        result = self.analyze()
        self.assertTrue(result['analysis_complete'])
        self.assertTrue(result['selected_stream_agreement_qualified'])
        self.assertTrue(result['comparison']['literal_byte_agreement'])
        counts = result['pcap']['counts']
        self.assertEqual(2, counts['selected_successful_completion_records'])
        self.assertEqual(1, counts['selected_irp_reuses_after_completion'])
        self.assertEqual(len(payload), result['pcap']['selected_stream_bytes'])
        self.assertEqual(0, result['pcap']['urb_pairing']['count'])
        self.assertFalse(result['capture_integrity']['usb_capture_losslessness_proven'])
        self.assertFalse(result['hardware_access_performed'])

    def test_big_little_endian_and_micro_nanosecond_pcap_share_little_usb_header(self):
        for endian in ('<', '>'):
            for ns in (False, True):
                with self.subTest(endian=endian, ns=ns):
                    self.inputs(exchange(b'actual bytes', irp=0x123456789abcdef0), [b'actual bytes'],
                                endian=endian, nanoseconds=ns)
                    result = self.analyze()
                    self.assertTrue(result['selected_stream_agreement_qualified'])
                    self.assertEqual(1000000000 if ns else 1000000,
                                     result['pcap']['header']['timestamp_fraction_units_per_second'])
                    self.assertEqual('0x123456789abcdef0', result['pcap']['selected_record_examples'][0]['irp_id_hex'])

    def test_wall_clock_regression_warns_without_reordering_or_invalidating_bytes(self):
        self.inputs(exchange(b'first') + exchange(b'second', irp=2), [b'firstsecond'])
        raw = bytearray(self.pcap_path.read_bytes())
        # Regress the second completion's wall time while preserving file order.
        last_record_offset = 24 + 43 + 48 + 43
        struct.pack_into('<II', raw, last_record_offset, 1761849999, 0)
        self.pcap_path.write_bytes(raw)
        result = self.analyze()
        self.assertTrue(result['analysis_complete'])
        self.assertTrue(result['selected_stream_agreement_qualified'])
        self.assertTrue(result['comparison']['literal_byte_agreement'])
        warnings = result['pcap']['timing_warnings']
        self.assertEqual({'pcap_timestamp_regressed': 1}, warnings['counts_by_code'])
        self.assertEqual(4, warnings['examples'][0]['record'])
        self.assertEqual(0, result['pcap']['issues']['count'])
        # An out-of-range fraction is a malformed field, not a clock warning.
        struct.pack_into('<I', raw, last_record_offset + 4, 1000000)
        self.pcap_path.write_bytes(raw)
        invalid = self.analyze()
        self.assertFalse(invalid['analysis_complete'])
        self.assertIn('invalid_timestamp_fraction', invalid['pcap']['issues']['counts_by_code'])

    def test_selection_excludes_other_devices_buses_and_out_endpoints_and_inventory_is_explicit(self):
        records = (exchange(b'wrong device', device=8) + exchange(b'right', irp=2)
                   + exchange(b'wrong bus', bus=3) + [usb(b'host output', info=0, endpoint=0x01)])
        self.inputs(records, [b'right'])
        result = self.analyze()
        self.assertTrue(result['selected_stream_agreement_qualified'])
        self.assertEqual(5, result['pcap']['counts']['unselected_records'])
        inventory = compare.analyze(self.pcap_path)
        self.assertEqual('inventory', inventory['mode'])
        self.assertEqual(4, len(inventory['pcap']['endpoint_inventory']))
        self.assertIsNone(inventory['comparison'])
        self.assertIsNone(inventory['selection'])
        with self.assertRaisesRegex(ValueError, 'explicit integer'):
            compare.analyze(self.pcap_path, self.serial_path)
        with self.assertRaisesRegex(ValueError, '0x81'):
            compare.analyze(self.pcap_path, self.serial_path, bus=2, device=7, endpoint=1)

    def test_duplicate_completion_is_not_deduplicated_and_submission_bytes_are_invalid(self):
        self.inputs(exchange(b'ack') + [usb(b'ack')], [b'ack'])
        result = self.analyze()
        self.assertEqual(6, result['comparison']['usb_bytes'])
        self.assertFalse(result['comparison']['literal_byte_agreement'])
        self.assertEqual(1, result['pcap']['urb_pairing']['counts_by_code']['duplicate_completion_without_submission'])
        self.assertFalse(result['selected_stream_agreement_qualified'])
        self.inputs([usb(b'unexpected', info=0), usb(b'ack')], [b'ack'])
        result = self.analyze()
        self.assertTrue(result['comparison']['literal_byte_agreement'])
        self.assertEqual(1, result['pcap']['issues']['counts_by_code']['unexpected_payload_on_in_submission'])
        self.assertFalse(result['analysis_complete'])

    def test_irp_overlap_or_missing_capture_boundaries_remain_uncertain(self):
        cases = [([usb(b'ack')], 'completion_without_recorded_submission'),
                 (exchange(b'ack') + [usb(info=0, irp=2)], 'submission_pending_at_capture_end'),
                 ([usb(info=0), usb(info=0), usb(b'ack')], 'duplicate_or_reused_pending_submission')]
        for records, expected in cases:
            with self.subTest(expected=expected):
                self.inputs(records, [b'ack'])
                result = self.analyze()
                self.assertTrue(result['comparison']['literal_byte_agreement'])
                self.assertTrue(result['analysis_complete'])
                self.assertIn(expected, result['pcap']['urb_pairing']['counts_by_code'])
                self.assertFalse(result['selected_stream_agreement_qualified'])

    def test_selected_failed_and_unsupported_transfers_cannot_silently_qualify(self):
        for changes, code in [({'status': 0xc0000001}, 'selected_non_success_status'),
                              ({'function': 8}, 'unsupported_selected_transfer'),
                              ({'transfer': 1}, 'unsupported_selected_transfer'),
                              ({'info': 3}, 'unsupported_selected_transfer')]:
            with self.subTest(changes=changes):
                self.inputs(exchange(b'good') + [usb(info=0, irp=2), usb(b'bad', irp=2, **changes)], [b'good'])
                result = self.analyze()
                self.assertTrue(result['comparison']['literal_byte_agreement'])
                self.assertFalse(result['analysis_complete'])
                self.assertIn(code, result['pcap']['issues']['counts_by_code'])
                self.assertIn('captured_data_sha256', result['pcap']['selected_record_examples'][-1])

    def test_snaplen_length_claims_and_physically_truncated_files_fail_closed(self):
        self.inputs([usb(info=0), (usb(b'ab'), 32)], [b'ab'], snaplen=29)
        result = self.analyze()
        self.assertIn('pcap_snaplen_truncation', result['pcap']['issues']['counts_by_code'])
        self.assertFalse(result['analysis_complete'])
        self.assertEqual(0, result['comparison']['usb_bytes'])
        self.inputs(exchange(b'actual'), [b'actual'])
        self.pcap_path.write_bytes(self.pcap_path.read_bytes()[:-1])
        result = self.analyze()
        self.assertIn('truncated_pcap_record_data', result['pcap']['issues']['counts_by_code'])
        self.assertFalse(result['pcap']['source_fully_read'])
        self.inputs([usb(info=0), usb(b'a', declared=0xffffffff)], [b'a'])
        result = self.analyze()
        self.assertIn('usbpcap_header_or_data_length_mismatch', result['pcap']['issues']['counts_by_code'])
        self.assertEqual(0, result['comparison']['usb_bytes'])
        self.inputs(exchange(b'good'), [b'good'])
        self.pcap_path.write_bytes(self.pcap_path.read_bytes() + b'\x01\x02')
        result = self.analyze()
        self.assertTrue(result['comparison']['literal_byte_agreement'])
        self.assertFalse(result['analysis_complete'])
        self.assertIn('truncated_pcap_record_header', result['pcap']['issues']['counts_by_code'])

    def test_first_difference_and_eof_are_exact_and_no_prefix_alignment_occurs(self):
        self.inputs(exchange(bytes(range(50))), [bytes(range(20)), bytes([99]) + bytes(range(21, 50))])
        result = self.analyze()['comparison']
        self.assertEqual(20, result['first_differing_stream_offset'])
        self.assertEqual(4, result['difference_context']['stream_offset_start'])
        self.assertEqual(33 * 2, len(result['difference_context']['usb_hex']))
        self.assertEqual(2, result['difference_context']['usb_location']['record'])
        self.assertEqual(3, result['difference_context']['serial_location']['line'])
        self.assertEqual(0, result['difference_context']['serial_location']['offset_within_payload'])
        self.inputs(exchange(b'prefixBODY'), [b'BODY'])
        result = self.analyze()['comparison']
        self.assertEqual(0, result['first_differing_stream_offset'])
        self.assertFalse(result['alignment_or_trimming_performed'])
        self.inputs(exchange(b'bodyEXTRA'), [b'body'])
        result = self.analyze()['comparison']
        self.assertEqual(4, result['first_differing_stream_offset'])
        self.assertTrue(result['difference_context']['serial_eof_at_difference'])
        self.assertIsNone(result['difference_context']['serial_location'])

    def test_invalid_serial_data_and_incomplete_terminal_evidence_are_not_success(self):
        for malformed_success in (1, 1.0, 'true', None):
            with self.subTest(malformed_success=malformed_success):
                self.inputs(exchange(b'good'), [b'good'])
                rows = [json.loads(line) for line in self.serial_path.read_text().splitlines()]
                rows[-1]['success'] = malformed_success
                self.serial_path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf8')
                result = self.analyze()
                self.assertTrue(result['comparison']['literal_byte_agreement'])
                self.assertIn('serial_result_not_one_final_success', result['serial']['issues']['counts_by_code'])
                self.assertFalse(result['analysis_complete'])
                self.assertFalse(result['selected_stream_agreement_qualified'])
        self.inputs(exchange(b'good'), [b'good'])
        with self.serial_path.open('a', encoding='utf8') as stream:
            stream.write('{broken json')
        result = self.analyze()
        self.assertTrue(result['comparison']['literal_byte_agreement'])
        self.assertFalse(result['serial']['source_fully_read'])
        self.assertFalse(result['analysis_complete'])
        self.inputs(exchange(b'good'), [b'good'])
        rows = [json.loads(line) for line in self.serial_path.read_text().splitlines()]
        rows[-1]['success'] = False
        rows[1]['raw_hex'] = 'xx'
        self.serial_path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf8')
        result = self.analyze()
        self.assertIn('invalid_serial_rx_bytes', result['serial']['issues']['counts_by_code'])
        self.assertFalse(result['selected_stream_agreement_qualified'])

    def test_pcapng_wrong_linktype_and_oversized_input_are_explicit(self):
        self.pcap_path.write_bytes(b'\x0a\x0d\x0d\x0a' + b'\x00' * 24)
        result = compare.analyze(self.pcap_path)
        self.assertEqual(1, result['pcap']['issues']['counts_by_code']['unsupported_pcapng'])
        self.assertFalse(result['analysis_complete'])
        self.inputs([], [], linktype=1)
        result = compare.analyze(self.pcap_path)
        self.assertIn('unsupported_linktype_or_additional_flags', result['pcap']['issues']['counts_by_code'])
        with self.assertRaisesRegex(ValueError, 'memory limit'):
            compare.analyze(self.pcap_path, max_input_bytes=23)

    def test_cli_receipt_records_input_and_tool_hash_and_never_overwrites(self):
        self.inputs(exchange(b'whole bytes'), [b'whole bytes'])
        output = self.folder / 'receipt.json'
        args = ['--pcap', str(self.pcap_path), '--serial', str(self.serial_path),
                '--bus', '2', '--device', '7', '--endpoint', '0x81', '--output', str(output)]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, compare.main(args))
        result = json.loads(output.read_text())
        self.assertEqual(compare.sha256(self.pcap_path.read_bytes()), result['inputs']['pcap']['sha256'])
        self.assertEqual(compare.sha256(Path(compare.__file__).read_bytes()), result['implementation_sha256'])
        self.assertTrue(result['selected_stream_agreement_qualified'])
        saved = output.read_bytes()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            compare.main(args)
        self.assertEqual(2, raised.exception.code)
        self.assertEqual(saved, output.read_bytes())


if __name__ == '__main__':
    unittest.main()
