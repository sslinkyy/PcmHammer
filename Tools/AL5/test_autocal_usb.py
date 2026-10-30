"""Offline packet/descriptor boundary tests using synthetic USBPcap data."""
import struct
import unittest

import analyze_autocal_usb as a
import compare_usb_serial_capture as u
from checksum import crc16


def wrapper(channel, payload=b'', route=b'\x01\x82'):
    header = (b'\x01T' if channel == 1 else b'\x01R') + route + bytes(6) + len(payload).to_bytes(2, 'little')
    body = header + payload
    return body + crc16(body).to_bytes(2, 'little') + (b'\x19' if channel == 2 else b'')


def ftdi(data, size=64):
    return b''.join(b'\x31\x60' + data[i:i + size - 2] for i in range(0, len(data), size - 2))


def pcap_record(irp, endpoint, completion, data=b'', status=0, function=9, transfer=3):
    h = u.USB_HEADER.pack(27, irp, status, function, int(completion), 2, 8, endpoint, transfer, len(data))
    return struct.pack('<IIII', 10, 0, len(h) + len(data), len(h) + len(data)) + h + data


def pcap(*records):
    return b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, 1048576, 249) + b''.join(records)


def descriptor_report(address=8, instance=r'USB\VID_0403&PID_E4A3\TEST_ONLY'):
    return ('================ USB Device ================\r\n'
            'Device ID : ' + instance + '\r\n'
            f'Device Address : 0x{address:02x} ({address})\r\n'
            'Device Bus Speed : 0x01 (Full-Speed)\r\n'
            '----------- Device Descriptor -----------\r\n'
            'Data (HexDump) : 12 01 00 02 00 00 00 08 03 04 A3 E4 00 06 01 02   ................\r\n'
            '                  03 01                                             ..\r\n'
            '\r\n----------- Configuration Descriptor -----------\r\n'
            'Data (HexDump) : 09 02 20 00 01 01 00 80 96 09 04 00 00 02 FF FF   ................\r\n'
            '                  FF 02 07 05 81 02 40 00 00 07 05 02 02 40 00 00   ................\r\n'
            '\r\n================ USB Port4 ================\r\n').encode('ascii')


class AutoCalUsbTests(unittest.TestCase):
    def test_aggregated_packets_remove_status_per_packet(self):
        expected = wrapper(2, bytes(range(256)), b'\x15\x85')
        raw = ftdi(expected)
        self.assertEqual(len(raw), 281)
        packets = a.packetize(raw, 64)
        self.assertEqual([p['bytes'] for p in packets], [64, 64, 64, 64, 25])
        self.assertEqual([p['offset'] for p in packets], [0, 64, 128, 192, 256])
        self.assertEqual(b''.join(p['application_bytes'] for p in packets), expected)
        self.assertNotEqual(raw[2:], expected)

    def test_status_only_packet_retained(self):
        self.assertEqual(a.packetize(b'\x31\x60', 64), [{'offset': 0, 'bytes': 2, 'status_hex': '3160',
                         'application_offset': 2, 'application_bytes': b''}])

    def test_one_byte_packet_rejected(self):
        with self.assertRaises(ValueError):
            a.packetize(bytes(65), 64)

    def test_packet_size_must_be_explicit_supported_integer(self):
        for size in (True, 0, 63, 1024):
            with self.subTest(size=size), self.assertRaises(ValueError):
                a.packetize(b'12', size)

    def test_envelope_spans_multiple_source_packets(self):
        raw = wrapper(2, bytes(range(80)))
        parts = [{'record': 4, 'stream_start': 0, 'stream_end_exclusive': 62, 'pcap_file_offset': 200},
                 {'record': 4, 'stream_start': 62, 'stream_end_exclusive': len(raw), 'pcap_file_offset': 264}]
        result, private = a.envelopes(raw, parts, 2)
        self.assertTrue(result['all_retained_bytes_frame_and_crc_match'])
        self.assertEqual(len(result['envelopes'][0]['pcap_spans']), 2)
        self.assertEqual(private[0]['wrapper_hex'], raw.hex())
        self.assertNotIn('wrapper_hex', result['envelopes'][0])

    def test_bad_crc_is_retained(self):
        raw = bytearray(wrapper(2, b'ACV2\0')); raw[-2] ^= 1
        result, private = a.envelopes(bytes(raw), [{'record': 2, 'stream_start': 0, 'stream_end_exclusive': len(raw), 'pcap_file_offset': 40}], 2)
        self.assertEqual(result['crc_failed_ordinals'], [0])
        self.assertEqual(private[0]['wrapper_hex'], raw.hex())
        self.assertEqual(result['unparsed']['bytes'], 0)

    def test_unknown_prefix_does_not_resynchronize(self):
        raw = b'X' + wrapper(2)
        result, private = a.envelopes(raw, [{'record': 2, 'stream_start': 0, 'stream_end_exclusive': len(raw), 'pcap_file_offset': 40}], 2)
        self.assertEqual(result['envelope_count'], 0)
        self.assertEqual(result['unparsed']['bytes'], len(raw))
        self.assertEqual(private, [])

    def test_full_pcap_preserves_pending_and_unsupported(self):
        tx, rx = wrapper(1), wrapper(2, bytes(range(256)))
        raw = pcap(pcap_record(1, 2, False, tx, status=0xdeadbeef), pcap_record(1, 2, True),
                   pcap_record(2, 0x81, False), pcap_record(2, 0x81, True, ftdi(rx)),
                   pcap_record(3, 0x81, False), pcap_record(3, 0x81, True, b'\x31\x60'),
                   pcap_record(4, 0x81, False, function=30, transfer=254),
                   pcap_record(4, 0x81, True, function=30, transfer=254),
                   pcap_record(5, 0x81, False))
        result, private = a.analyze(raw, bus=2, device=8, in_endpoint=0x81, out_endpoint=2, max_packet_size=64)
        self.assertTrue(result['framing_agreement_under_packet_hypothesis'])
        self.assertFalse(result['complete_capture_proven'])
        self.assertFalse(result['descriptor_packet_size_verified'])
        self.assertEqual(result['usb_producer']['urb_pairing']['count'], 1)
        self.assertEqual(len(result['unsupported_or_other_records']), 2)
        self.assertEqual(result['derived_status_only_packet_count'], 1)
        self.assertEqual(len(result['packet_ledger']), 6)
        self.assertEqual(result['output_pairing_issues'], [])
        self.assertEqual(private['rx'][0]['wrapper_hex'], rx.hex())

    def test_wrong_packet_hypothesis_cannot_silently_pass(self):
        rx = wrapper(2, bytes(range(256)))
        tx = wrapper(1)
        raw = pcap(pcap_record(1, 2, False, tx), pcap_record(1, 2, True),
                   pcap_record(2, 0x81, False), pcap_record(2, 0x81, True, ftdi(rx)))
        result, _ = a.analyze(raw, bus=2, device=8, in_endpoint=0x81, out_endpoint=2, max_packet_size=512)
        self.assertFalse(result['framing_agreement_under_packet_hypothesis'])
        self.assertTrue(result['rx']['crc_failed_ordinals'])
        self.assertGreater(result['rx']['unparsed']['bytes'], 0)

    def test_truncated_record_rejected(self):
        with self.assertRaises(ValueError):
            a.analyze(pcap(pcap_record(1, 0x81, True, b'12'))[:-1], bus=2, device=8,
                      in_endpoint=0x81, out_endpoint=2, max_packet_size=64)

    def test_identity_bound_descriptor(self):
        result = a.descriptor_evidence_from_report(descriptor_report(), r'USB\VID_0403&PID_E4A3\TEST_ONLY', 8, 0x81, 2, 64)
        self.assertEqual([e['max_packet_size'] for e in result['endpoints']], [64, 64])
        self.assertEqual(len(bytes.fromhex(result['configuration_descriptor_hex'])), 32)
        self.assertTrue(result['configuration_descriptor_source_lines'])

    def test_utf16_descriptor_offsets_remain_raw_file_offsets(self):
        text = descriptor_report().decode('ascii')
        raw = b'\xff\xfe' + text.encode('utf-16le')
        result = a.descriptor_evidence_from_report(raw, r'USB\VID_0403&PID_E4A3\TEST_ONLY', 8, 0x81, 2, 64)
        self.assertEqual(result['source_text_encoding'], 'utf-16le')
        self.assertEqual(result['section_start_file_offset'], 2)
        span = result['configuration_descriptor_source_lines'][0]
        self.assertTrue(raw[span['file_offset']:span['file_offset'] + span['bytes']].decode('utf-16le').startswith('Data (HexDump) : 09 02'))

    def test_descriptor_wrong_identity_address_or_size_rejected(self):
        cases = [(r'USB\VID_0403&PID_E4A3\WRONG', 8, 64),
                 (r'USB\VID_0403&PID_E4A3\TEST_ONLY', 2, 64),
                 (r'USB\VID_0403&PID_E4A3\TEST_ONLY', 8, 512)]
        for identity, address, size in cases:
            with self.subTest(identity=identity, address=address, size=size), self.assertRaises(ValueError):
                a.descriptor_evidence_from_report(descriptor_report(), identity, address, 0x81, 2, size)

    def test_ambiguous_descriptor_identity_rejected(self):
        with self.assertRaises(ValueError):
            a.descriptor_evidence_from_report(descriptor_report() * 2, r'USB\VID_0403&PID_E4A3\TEST_ONLY', 8, 0x81, 2, 64)

    def test_descriptor_raw_length_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            a.descriptor_evidence_from_report(descriptor_report().replace(b'09 02 20 00', b'09 02 21 00'),
                                             r'USB\VID_0403&PID_E4A3\TEST_ONLY', 8, 0x81, 2, 64)


if __name__ == '__main__':
    unittest.main()
