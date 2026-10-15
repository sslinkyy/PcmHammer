import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

from inspect_allison_playback import HEADER, SEPARATOR, inspect_bytes, main


def record(payload, timestamp=1, flags=0, unused=None, trailer=b'\x00'*8):
    message = timestamp.to_bytes(4, 'big') + b'\x00\xef\x00\x06\x03\xf9' + payload
    if unused is None:
        unused = b'\xee'*(18-len(message))
    assert len(message)+len(unused) == 18
    assert len(trailer) == 8
    return struct.pack('<HH', len(message), flags)+message+unused+trailer


class PlaybackTests(unittest.TestCase):
    def test_exact_boundaries_and_payload_scope(self):
        a = record(b'\x62\x1a\x40U2A', 1193)
        b = record(b'\x44', 2000, trailer=b'\x12\x20\x2c\x7fABCD')
        data = HEADER+a+SEPARATOR+b
        report = inspect_bytes(data, include_records=True)
        self.assertTrue(report['complete'])
        self.assertEqual(report['coverage']['examined_end_offset'], len(data))
        static, dynamic = report['sections']['static'], report['sections']['data']
        self.assertEqual(static['start_offset'], len(HEADER))
        self.assertEqual(dynamic['records'][0]['offset'], len(HEADER)+30+len(SEPARATOR))
        self.assertEqual(dynamic['payload_leading_byte_counts'], {'44': 1})
        self.assertEqual(dynamic['special_payload_samples']['12'], [])
        self.assertEqual(static['identification_candidates'][0]['ascii_candidate'], 'U2A')
        self.assertEqual(dynamic['records'][0]['payload_hex'], '44')
        self.assertTrue(all(value is False for value in report['gates'].values()))

    def test_unaligned_embedded_separator_is_not_a_boundary(self):
        # The delimiter occurs across the unused/trailer bytes of a valid record.
        raw = record(b'', unused=SEPARATOR[:8], trailer=SEPARATOR[8:]+b'abcdef')
        report = inspect_bytes(HEADER+raw+SEPARATOR+record(b'\x59'), include_records=True)
        self.assertTrue(report['complete'])
        self.assertEqual(report['sections']['static']['record_count'], 1)

    def test_invalid_length_stops_without_resync(self):
        valid = record(b'\x52')
        bad = struct.pack('<H', 19)+valid[2:]
        report = inspect_bytes(HEADER+valid+bad+SEPARATOR+valid, include_records=True)
        self.assertFalse(report['complete'])
        self.assertEqual(report['error']['code'], 'invalid_message_length')
        self.assertEqual(report['coverage']['examined_end_offset'], len(HEADER)+30)
        self.assertEqual(report['sections']['static']['record_count'], 1)
        self.assertEqual(report['sections']['data']['record_count'], 0)

    def test_short_length_rejected(self):
        raw = struct.pack('<H', 9)+record(b'')[2:]
        self.assertEqual(inspect_bytes(HEADER+SEPARATOR+raw)['error']['code'], 'invalid_message_length')

    def test_opaque_flags_preserved_without_length_expansion(self):
        report = inspect_bytes(HEADER+SEPARATOR+record(b'\x59', flags=0xffff), include_records=True)
        self.assertTrue(report['complete'])
        row = report['sections']['data']['records'][0]
        self.assertEqual(row['opaque_high_word'], 0xffff)
        self.assertEqual(row['message_length_low_word'], 11)
        self.assertEqual(report['sections']['data']['opaque_high_word_counts'], {'0xffff': 1})
        self.assertFalse(report['gates']['protocol_interpretation_qualified'])

    def test_truncated_record_retains_complete_prefix(self):
        raw = record(b'\x6a\x01')
        report = inspect_bytes(HEADER+SEPARATOR+raw+raw[:15])
        self.assertFalse(report['complete'])
        self.assertEqual(report['error']['code'], 'truncated_record_or_separator')
        self.assertEqual(report['sections']['data']['record_count'], 1)
        self.assertEqual(report['coverage']['unexamined_bytes'], 15)

    def test_missing_and_truncated_separator(self):
        for suffix in (b'', SEPARATOR[:5]):
            report = inspect_bytes(HEADER+record(b'\x60')+suffix)
            self.assertFalse(report['complete'])
            self.assertEqual(report['sections']['static']['record_count'], 1)

    def test_bad_or_incomplete_header_is_not_searched_past(self):
        for bad in (HEADER[:-1], HEADER.replace(b'J1939', b'J1708'), b'x'+HEADER):
            report = inspect_bytes(bad+SEPARATOR+record(b'\x44'))
            self.assertFalse(report['complete'])
            self.assertEqual(report['error']['code'], 'unsupported_or_truncated_header')
            self.assertEqual(report['coverage']['examined_end_offset'], 0)

    def test_unused_previous_slot_comparison_excludes_tail(self):
        first = record(bytes.fromhex('6aff010203040506'))
        second = record(b'\x44', timestamp=2, unused=first[15:22], trailer=b'12345678')
        report = inspect_bytes(HEADER+SEPARATOR+first+second)
        dynamic = report['sections']['data']
        self.assertEqual(dynamic['short_record_previous_slot_comparison'], {'same_as_previous_slot': 1})
        self.assertEqual(dynamic['special_payload_samples']['44'][0]['payload_hex'], '44')
        self.assertEqual(dynamic['special_payload_samples']['44'][0]['unused_slot_hex'], first[15:22].hex())

    def test_timestamp_raw_backwards_and_empty_payload(self):
        report = inspect_bytes(HEADER+SEPARATOR+record(b'', 100)+record(b'\x7f\x2a\x23', 99))
        dynamic = report['sections']['data']
        self.assertEqual(dynamic['timestamp_backwards_count'], 1)
        self.assertEqual(dynamic['timestamp_units'], 'unknown')
        self.assertEqual(dynamic['payload_leading_byte_counts'], {'7f': 1, 'empty': 1})
        self.assertEqual(dynamic['special_payload_samples']['7f'][0]['payload_hex'], '7f2a23')

    def test_cli_partial_report_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory)/'source.log', Path(directory)/'report.json'
            source.write_bytes(HEADER+SEPARATOR+record(b'\x44')+b'bad')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(source), '--output', str(output)]), 1)
            self.assertFalse(json.loads(output.read_text())['complete'])
            original = output.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main([str(source), '--output', str(output)])
            self.assertEqual(output.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
