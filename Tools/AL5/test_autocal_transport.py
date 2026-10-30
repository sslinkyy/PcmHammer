"""Offline HTX wrapper contracts; these tests never establish USB/device behavior."""
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

import autocal_transport as transport
from audit_trace_wrappers import framed_message
from checksum import crc16
from decode_trace_containers import decode, records, SIGNATURE


FIXTURE = Path(__file__).with_name('Fixtures') / 'autocal_htx_envelope_cases.json'


def wrapped(payload=b'', channel=1, route=b'\x01\x82', metadata=bytes(6), trailer=0x19):
    head = (b'\x01\x54' if channel == 1 else b'\x01\x52') + route + metadata
    head += len(payload).to_bytes(2, 'little') + payload
    return head + crc16(head, 0).to_bytes(2, 'little') + (bytes([trailer]) if channel == 2 else b'')


def record(payload, channel=1, kind=0x42):
    return struct.pack('<dBHHBI', 46282.5, channel, 7, 2, kind, len(payload)) + payload


def encode(raw_records):
    decoded = SIGNATURE + bytes(1024 - len(SIGNATURE)) + raw_records
    return bytes(((((b ^ 0xa5) >> 3) | ((b ^ 0xa5) << 5)) + 0x87) & 255
                 for b in zlib.compress(decoded))


class AutoCalHtxEnvelopeTests(unittest.TestCase):
    def test_literal_shared_corpus_and_exact_provenance(self):
        corpus = json.loads(FIXTURE.read_text(encoding='utf8'))
        self.assertEqual(1, corpus['schema_version'])
        for case in corpus['cases']:
            with self.subTest(case=case['name']):
                raw = bytes.fromhex(case['wrapper_hex'])
                saved = encode(record(raw, case['channel']))
                decoded = decode(saved)
                parsed = list(records(decoded))[0]
                observed = transport.envelope_evidence(parsed, 0)
                self.assertEqual(case['framing_supported'], observed['framing_supported'])
                self.assertEqual(case['outer_crc_matches'], observed['outer_crc16']['matches'])
                self.assertEqual(case['route_role'], observed['route_role'])
                self.assertEqual(case['rx_trailing_byte_hex'], observed['trailing_byte_after_crc_hex'])
                self.assertEqual(raw, decoded[1042:1042 + len(raw)])
                self.assertEqual(transport.sha256(raw), observed['wrapper']['sha256'])
                self.assertEqual(1042, observed['wrapper']['decoded_offset'])
                framed = framed_message(parsed)
                self.assertEqual(case['framing_supported'], framed is not None)
                if case['payload_hex'] is not None:
                    payload = bytes.fromhex(case['payload_hex'])
                    self.assertEqual(payload, framed[1])
                    self.assertEqual(transport.sha256(payload), observed['payload']['sha256'])
                    self.assertEqual(len(payload), observed['payload']['bytes'])
                    self.assertEqual(1054, observed['payload']['decoded_offset'])
                else:
                    self.assertIsNone(observed['payload'])
                self.assertFalse(observed['sequence_number_semantics_verified'])
                self.assertIsNone(observed['response_pairing'])

    def test_crc_reference_vector(self):
        self.assertEqual(0xbb3d, crc16(b'123456789', 0))

    def test_crc_failure_remains_in_replay_with_payload_hash(self):
        good = wrapped(b'synthetic payload')
        damaged = bytearray(good)
        damaged[12] ^= 1
        report = transport.replay_bytes(encode(record(good) + record(bytes(damaged))))
        self.assertEqual(2, report['supported_wrapper_count'])
        self.assertEqual([1], report['outer_crc_failed_record_ordinals'])
        self.assertFalse(report['complete_outer_crc_agreement'])
        self.assertNotEqual(report['envelopes'][0]['payload']['sha256'],
                            report['envelopes'][1]['payload']['sha256'])

    def test_unknown_route_retained_without_bus_classification(self):
        raw = wrapped(bytes.fromhex('6cf0107600'), route=b'\xff\xfe')
        replay = transport.replay_bytes(encode(record(raw)))
        self.assertTrue(replay['complete_outer_crc_agreement'])
        self.assertEqual([0], replay['unknown_route_record_ordinals'])
        self.assertEqual({'unknown': 1}, replay['role_counts'])
        self.assertEqual('fffe', replay['envelopes'][0]['route_bytes_hex'])

    def test_local_payload_header_is_never_promoted_to_vehicle_message(self):
        raw = wrapped(bytes.fromhex('6cf0107600'), route=b'\x15\x84')
        replay = transport.replay_bytes(encode(record(raw)))
        self.assertEqual({'adapter_local_candidate': 1}, replay['role_counts'])
        self.assertTrue(replay['envelopes'][0]['outer_crc16']['matches'])

    def test_text_and_unknown_wrapper_bytes_remain_accounted_for(self):
        looking = wrapped(b'payload')
        unknown = b'\x01\x55' + looking[2:]
        report = transport.replay_bytes(encode(record(looking, kind=0x54) + record(unknown)))
        self.assertEqual(2, report['record_count'])
        self.assertEqual(1, report['other_record_count'])
        self.assertEqual([1], report['unsupported_wrapper_record_ordinals'])
        self.assertEqual(0, report['outer_crc_checked_count'])
        self.assertEqual(transport.sha256(looking), report['other_records'][0]['payload']['sha256'])
        self.assertFalse(report['complete_outer_crc_agreement'])

    def test_length_ffff_is_framed_without_invented_hapi_capacity_claim(self):
        payload = bytes(65535)
        raw = wrapped(payload, channel=2, route=b'\x10\x00')
        replay = transport.replay_bytes(encode(record(raw, 2)))
        frame = replay['envelopes'][0]
        self.assertEqual(65535, frame['declared_payload_bytes'])
        self.assertEqual(65550, frame['wrapper']['bytes'])
        self.assertTrue(frame['outer_crc16']['matches'])
        self.assertEqual('bus_receive_candidate', frame['route_role'])

    def test_opaque_rx_metadata_and_trailer_never_create_pairing(self):
        first = wrapped(b'x', channel=2, metadata=bytes.fromhex('000001000000'))
        second = wrapped(b'x', channel=2, metadata=bytes(6), trailer=0x7f)
        report = transport.replay_bytes(encode(record(first, 2) + record(second, 2) + record(first, 2)))
        self.assertEqual(3, report['supported_wrapper_count'])
        self.assertEqual([0, 1, 2], [r['record_ordinal'] for r in report['envelopes']])
        self.assertEqual({'19': 2, '7f': 1}, report['metadata_observation']['rx_trailing_byte_values'])
        self.assertTrue(report['complete_outer_crc_agreement'])
        self.assertTrue(all(r['response_pairing'] is None for r in report['envelopes']))

    def test_container_and_record_truncation_fail_without_partial_success(self):
        source = encode(record(wrapped()))
        with self.assertRaises(ValueError):
            transport.replay_bytes(source[:-1])
        with self.assertRaises(ValueError):
            transport.replay_bytes(encode(record(wrapped())[:-1]))

    def test_report_pins_input_and_has_no_active_transport(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'saved.htx'
            source = encode(record(wrapped(b'private payload that should not be exported')))
            path.write_bytes(source)
            result = transport.report(path, transport.sha256(source).upper())
            self.assertEqual(str(path.resolve()), result['input']['path'])
            self.assertFalse(result['usb_wire_framing_verified'])
            self.assertFalse(result['active_transport_implemented'])
            self.assertFalse(result['live_write_enabled'])
            self.assertFalse(result['ready_to_flash'])
            self.assertEqual([], result['would_send'])
            self.assertNotIn(b'private payload that should not be exported'.hex(), json.dumps(result))
            for bad in ('0' * 64, 'not a digest'):
                with self.assertRaises(ValueError):
                    transport.report(path, bad)

    def test_source_change_rejected(self):
        original = encode(record(wrapped()))
        changed = encode(record(wrapped(b'changed')))
        with patch.object(transport, 'read_bounded', side_effect=[original, changed]):
            with self.assertRaisesRegex(ValueError, 'changed during replay'):
                transport.report(Path('unused.htx'), transport.sha256(original))

    def test_cli_preserves_output_and_reports_bad_crc_without_dropping_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path, output = Path(directory) / 'saved.htx', Path(directory) / 'report.json'
            bad = bytearray(wrapped())
            bad[-1] ^= 1
            source = encode(record(bytes(bad)))
            path.write_bytes(source)
            argv = ['--trace', str(path), '--expected-sha256', transport.sha256(source), '--output', str(output)]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(1, transport.main(argv))
            saved = output.read_bytes()
            self.assertEqual([0], json.loads(saved)['replay']['outer_crc_failed_record_ordinals'])
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                transport.main(argv)
            self.assertEqual(saved, output.read_bytes())
            self.assertEqual(source, path.read_bytes())


if __name__ == '__main__':
    unittest.main()
