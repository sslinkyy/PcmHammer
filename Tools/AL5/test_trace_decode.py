"""Saved-container decoding must be bounded and must not enable live programming."""
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib
from al5_segment import sha256
from decode_trace_containers import decode, records, report, SIGNATURE, vehicle_message
from test_offline import fixture
from write_plan import plan


def encode(decoded):
    return bytes(((((b^0xA5)>>3)|((b^0xA5)<<5))+0x87)&255 for b in zlib.compress(decoded))


def record(payload,channel=1,kind=0x42):
    return struct.pack('<dBHHBI',46282.5,channel,7,2,kind,len(payload))+payload


class TraceDecodeTests(unittest.TestCase):
    def test_roundtrip_and_observed_tx_rx_wrapper_lengths(self):
        header=SIGNATURE+b'\x00'*(1024-len(SIGNATURE))
        message=bytes.fromhex('6c18f02701')
        tx=b'\x01\x54'+b'\x00'*8+struct.pack('<H',len(message))+message+b'\x00'*2
        rx_message=bytes.fromhex('6cf0186701')
        rx=b'\x01\x52'+b'\x00'*8+struct.pack('<H',len(rx_message))+rx_message+b'\x00'*3
        raw=header+record(tx)+record(rx,channel=2)
        self.assertEqual(raw,decode(encode(raw)))
        parsed=list(records(raw))
        self.assertEqual(('host_tx_candidate',message),vehicle_message(parsed[0]))
        self.assertEqual(('device_rx_candidate',rx_message),vehicle_message(parsed[1]))
        self.assertIsNone(vehicle_message({**parsed[0],'payload':tx[:-1]}))
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'20261001_000000_AL5_W.htx';path.write_bytes(encode(raw))
            result=report([path]);case=result['traces'][0]
            self.assertEqual(2,case['record_count'])
            self.assertEqual(sha256(raw),case['decoded_sha256'])
            self.assertEqual(2,case['observed_al5_message_count'])
            self.assertTrue(result['saved_container_format_decoded'])
            self.assertFalse(result['programming_transport_verified'])
            self.assertNotIn(message.hex(),json.dumps(result))

    def test_corrupt_trailing_oversized_and_truncated_inputs_rejected(self):
        raw=SIGNATURE+b'\x00'*(1024-len(SIGNATURE))+record(b'hello',kind=0x54)
        encoded=encode(raw)
        for invalid in (b'junk',encoded[:-3],encoded+b'junk',encode(b'unsupported')):
            with self.assertRaises(ValueError):decode(invalid)
        with patch('decode_trace_containers.MAX_DECODED',64):
            with self.assertRaises(ValueError):decode(encoded)
        with self.assertRaises(ValueError):list(records(raw[:-1]))
        with self.assertRaises(ValueError):list(records(raw+b'\x00'))
        invalid=bytearray(raw);struct.pack_into('<d',invalid,1024,float('nan'))
        with self.assertRaises(ValueError):list(records(invalid))

    def test_saved_evidence_hash_and_all_write_gates(self):
        data=fixture();result=plan(data,data,sha256(data),'AL5',15184109)
        assessment=result['existing_trace_assessment']['saved_container_decode']
        root=Path(__file__).resolve().parents[2]
        path=root/assessment['evidence']
        self.assertEqual(sha256(path.read_bytes()),assessment['evidence_sha256'])
        evidence=json.loads(path.read_text(encoding='utf8'))
        self.assertEqual(sha256((root/evidence['static_evidence']).read_bytes()),evidence['static_evidence_sha256'])
        self.assertEqual(17,evidence['trace_count'])
        self.assertTrue(all(t['records_consume_decoded_file'] for t in evidence['traces']))
        original=json.loads((root/'Docs/AL5/EFILIVE_TRACE_INVENTORY.json').read_text(encoding='utf8'))
        by_name={t['source_name']:t for t in evidence['traces']}
        self.assertEqual(224,by_name['20260917_151435_AL5_W.htx']['record_count'])
        self.assertEqual(32,by_name['20260917_151435_AL5_W.htx']['observed_al5_message_count'])
        self.assertEqual(12,by_name['20260917_152044_AL5_W.htx']['observed_al5_message_count'])
        self.assertTrue(all(t['observed_al5_message_count']>0 for t in evidence['traces']))
        for trace in original['traces']:self.assertEqual(trace['source_sha256'],by_name[trace['source_name']]['source_sha256'])
        self.assertTrue(assessment['saved_container_format_decoded'])
        self.assertFalse(assessment['erase_program_protocol_verified'])
        self.assertFalse(result['ready_to_flash']);self.assertFalse(result['live_write_enabled'])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send','erase_packets','program_packets'):self.assertEqual([],result[key])


if __name__=='__main__':unittest.main()
