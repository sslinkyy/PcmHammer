"""Unframed signatures and complete file decoding must not establish a flash exchange."""
import json
from pathlib import Path
import tempfile
import unittest
from al5_segment import sha256
from audit_trace_wrappers import analyze
from test_trace_decode import encode, record, SIGNATURE
from test_offline import fixture
from write_plan import plan

ROOT = Path(__file__).resolve().parents[2]


def analyze_records(raw_records):
    header = SIGNATURE + b'\x00' * (1024 - len(SIGNATURE))
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / '20261001_000000_AL5_W.htx'
        path.write_bytes(encode(header + raw_records))
        return analyze(path)


class TraceWrapperAuditTests(unittest.TestCase):
    def test_unsupported_embedded_signature_is_not_framed_request(self):
        result = analyze_records(record(b'unknown-wrapper' + bytes.fromhex('6dfef136ee')))
        self.assertEqual(1, result['unsupported_wrapper_records'])
        self.assertEqual({}, result['framed_destructive_request_counts'])
        self.assertEqual(1, result['unsupported_record_signature_hits']['6dfef136:0xee'])
        self.assertFalse(result['complete_programming_exchange_verified'])

    def test_global_f1_and_response_variants_are_counted(self):
        message = bytes.fromhex('6dfef136ee')
        tx = b'\x01\x54' + b'\x00' * 8 + len(message).to_bytes(2, 'little') + message + b'\x00' * 2
        response = bytes.fromhex('6df118760073')
        rx = b'\x01\x52' + b'\x00' * 8 + len(response).to_bytes(2, 'little') + response + b'\x00' * 3
        result = analyze_records(record(tx) + record(rx, channel=2))
        self.assertEqual(2, result['supported_wrapper_records'])
        self.assertEqual({'0xee': 1}, result['framed_destructive_request_counts'])
        self.assertEqual({'0x73': 1}, result['framed_mode76_status_counts'])
        self.assertFalse(result['complete_programming_exchange_verified'])

    def test_saved_all_binary_records_supported_but_no_complete_exchange(self):
        report = json.loads((ROOT / 'Docs/AL5/TRACE_WRAPPER_AUDIT.json').read_text())
        self.assertEqual(sha256((ROOT / 'Tools/AL5/audit_trace_wrappers.py').read_bytes()), report['generator_sha256'])
        self.assertEqual(5, report['trace_count'])
        self.assertEqual(709, sum(t['binary_records'] for t in report['traces']))
        previous = json.loads((ROOT / 'Docs/AL5/CAPTURED_LOADER_REQUESTS.json').read_text())
        hashes = {t['source_name']: t['source_sha256'] for t in previous['traces']}
        for trace in report['traces']:
            self.assertEqual(hashes[trace['source_name']], trace['source_sha256'])
            self.assertEqual(trace['binary_records'], trace['supported_wrapper_records'])
            self.assertEqual(0, trace['unsupported_wrapper_records'])
            self.assertEqual({}, trace['framed_destructive_request_counts'])
            self.assertEqual({}, trace['framed_mode76_status_counts'])
            self.assertIsNone(trace['operation_outcome'])

    def test_planner_links_audit_with_physical_gates_closed(self):
        data = fixture()
        result = plan(data, data, sha256(data), 'AL5', 15184109)
        evidence = result['existing_trace_assessment']['complete_trace_wrapper_audit']
        self.assertEqual(sha256((ROOT / evidence['evidence']).read_bytes()), evidence['evidence_sha256'])
        self.assertEqual(709, evidence['binary_records'])
        self.assertFalse(evidence['complete_programming_exchange_verified'])
        self.assertFalse(evidence['physical_transport_verified'])
        self.assertFalse(result['ready_to_flash'])
        self.assertEqual([], result['would_send'])


if __name__ == '__main__':
    unittest.main()
