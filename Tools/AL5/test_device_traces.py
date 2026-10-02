"""Undecoded device files and raw signatures never count as programming evidence."""
import json
from pathlib import Path
import tempfile
import unittest
from al5_segment import sha256
from inspect_device_traces import inspect, report, MAX_INPUT
from test_offline import fixture
from write_plan import plan

ROOT = Path(__file__).resolve().parents[2]


class DeviceTraceTests(unittest.TestCase):
    def test_literal_program_signatures_are_diagnostic_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'USR_0001.efx'
            path.write_bytes(b'V03VPW' + bytes(24) + bytes.fromhex('6d18f036ee'))
            result = report([path], user_reports_encryption=True)
            self.assertTrue(result['encryption_context']['user_reports_efilive_encryption'])
            self.assertFalse(result['encryption_context']['algorithm_independently_verified'])
            trace = result['traces'][0]
            self.assertEqual(1, trace['unframed_header_signature_hits']['6d18f0'])
            self.assertFalse(trace['signature_hits_are_packet_evidence'])
            self.assertFalse(trace['device_record_framing_verified'])
            self.assertFalse(trace['controller_identity_verified'])
            self.assertIsNone(trace['operation_outcome'])
            self.assertFalse(result['complete_programming_exchange_verified'])
            self.assertFalse(result['live_write_enabled'])
            self.assertIsNone(result['erase_scope'])
            self.assertEqual([], result['would_send'])

    def test_unsupported_or_oversized_inputs_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'USR_0001.efx'
            path.write_bytes(b'V03CAN' + bytes(24))
            with self.assertRaisesRegex(ValueError, 'unsupported'):
                inspect(path)
            path.write_bytes(b'V03VPW')
            with self.assertRaisesRegex(ValueError, 'size'):
                inspect(path)
            with path.open('wb') as stream:
                stream.truncate(MAX_INPUT + 1)
            with self.assertRaisesRegex(ValueError, 'size'):
                inspect(path)
            with self.assertRaisesRegex(ValueError, 'USR_nnnn'):
                inspect(Path(directory) / 'unrelated.bin')

    def test_supplied_inventory_is_distinct_and_unresolved(self):
        saved = json.loads((ROOT / 'Docs/AL5/AUTOCAL_DEVICE_TRACE_INVENTORY.json').read_bytes())
        self.assertEqual(sha256((ROOT / 'Tools/AL5/inspect_device_traces.py').read_bytes()), saved['generator_sha256'])
        self.assertEqual(2, saved['unique_file_hashes'])
        for trace in saved['traces']:
            self.assertEqual(44571, trace['bytes'])
            self.assertFalse(trace['htx_decoder_accepts'])
            self.assertEqual([], trace['bounded_rotation_xor_zlib_probe']['complete_streams'])
            self.assertEqual([], trace['bounded_existing_htx_transform_offset_probe']['complete_streams'])
        data = fixture()
        result = plan(data, data, sha256(data), 'AL5', 15184109)
        evidence = result['existing_trace_assessment']['autocal_device_trace_assessment']
        self.assertEqual(sha256((ROOT / evidence['evidence']).read_bytes()), evidence['evidence_sha256'])
        self.assertFalse(evidence['format_decoding_verified'])
        self.assertFalse(evidence['complete_programming_exchange_verified'])
        self.assertFalse(result['ready_to_flash'])
        self.assertFalse(result['live_write_enabled'])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send', 'erase_packets', 'program_packets'):
            self.assertEqual([], result[key])


if __name__ == '__main__':
    unittest.main()
