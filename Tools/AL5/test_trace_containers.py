"""An opaque trace or filename must never be treated as programming proof."""
import json
from pathlib import Path
import tempfile
import unittest
import zlib
from al5_segment import sha256
from inspect_trace_containers import inspect, inventory, probe_zlib
from test_offline import fixture
from write_plan import plan


class TraceContainerTests(unittest.TestCase):
    def test_bounded_probe_recovers_synthetic_stream_hash_without_payload(self):
        payload=b'synthetic trace format test only\n'*20
        raw=b'HEAD'+zlib.compress(payload)
        key,rotation=0x27,3
        encoded=bytes((((b^key)<<rotation)|((b^key)>>(8-rotation)))&255 for b in raw)
        matches=probe_zlib(encoded)['complete_streams']
        self.assertIn({'rotation_right_bits':rotation,'xor_byte':key,'offset':4,
                       'decoded_bytes':len(payload),'decoded_sha256':sha256(payload)},matches)
        self.assertNotIn('synthetic trace format',json.dumps(matches))
        self.assertEqual([],probe_zlib(zlib.compress(b'A'*10000),output_limit=64)['complete_streams'])

    def test_filename_and_compression_match_do_not_establish_flash_outcome(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'20261001_000000_AL5_W.htx'
            data=zlib.compress(b'Synthetic complete container, not a flash.')
            path.write_bytes(data)
            report=inventory([path],probe=True)
            record=report['traces'][0]
            self.assertEqual(sha256(data),record['source_sha256'])
            self.assertEqual('W',record['filename_context']['mode'])
            self.assertTrue(record['bounded_zlib_probe']['complete_streams'])
            self.assertFalse(record['container_decoded'])
            self.assertIsNone(record['operation_outcome'])
            self.assertFalse(report['programming_transport_verified'])
            path.rename(Path(folder)/'20261001_000000_F_AL5.htx')
            self.assertEqual('F',inspect(Path(folder)/'20261001_000000_F_AL5.htx')['filename_context']['mode'])
            with self.assertRaises(ValueError):inspect(Path(folder)/'not-a-trace.txt')

    def test_inventory_hash_link_and_planner_gates(self):
        data=fixture()
        result=plan(data,data,sha256(data),'AL5',15184109)
        evidence=result['existing_trace_assessment']
        path=Path(__file__).resolve().parents[2]/evidence['evidence']
        self.assertEqual(sha256(path.read_bytes()),evidence['evidence_sha256'])
        report=json.loads(path.read_text(encoding='utf8'))
        self.assertEqual(6,report['trace_count'])
        self.assertEqual(5,sum(t['filename_context']['mode']=='W' for t in report['traces']))
        for trace in report['traces']:
            self.assertEqual([],trace['bounded_zlib_probe']['complete_streams'])
            self.assertIsNone(trace['operation_outcome'])
        self.assertTrue(evidence['format_decoding_verified'])
        self.assertFalse(evidence['programming_transport_verified'])
        self.assertFalse(result['ready_to_flash'])
        self.assertFalse(result['live_write_enabled'])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send','erase_packets','program_packets'):self.assertEqual([],result[key])


if __name__=='__main__':unittest.main()
