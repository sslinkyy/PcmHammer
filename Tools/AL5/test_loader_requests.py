"""Static destructive routes and missing captured commands must not open write gates."""
import json
from pathlib import Path
import tempfile
import unittest
from al5_segment import sha256
from inspect_loader_requests import analyze
from test_trace_decode import encode, record, SIGNATURE
from test_offline import fixture
from write_plan import plan


class LoaderRequestTests(unittest.TestCase):
    def test_global_and_module_destructive_commands_are_detected(self):
        raw=SIGNATURE+b'\x00'*(1024-len(SIGNATURE))
        for subtype in (0xEE,0,0xFF):
            message=bytes([0x6D,0xFE,0xF0,0x36,subtype])
            wrapper=b'\x01\x54'+b'\x00'*8+len(message).to_bytes(2,'little')+message+b'\x00'*2
            raw+=record(wrapper)
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'20261001_000000_AL5_W.htx';path.write_bytes(encode(raw))
            result=analyze(path)
            self.assertTrue(result['loader_erase_subtype_observed'])
            self.assertTrue(result['loader_word_program_subtype_observed'])
            self.assertTrue(result['loader_finalize_subtype_observed'])
            self.assertFalse(result['capture_complete_verified'])
            self.assertIsNone(result['operation_outcome'])

    def test_saved_census_and_static_erase_id_finalize_observations(self):
        root=Path(__file__).resolve().parents[2]
        census=json.loads((root/'Docs/AL5/CAPTURED_LOADER_REQUESTS.json').read_text(encoding='utf8'))
        source=root/census['static_evidence']
        self.assertEqual(sha256(source.read_bytes()),census['static_evidence_sha256'])
        instructions={i['address']:i for w in json.loads(source.read_text())['windows'] for i in w['instructions']}
        self.assertIn('#$8000',instructions['0xff9368']['operands'])
        self.assertIn('#$10000',instructions['0xff9370']['operands'])
        self.assertIn('#$2258',instructions['0xff9494']['operands'])
        self.assertIn('#$1fffe',instructions['0xff920c']['operands'])
        self.assertIn('#$4afc',instructions['0xff921c']['operands'])
        self.assertEqual(5,census['trace_count'])
        self.assertFalse(census['destructive_requests_observed'])
        self.assertEqual(4,sum(c['mode36_subtype_counts'].get('0x80',0) for c in census['traces']))
        self.assertTrue(all(not c['capture_complete_verified'] for c in census['traces']))

    def test_plan_links_census_without_claiming_programming_or_geometry(self):
        data=fixture();result=plan(data,data,sha256(data),'AL5',15184109)
        evidence=result['existing_trace_assessment']['captured_loader_request_census']
        path=Path(__file__).resolve().parents[2]/evidence['evidence']
        self.assertEqual(sha256(path.read_bytes()),evidence['evidence_sha256'])
        self.assertFalse(evidence['physical_erase_geometry_verified'])
        self.assertFalse(evidence['calibration_programming_verified'])
        self.assertFalse(result['ready_to_flash']);self.assertFalse(result['live_write_enabled'])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send','erase_packets','program_packets'):self.assertEqual([],result[key])


if __name__=='__main__':unittest.main()
