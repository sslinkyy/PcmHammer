"""Captured execute-request traffic must never authorize live loader execution."""
import json
from pathlib import Path
import unittest
from al5_segment import sha256
from analyze_trace_transfers import transfer_contract
from test_offline import fixture
from write_plan import plan


def synthetic_message(address=0xFF9000,subtype=0x80):
    body=bytes([subtype])+b'\x00\x04'+address.to_bytes(3,'big')+b'ABCD'
    return bytes.fromhex('6d18f036')+body+(sum(body)&65535).to_bytes(2,'big')


class CapturedTransferTests(unittest.TestCase):
    def test_contract_reports_bad_length_checksum_and_bounds(self):
        msg=synthetic_message();valid=transfer_contract(msg)
        self.assertTrue(valid['byte_sum_matches']);self.assertTrue(valid['length_matches'])
        self.assertTrue(valid['within_offline_handler_bounds'])
        self.assertTrue(valid['requests_execution_in_offline_handler'])
        self.assertFalse(valid['payload_executed'])
        self.assertFalse(transfer_contract(msg[:-1]+bytes([msg[-1]^1]))['byte_sum_matches'])
        self.assertFalse(transfer_contract(msg[:5]+b'\x00\x05'+msg[7:])['length_matches'])
        for address in (0xFF9001,0xFFA7FE,0x8000):
            self.assertFalse(transfer_contract(synthetic_message(address))['within_offline_handler_bounds'])
        self.assertFalse(transfer_contract(synthetic_message(subtype=0))['requests_execution_in_offline_handler'])
        with self.assertRaises(ValueError):transfer_contract(b'short')

    def test_saved_write_payloads_match_contract_and_static_entry_hash(self):
        root=Path(__file__).resolve().parents[2]
        report=json.loads((root/'Docs/AL5/CAPTURED_RAM_TRANSFER.json').read_text(encoding='utf8'))
        static=json.loads((root/'Docs/AL5/CAPTURED_LOADER_ENTRY_STATIC.json').read_text(encoding='utf8'))
        self.assertEqual(17,report['trace_count']);self.assertEqual(16,report['transfer_count'])
        self.assertTrue(report['all_captured_contracts_match'])
        self.assertEqual(sha256((root/report['boot_contract_evidence']).read_bytes()),report['boot_contract_evidence_sha256'])
        writes=[t for case in report['traces'] if case['filename_mode']=='W' for t in case['transfers']]
        self.assertEqual(4,len(writes))
        for case in writes:
            self.assertEqual('0xff9000',case['address'])
            self.assertEqual(1590,case['declared_payload_bytes'])
            self.assertEqual('0x80',case['subtype'])
            self.assertEqual(static['payload_sha256'],case['payload_sha256'])
            self.assertEqual(2,case['prior_7444_response_candidates'])
            self.assertEqual(0,case['subsequent_76_response_candidates'])
        self.assertFalse(report['calibration_programming_verified'])

    def test_planner_links_contracts_but_has_no_executable_plan(self):
        data=fixture();result=plan(data,data,sha256(data),'AL5',15184109)
        evidence=result['existing_trace_assessment']['captured_ram_transfer']
        path=Path(__file__).resolve().parents[2]/evidence['evidence']
        self.assertEqual(sha256(path.read_bytes()),evidence['evidence_sha256'])
        self.assertTrue(evidence['all_captured_contracts_match'])
        self.assertFalse(evidence['loader_execution_verified'])
        self.assertFalse(result['ready_to_flash']);self.assertFalse(result['live_write_enabled'])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send','erase_packets','program_packets'):self.assertEqual([],result[key])


if __name__=='__main__':unittest.main()
