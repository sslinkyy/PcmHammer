"""Small-record failure evidence must not waive preservation or enable packets."""
import json
import unittest
from pathlib import Path
from al5_segment import sha256
from test_offline import fixture
from write_plan import plan


class SmallRecordFailureTests(unittest.TestCase):
    def test_interruption_boundaries_and_unchecked_failure_status(self):
        root=Path(__file__).resolve().parents[2]
        report=json.loads((root/'Docs/AL5/SMALL_RECORD_FAILURE_EMULATION.json').read_text(encoding='utf8'))
        self.assertTrue(report['all_pass'])
        self.assertEqual(28,len(report['cases']))
        self.assertTrue(report['synthetic_payload_failure_can_leave_committed_erased_payload'])
        for case in report['cases']:
            observed=case['observed']
            self.assertTrue(case['pass'])
            self.assertTrue(observed['only_target_slot_changed'])
            if case['fail_at']==2:
                self.assertEqual('0xffaa',observed['slot_marker'])
                self.assertEqual(0,observed['reader_return_d0'])
                self.assertTrue(observed['reader_copied_erased_payload'])
                self.assertFalse(observed['reader_payload_matches_requested'])
                self.assertEqual('0x20',observed['attempts'][1]['synthetic_status'])
                self.assertFalse(observed['attempts'][1]['host_mutation_applied'])
            if case['interrupt_after_operations'] in (1,2):
                self.assertEqual('0xfffe',observed['slot_marker'])
                self.assertEqual(2,observed['reader_return_d0'])
                self.assertTrue(observed['reader_destination_unchanged'])

    def test_plan_hash_links_failure_evidence_and_stays_blocked(self):
        data=fixture()
        result=plan(data,data,sha256(data),'AL5',15184109)
        evidence=result['boot_preparation_assessment']['small_record_failure_evidence']
        path=Path(__file__).resolve().parents[2]/evidence['evidence']
        self.assertEqual(sha256(path.read_bytes()),evidence['evidence_sha256'])
        self.assertTrue(evidence['synthetic_payload_failure_can_leave_committed_erased_payload'])
        self.assertFalse(evidence['physical_recovery_verified'])
        self.assertFalse(result['ready_to_flash'])
        self.assertFalse(result['live_write_enabled'])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send','erase_packets','program_packets'):self.assertEqual([],result[key])


if __name__=='__main__':unittest.main()
