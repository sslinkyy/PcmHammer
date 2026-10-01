"""Initialization metadata writes must remain visible and never enable flashing."""
import json
import unittest
from pathlib import Path
from al5_segment import sha256
from test_offline import fixture
from write_plan import plan


class ContextPreambleTests(unittest.TestCase):
    def test_cold_and_warm_metadata_writes_do_not_establish_recovery(self):
        data=fixture()
        result=plan(data,data,sha256(data),'AL5',15184109)
        evidence=result['boot_preparation_assessment']['context_preamble_evidence']
        path=Path(__file__).resolve().parents[2]/evidence['evidence']
        self.assertEqual(sha256(path.read_bytes()),evidence['evidence_sha256'])
        report=json.loads(path.read_text(encoding='utf8'))
        self.assertTrue(report['all_pass'])
        for case in report['cases']:
            self.assertEqual([],case['cold_context']['preamble_helpers_bypassed'])
            self.assertEqual(9,len(case['metadata']['modeled_program_operations']))
            self.assertTrue(case['metadata']['only_expected_small_records_changed'])
            self.assertEqual([0,1,3,2],[c['index'] for c in case['metadata']['read_calls']])
            self.assertTrue(case['metadata']['new_bank_slots_erased_after_separate_main_update'])
            self.assertEqual(16,len(case['warm_reentry']['modeled_storage_operations']))
            self.assertEqual(0,case['warm_reentry']['additional_default_helpers'])
            self.assertTrue(case['warm_reentry']['metadata_slots_rewritten_in_bank2'])
        self.assertTrue(evidence['context_initializer_has_persistent_writes'])
        self.assertFalse(evidence['complete_startup_verified'])
        self.assertFalse(evidence['physical_recovery_verified'])
        self.assertFalse(result['ready_to_flash'])
        self.assertFalse(result['live_write_enabled'])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send','erase_packets','program_packets'):
            self.assertEqual([],result[key])

    def test_read_record_states_copy_only_committed_payloads(self):
        root=Path(__file__).resolve().parents[2]
        report=json.loads((root/'Docs/AL5/CONTEXT_PREAMBLE_EMULATION.json').read_text(encoding='utf8'))
        self.assertEqual(12,len(report['record_reader_cases']))
        for case in report['record_reader_cases']:
            committed=case['synthetic_record_marker']=='0xffaa'
            self.assertEqual(committed,case['observed']['copied_payload_matches'])
            self.assertEqual(not committed,case['observed']['destination_unchanged'])
            self.assertTrue(case['observed']['bank_unchanged'])


if __name__=='__main__':unittest.main()
