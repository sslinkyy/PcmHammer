"""Synthetic word-loop evidence must retain independent physical write gates."""
import json
from pathlib import Path
import unittest
from al5_segment import sha256
from emulate_loader_program import experiment
from emulate_loader_parser import EXPECTED_SHA
from test_offline import fixture
from write_plan import plan

ROOT = Path(__file__).resolve().parents[2]


class LoaderProgramTests(unittest.TestCase):
    def test_unknown_code_rejected(self):
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            experiment(b'unknown loader')

    def test_failure_propagation_and_counter_wrap(self):
        report = json.loads((ROOT / 'Docs/AL5/LOADER_PROGRAM_EMULATION.json').read_text())
        self.assertEqual(EXPECTED_SHA, report['payload_sha256'])
        self.assertEqual(sha256((ROOT / 'Tools/AL5/emulate_loader_program.py').read_bytes()), report['generator_sha256'])
        self.assertTrue(report['all_pass'])
        self.assertEqual(8, len(report['cases']))
        cases = {c['case']: c['observed'] for c in report['cases']}
        for c in report['cases']:
            observed, expected = c['observed'], c['expected']
            self.assertTrue(c['pass'])
            self.assertEqual(0, observed['flash_command_instructions_executed'])
            self.assertEqual(expected['stop'], observed['stop'])
            self.assertEqual(expected['word_count'], len(observed['modeled_words']))
            self.assertEqual(expected['statuses'], [r['status'] for r in observed['responses']])
            for response in observed['responses']:
                self.assertEqual(0x76, response['service'])
                self.assertEqual(0, response['subtype'])
        self.assertEqual(12290, cases['first_word_failure']['poll_reads'])
        self.assertEqual(12291, cases['second_word_failure']['poll_reads'])
        self.assertEqual([1, 65535], cases['odd_count']['loop_counts'])
        self.assertEqual(1, cases['odd_count']['checksum_source_words'])
        self.assertEqual([0, 65534, 65532], cases['zero_word_count_direct']['loop_counts'])
        self.assertEqual('0xffffc', cases['later_upper_bound']['modeled_words'][0]['address'])

    def test_plan_never_promotes_model_to_physical_verification(self):
        data = fixture()
        result = plan(data, data, sha256(data), 'AL5', 15184109)
        evidence = result['existing_trace_assessment']['loader_word_loop_assessment']
        self.assertEqual(sha256((ROOT / evidence['evidence']).read_bytes()), evidence['evidence_sha256'])
        self.assertTrue(evidence['offline_cases_pass'])
        self.assertFalse(evidence['physical_programming_verified'])
        self.assertFalse(evidence['wire_acknowledgments_verified'])
        self.assertFalse(result['ready_to_flash'])
        self.assertFalse(result['live_write_enabled'])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send', 'erase_packets', 'program_packets'):
            self.assertEqual([], result[key])


if __name__ == '__main__':
    unittest.main()
