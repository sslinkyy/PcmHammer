"""Bounded parser observations cannot establish physical write validation."""
import json
from pathlib import Path
import unittest
from al5_segment import sha256
from emulate_loader_parser import experiment, EXPECTED_SHA
from test_offline import fixture
from write_plan import plan

ROOT = Path(__file__).resolve().parents[2]


class LoaderParserTests(unittest.TestCase):
    def test_unknown_loader_rejected_before_emulator_import(self):
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            experiment(b'not the saved loader')

    def test_saved_fault_observations_and_generator_provenance(self):
        report = json.loads((ROOT / 'Docs/AL5/LOADER_PARSER_EMULATION.json').read_text())
        self.assertEqual(EXPECTED_SHA, report['payload_sha256'])
        self.assertEqual(sha256((ROOT / 'Tools/AL5/emulate_loader_parser.py').read_bytes()), report['generator_sha256'])
        self.assertEqual(14, len(report['cases']))
        self.assertTrue(report['all_pass'])
        cases = {c['case']: c['observed'] for c in report['cases']}
        for c in report['cases']:
            self.assertTrue(c['pass'])
            self.assertEqual(0, c['observed']['flash_commands_executed'])
            for key, value in c['expected'].items():
                self.assertEqual(value, c['observed'][key])
        self.assertTrue(cases['zero_count']['frame_overread_attempted'])
        self.assertTrue(cases['short_payload']['frame_overread_attempted'])
        self.assertTrue(cases['odd_count_one']['program_source_overlaps_checksum'])
        for case in ('odd_destination', 'below_calibration', 'zero_destination', 'below_upper_bound'):
            self.assertEqual('flash_command_trap', cases[case]['stop'])
        self.assertEqual(128, cases['upper_bound']['program_error_bits'])
        self.assertEqual([0x77], cases['bad_sum']['status_arguments'])
        self.assertEqual([0x73], cases['delay_subtype']['status_arguments'])

    def test_plan_links_parser_without_enabling_packets(self):
        data = fixture()
        result = plan(data, data, sha256(data), 'AL5', 15184109)
        evidence = result['existing_trace_assessment']['loader_parser_assessment']
        self.assertEqual(sha256((ROOT / evidence['evidence']).read_bytes()), evidence['evidence_sha256'])
        self.assertTrue(evidence['offline_cases_pass'])
        self.assertFalse(evidence['physical_programming_verified'])
        self.assertFalse(result['ready_to_flash'])
        self.assertFalse(result['live_write_enabled'])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send', 'erase_packets', 'program_packets'):
            self.assertEqual([], result[key])


if __name__ == '__main__':
    unittest.main()
