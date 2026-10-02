"""Short-frame routes must remain synthetic evidence only."""
import json
from pathlib import Path
import unittest
from al5_segment import sha256
from emulate_loader_stale import run
from emulate_loader_receive import experiment
from test_offline import fixture
from write_plan import plan

ROOT = Path(__file__).resolve().parents[2]


class LoaderStaleTests(unittest.TestCase):
    def test_unknown_loader_rejected(self):
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            experiment(b'unknown loader', [])

    def test_saved_routes_and_conditional_address_arithmetic(self):
        report = json.loads((ROOT / 'Docs/AL5/LOADER_STALE_BUFFER_EMULATION.json').read_text())
        self.assertEqual(sha256((ROOT / 'Tools/AL5/emulate_loader_stale.py').read_bytes()), report['generator_sha256'])
        self.assertEqual(sha256((ROOT / 'Tools/AL5/emulate_loader_receive.py').read_bytes()), report['receive_generator_sha256'])
        self.assertEqual(sha256((ROOT / 'Docs/AL5/CAPTURED_LOADER_STATIC.json').read_bytes()), report['static_evidence_sha256'])
        self.assertEqual(8, len(report['cases']))
        self.assertTrue(report['all_pass'])
        cases = {c['case']: c['observed'] for c in report['cases']}
        for case in report['cases']:
            self.assertTrue(case['pass'])
            self.assertFalse(case['observed']['reset_instruction_executed'])
            self.assertEqual(0, case['observed']['mmio_instructions_executed'])
            self.assertEqual(case['expected_stop'], case['observed']['stop'])
        self.assertEqual('receive_boundary', cases['short_clean_buffer']['stop'])
        for label in ('two_bytes_stale_erase', 'three_bytes_stale_erase',
                      'four_bytes_stale_erase', 'rejected_frame_leaves_erase_tail'):
            self.assertEqual('erase_route_trap', cases[label]['stop'])
        self.assertEqual('finalize_route_trap', cases['two_bytes_stale_finalize']['stop'])
        self.assertEqual('block_parser_trap', cases['two_bytes_stale_block']['stop'])
        self.assertEqual('shared_exit_trap', cases['two_bytes_stale_exit']['stop'])
        self.assertEqual([0x40, 0], cases['rejected_frame_leaves_erase_tail']['completion_flags'])
        addresses = report['address_observations']
        self.assertEqual(3422, addresses['distance_to_initial_stack_if_low24_aliases'])
        self.assertFalse(addresses['physical_aliasing_verified'])
        self.assertFalse(addresses['physical_receive_capacity_verified'])

    def test_plan_does_not_promote_stale_routes_to_physical_claims(self):
        data = fixture()
        result = plan(data, data, sha256(data), 'AL5', 15184109)
        evidence = result['existing_trace_assessment']['loader_stale_buffer_assessment']
        self.assertEqual(sha256((ROOT / evidence['evidence']).read_bytes()), evidence['evidence_sha256'])
        self.assertTrue(evidence['offline_cases_pass'])
        for key in ('physical_short_frame_acceptance_verified', 'physical_receive_capacity_verified',
                    'physical_address_aliasing_verified'):
            self.assertFalse(evidence[key])
        self.assertFalse(result['ready_to_flash'])
        self.assertFalse(result['live_write_enabled'])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send', 'erase_packets', 'program_packets'):
            self.assertEqual([], result[key])


if __name__ == '__main__':
    unittest.main()
