"""Sender observations must not become verified physical transport or recovery."""
import json
from pathlib import Path
import unittest
from al5_segment import sha256
from emulate_loader_sender import experiment
from emulate_loader_parser import EXPECTED_SHA
from test_offline import fixture
from write_plan import plan

ROOT = Path(__file__).resolve().parents[2]


class LoaderSenderTests(unittest.TestCase):
    def test_unknown_loader_rejected(self):
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            experiment(b'unknown loader')

    def test_saved_header_timeout_exit_and_length_observations(self):
        report = json.loads((ROOT / 'Docs/AL5/LOADER_SENDER_EMULATION.json').read_text())
        self.assertEqual(EXPECTED_SHA, report['payload_sha256'])
        self.assertEqual(sha256((ROOT / 'Tools/AL5/emulate_loader_sender.py').read_bytes()), report['generator_sha256'])
        self.assertEqual(10, len(report['cases']))
        self.assertTrue(report['all_pass'])
        cases = {c['case']: c['observed'] for c in report['cases']}
        for case in report['cases']:
            self.assertTrue(case['pass'])
            self.assertFalse(case['observed']['reset_instruction_executed'])
            self.assertEqual(0, case['observed']['mmio_instructions_executed'])
            for key, expected in case['expected'].items():
                self.assertEqual(expected, case['observed'][key])
        self.assertEqual({'priority': 0x6D, 'destination': 0xF0, 'source': 0x18}, cases['status_ready']['fifo_groups'][0]['header'])
        self.assertEqual({'priority': 0x6C, 'destination': 0xF1, 'source': 0x18}, cases['priority_6c_source_f1']['fifo_groups'][0]['header'])
        self.assertEqual(11, cases['delayed_ready']['ready_reads'])
        self.assertEqual(4096, cases['always_busy']['watchdog_calls_trapped'])
        self.assertEqual([4, 4], [g['bytes'] for g in cases['cleanup_broadcasts']['fifo_groups']])
        for label, status in (('status_ready', 0x73), ('finalize_success_tail', 0x86), ('finalize_failure_tail', 0xFF)):
            group = cases[label]['fifo_groups'][0]
            self.assertEqual(6, group['bytes'])
            self.assertEqual(12, group['final_control'])
            self.assertEqual({'service': 0x76, 'subtype': 0, 'status': status}, group['status_body'])
        self.assertEqual('0xffff8000', report['reset_mmio_address'])
        self.assertFalse(report['physical_reset_verified'])

    def test_plan_cannot_promote_sender_to_recovery_or_transport(self):
        data = fixture()
        result = plan(data, data, sha256(data), 'AL5', 15184109)
        evidence = result['existing_trace_assessment']['loader_sender_assessment']
        self.assertEqual(sha256((ROOT / evidence['evidence']).read_bytes()), evidence['evidence_sha256'])
        self.assertTrue(evidence['offline_cases_pass'])
        for key in ('physical_transport_verified', 'physical_reset_verified', 'recovery_verified'):
            self.assertFalse(evidence[key])
        self.assertFalse(result['ready_to_flash'])
        self.assertFalse(result['live_write_enabled'])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send', 'erase_packets', 'program_packets'):
            self.assertEqual([], result[key])


if __name__ == '__main__':
    unittest.main()
