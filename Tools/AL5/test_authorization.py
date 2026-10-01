"""Reject malformed staged records and keep offline authorization non-executable."""
import unittest
from pathlib import Path
from emulate_application_authorization import result_payload
from test_offline import fixture
from write_plan import plan
from al5_segment import sha256


class AuthorizationTests(unittest.TestCase):
    def test_declared_record_length_excludes_stale_seed_tail(self):
        self.assertEqual('0236', result_payload(bytes.fromhex('020236e5')))
        self.assertEqual('019ce5', result_payload(bytes.fromhex('03019ce5')))
        for raw in ('00000000', '04010000', '0202', '020236e500'):
            with self.assertRaises(ValueError): result_payload(bytes.fromhex(raw))

    def test_guard_unlock_evidence_cannot_enable_key_or_write_packets(self):
        data = fixture()
        report = plan(data, data, sha256(data), 'AL5', 15184109)
        evidence = report['boot_loader_assessment']['application_authorization_evidence']
        self.assertTrue(evidence['offline_cases_pass'])
        root = Path(__file__).resolve().parents[2]
        self.assertEqual(sha256((root/evidence['evidence']).read_bytes()), evidence['evidence_sha256'])
        self.assertFalse(evidence['live_key_submission_verified'])
        self.assertFalse(evidence['lockout_duration_verified'])
        self.assertFalse(report['boot_loader_assessment']['live_session_authorized'])
        self.assertFalse(report['ready_to_flash'])
        for key in ('would_send', 'erase_packets', 'program_packets'):
            self.assertEqual([], report[key])


if __name__ == '__main__': unittest.main()
