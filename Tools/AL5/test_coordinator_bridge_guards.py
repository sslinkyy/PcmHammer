"""Public stdio boundary tests; no native instructions or device dependencies."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid

import test_native_coordinator_bridge as runner
from al5_segment import sha256
from emulate_al5_program_session import fixture


class NativeRunnerInputGuards(unittest.TestCase):
    def test_existing_report_preserved_before_any_native_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'report.json'
            path.write_bytes(b'keep')
            with patch.object(runner, 'case') as case, patch('sys.stderr'):
                with self.assertRaises(SystemExit):
                    runner.main(['--low', 'absent', '--loader', 'absent', '--bridge', 'absent', '--output', str(path)])
                case.assert_not_called()
            self.assertEqual(b'keep', path.read_bytes())

    def test_native_input_length_is_bounded_before_allocation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'input.bin'
            path.write_bytes(bytes(129))
            with self.assertRaises(ValueError):
                runner.exact_file(path, 128)
            path.write_bytes(bytes(128))
            self.assertEqual(bytes(128), runner.exact_file(path, 128))


@unittest.skipUnless(os.environ.get('AL5_COORDINATOR_BRIDGE') and shutil.which('dotnet'), 'requires built BCL-only bridge')
class BridgeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.attempt = uuid.uuid4().hex
        self.candidate = fixture()
        self.backup = bytes(0x1FFFE-runner.END)

    def init(self):
        return dict(action='init', attempt=self.attempt, candidate=self.candidate.hex(),
            candidate_sha256=sha256(self.candidate), backup=self.backup.hex(), backup_sha256=sha256(self.backup))

    def command(self, action, sequence=1, **fields):
        return dict(action=action, attempt=self.attempt, sequence=sequence, **fields)

    def run_bridge(self, lines):
        result = subprocess.run(['dotnet', os.environ['AL5_COORDINATOR_BRIDGE'], '--offline-coordinator-bridge'],
            input=''.join((line if isinstance(line, str) else json.dumps(line))+'\n' for line in lines),
            text=True, encoding='utf-8', capture_output=True, timeout=15)
        return result, [json.loads(line) for line in result.stdout.splitlines()]

    def test_malformed_json_and_bad_init_pin_do_not_create_attempt(self):
        bad = self.init(); bad['candidate_sha256'] = '0'*64
        result, responses = self.run_bridge(['{', bad, self.init()])
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIsNone(responses[1]['state'])
        self.assertIsNone(responses[2]['state'])
        self.assertTrue(responses[2]['error'])
        self.assertEqual('AwaitingModelOutcome', responses[3]['state'])
        self.assertEqual(0, responses[3]['observations'])

    def test_foreign_and_stale_requests_leave_cursor_and_attempt_unchanged(self):
        foreign = self.command('outcome', outcome='ModelCompleted'); foreign['attempt'] = uuid.uuid4().hex
        result, responses = self.run_bridge([self.init(), foreign,
            self.command('outcome', sequence=2, outcome='ModelCompleted'), self.init()])
        self.assertEqual(0, result.returncode, result.stderr)
        for response in responses[2:]:
            self.assertTrue(response['error'])
            self.assertEqual(self.attempt, response['attempt'])
            self.assertEqual(1, response['pending']['sequence'])
            self.assertEqual(0, response['observations'])

    def test_loader_facts_required_and_stopped_reconciliation_cannot_resume(self):
        result, responses = self.run_bridge([self.init(), self.command('outcome', outcome='ModelCompleted'),
            self.command('outcome', sequence=2, outcome='ModelCompleted'),
            self.command('loader', sequence=2, body='7600ee', sender='Unknown', stack_delta=0, program_start=None, program_bytes=None),
            self.command('loader', sequence=2, body='760073', sender='Returned', stack_delta=0, program_start=None, program_bytes=None),
            self.command('reconcile', sequence=2, snapshot=(b'\xff'*98304).hex(), snapshot_sha256=sha256(b'\xff'*98304)),
            self.command('outcome', sequence=2, outcome='Cancelled')])
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(responses[3]['error'])
        self.assertTrue(responses[4]['error'])
        self.assertEqual('UnexpectedReply', responses[5]['detail']['reason'])
        self.assertEqual('SavedRangeMatches', responses[6]['detail']['disposition'])
        self.assertFalse(responses[6]['detail']['can_resume'])
        self.assertEqual('Stopped', responses[7]['state'])
        self.assertTrue(responses[7]['error'])
        self.assertEqual(2, responses[7]['observations'])
        for response in responses[1:]:
            self.assertFalse(response['live_writes_enabled'])
            self.assertFalse(response['automatic_retry_enabled'])
            self.assertFalse(response['physical_recovery_verified'])

    def test_oversized_line_fails_closed_without_initializing(self):
        result, responses = self.run_bridge([' '*((256*1024)+1)])
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(1, len(responses))
        self.assertIn('resource budget', result.stderr)

    def test_missing_baseline_does_not_initialize_an_attempt(self):
        missing = self.init(); missing['backup'] = ''; missing['backup_sha256'] = sha256(b'')
        result, responses = self.run_bridge([missing, self.init()])
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(responses[1]['error'])
        self.assertIsNone(responses[1]['state'])
        self.assertEqual(0, responses[2]['observations'])

    def test_explicit_reconstruction_changes_active_identity_without_resuming_source(self):
        snapshot = b'\xff'*98304
        next_attempt = uuid.uuid4().hex
        reconstruct = self.command('reconstruct', sequence=2, snapshot=snapshot.hex(),
            snapshot_sha256=sha256(snapshot), next_attempt=next_attempt)
        bad = dict(reconstruct); bad['snapshot_sha256'] = '0'*64
        same = dict(reconstruct); same['next_attempt'] = self.attempt
        source = dict(action='source-state', attempt=next_attempt)
        result, responses = self.run_bridge([self.init(), self.command('outcome', outcome='ModelCompleted'),
            self.command('loader', sequence=2, body='760085', sender='Returned', stack_delta=-12,
                         program_start=None, program_bytes=None), bad, same, reconstruct,
            self.command('outcome', outcome='ModelCompleted'), source])
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(responses[4]['error'])
        self.assertTrue(responses[5]['error'])
        fresh = responses[6]
        self.assertEqual(next_attempt, fresh['attempt'])
        self.assertEqual(0, fresh['observations'])
        self.assertEqual('BootAndLoaderEntry', fresh['pending']['phase'])
        self.assertEqual('Stopped', fresh['detail']['source_state'])
        self.assertTrue(responses[7]['error'])
        self.assertEqual('Stopped', responses[8]['detail']['source_state'])
        self.assertEqual(2, responses[8]['detail']['source_observations'])


if __name__ == '__main__':
    unittest.main()
