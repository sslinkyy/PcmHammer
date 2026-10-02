"""Status success alone must not permit another block or complete a replay."""
import unittest
from pathlib import Path
from al5_segment import START, END, sha256
from checksum import native_field
from test_offline import fixture
from test_host_validation import synthetic_frame
from replay_acknowledgments import replay
from write_plan import plan


def batch():
    baseline = fixture()
    candidate = bytearray(baseline)
    candidate[0x100:0x102] = b'\x12\x34'
    candidate[-4:] = native_field(candidate)
    frames = [synthetic_frame(START + 0x100), synthetic_frame(END - 4, candidate[-4:])]
    return baseline, bytes(candidate), frames


ACK = bytes.fromhex('6df018760073')  # Synthetic software bytes, not a verified wire frame.


def complete_events(candidate, frames):
    events = []
    for index, frame in enumerate(frames):
        events.extend([{'kind': 'issue', 'index': index}, {'kind': 'response', 'data': ACK},
                       {'kind': 'block_readback', 'index': index, 'data': frame[10:-2]}])
    return events + [{'kind': 'final_snapshot', 'data': candidate}]


class AcknowledgmentReplayTests(unittest.TestCase):
    def test_planner_links_replay_without_promoting_supplied_evidence(self):
        data = fixture()
        result = plan(data, data, sha256(data), 'AL5', 15184109)
        evidence = result['offline_acknowledgment_replay']
        path = Path(__file__).resolve().parents[2] / evidence['implementation']
        self.assertEqual(sha256(path.read_bytes()), evidence['implementation_sha256'])
        for key in ('wire_sequence_number_verified', 'physical_acknowledgment_correlation_verified',
                    'physical_readback_verified', 'automatic_retry_allowed'):
            self.assertFalse(evidence[key])
        self.assertFalse(result['ready_to_flash'])
        self.assertEqual([], result['would_send'])

    def test_complete_offline_sequence_keeps_live_gates_closed(self):
        baseline, candidate, frames = batch()
        result = replay(frames, baseline, complete_events(candidate, frames))
        self.assertEqual([], result['input_errors'])
        self.assertEqual('offline_complete', result['state'])
        self.assertEqual(2, result['matched_block_readbacks'])
        for key in ('automatic_retry_allowed', 'wire_sequence_number_verified',
                    'physical_acknowledgment_correlation_verified', 'physical_readback_verified',
                    'ready_to_flash', 'live_write_enabled'):
            self.assertFalse(result[key])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send', 'erase_packets', 'program_packets'):
            self.assertEqual([], result[key])

    def test_success_without_readback_cannot_advance(self):
        baseline, _, frames = batch()
        events = [{'kind': 'issue', 'index': 0}, {'kind': 'response', 'data': ACK}, {'kind': 'issue', 'index': 1}]
        result = replay(frames, baseline, events)
        self.assertEqual('aborted', result['state'])
        self.assertEqual(1, result['issued_blocks'])

    def test_duplicate_or_unsolicited_status_aborts(self):
        baseline, _, frames = batch()
        for events in ([{'kind': 'response', 'data': ACK}],
                       [{'kind': 'issue', 'index': 0}, {'kind': 'response', 'data': ACK}, {'kind': 'response', 'data': ACK}]):
            self.assertEqual('aborted', replay(frames, baseline, events)['state'])

    def test_bad_header_truncation_failure_and_timeout_abort(self):
        baseline, _, frames = batch()
        for event in ({'kind': 'response', 'data': ACK[:5]},
                      {'kind': 'response', 'data': bytes.fromhex('6df118760073')},
                      {'kind': 'response', 'data': ACK[:-1] + b'\xf8'},
                      {'kind': 'timeout'}, {'kind': 'disconnect'}):
            result = replay(frames, baseline, [{'kind': 'issue', 'index': 0}, event])
            self.assertEqual('aborted', result['state'])
            self.assertFalse(result['automatic_retry_allowed'])

    def test_wrong_readback_or_final_snapshot_aborts(self):
        baseline, candidate, frames = batch()
        events = complete_events(candidate, frames)
        events[2] = {'kind': 'block_readback', 'index': 0, 'data': b'\xff\xff'}
        self.assertEqual('aborted', replay(frames, baseline, events)['state'])
        events = complete_events(candidate, frames)
        events[-1] = {'kind': 'final_snapshot', 'data': baseline}
        self.assertEqual('aborted', replay(frames, baseline, events)['state'])

    def test_preflight_and_incomplete_events_never_complete(self):
        baseline, _, frames = batch()
        self.assertEqual('preflight_rejected', replay(frames + [frames[0]], baseline, [])['state'])
        self.assertEqual('incomplete', replay(frames, baseline, [{'kind': 'issue', 'index': 0}])['state'])

    def test_repeated_status_cannot_prove_wire_correlation(self):
        baseline, candidate, frames = batch()
        # Both blocks use indistinguishable ACK bytes. Readbacks are still mandatory.
        events = complete_events(candidate, frames)
        self.assertEqual(events[1]['data'], events[4]['data'])
        result = replay(frames, baseline, events)
        self.assertEqual('offline_complete', result['state'])
        self.assertFalse(result['physical_acknowledgment_correlation_verified'])


if __name__ == '__main__':
    unittest.main()
