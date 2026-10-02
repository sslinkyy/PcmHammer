"""Malformed later blocks must be rejected before any modeled edit."""
import unittest
from pathlib import Path
from al5_segment import START, END, sha256
from host_validation import inspect_block, simulate_batch
from test_offline import fixture
from write_plan import plan


def synthetic_frame(address=START, payload=b'\x12\x34', count=None, subtype=0):
    # Test fixture only. No production packet construction is provided.
    count = len(payload) if count is None else count
    tail = bytes([subtype]) + count.to_bytes(2, 'big') + address.to_bytes(3, 'big') + payload
    return bytes.fromhex('6d18f036') + tail + (sum(tail) & 65535).to_bytes(2, 'big')


class HostValidationTests(unittest.TestCase):
    def test_planner_links_implementation_without_live_transport(self):
        data = fixture()
        result = plan(data, data, sha256(data), 'AL5', 15184109)
        evidence = result['offline_host_validation']
        path = Path(__file__).resolve().parents[2] / evidence['implementation']
        self.assertEqual(sha256(path.read_bytes()), evidence['implementation_sha256'])
        self.assertFalse(evidence['physical_transport_verified'])
        self.assertFalse(evidence['physical_block_size_verified'])
        self.assertFalse(result['ready_to_flash'])
        self.assertEqual([], result['would_send'])

    def test_stale_short_frames_and_destructive_subtypes_rejected(self):
        for frame in (b'\x6d\x18', b'\x6d\x18\xf0\x36'):
            self.assertFalse(inspect_block(frame)['offline_input_valid'])
        for subtype in (0xEE, 0xFF, 0xDB, 0x80):
            self.assertFalse(inspect_block(synthetic_frame(subtype=subtype))['offline_input_valid'])

    def test_zero_odd_mismatch_alignment_and_full_range_checked(self):
        bad = [synthetic_frame(payload=b''), synthetic_frame(payload=b'\x42'),
               synthetic_frame(count=4), synthetic_frame(address=START + 1),
               synthetic_frame(address=START - 2), synthetic_frame(address=END - 2, payload=b'\x12\x34\x56\x78')]
        for frame in bad:
            self.assertFalse(inspect_block(frame)['offline_input_valid'])
        self.assertTrue(inspect_block(synthetic_frame(address=END - 2))['offline_input_valid'])
        bad_sum = bytearray(synthetic_frame()); bad_sum[-1] ^= 1
        self.assertFalse(inspect_block(bad_sum)['offline_input_valid'])
        global_frame = bytearray(synthetic_frame()); global_frame[1] = 0xFE
        self.assertFalse(inspect_block(global_frame)['offline_input_valid'])

    def test_later_malformed_block_prevents_all_edits(self):
        baseline = fixture()
        result = simulate_batch([synthetic_frame(), synthetic_frame(address=END)], baseline)
        self.assertEqual('preflight_rejected', result['stop'])
        self.assertEqual(0, result['modeled_bytes_written'])
        self.assertEqual(sha256(baseline), result['modeled_result_sha256'])

    def test_duplicate_overlap_empty_and_invalid_baseline_rejected(self):
        baseline = fixture()
        first = synthetic_frame(payload=b'\x12\x34\x56\x78')
        for frames in ([], [first, first], [first, synthetic_frame(address=START + 2)]):
            self.assertEqual(0, simulate_batch(frames, baseline)['modeled_bytes_written'])
        self.assertEqual(0, simulate_batch([first], baseline[:-1])['modeled_bytes_written'])

    def test_faults_can_leave_edits_and_never_allow_retry_or_live_write(self):
        baseline = fixture()
        frames = [synthetic_frame(payload=b'\x12\x34\x56\x78'), synthetic_frame(address=START + 4)]
        for fault, count in (('interrupted_word', 2), ('timeout', 4), ('negative_response', 4)):
            result = simulate_batch(frames, baseline, fault_index=0, fault_kind=fault)
            self.assertEqual(count, result['modeled_bytes_written'])
            self.assertNotEqual(sha256(baseline), result['modeled_result_sha256'])
            self.assertFalse(result['automatic_retry_allowed'])
            self.assertFalse(result['ready_to_flash'])
            self.assertFalse(result['live_write_enabled'])
            self.assertFalse(result['physical_write_outcome_verified'])
            self.assertIsNone(result['erase_scope'])
            for key in ('would_send', 'erase_packets', 'program_packets'):
                self.assertEqual([], result[key])

    def test_synthetic_completion_retains_checksum_and_physical_gates(self):
        result = simulate_batch([synthetic_frame()], fixture())
        self.assertEqual('synthetic_complete', result['stop'])
        self.assertFalse(result['modeled_result_native_checksum_valid'])
        self.assertFalse(result['ready_to_flash'])
        self.assertFalse(result['physical_block_size_verified'])


if __name__ == '__main__':
    unittest.main()
