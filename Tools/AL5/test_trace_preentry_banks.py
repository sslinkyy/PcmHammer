"""Bounded native pre-entry negative controls; saved firmware only, no hardware."""
import argparse
from pathlib import Path
import unittest
from trace_preentry_banks import PreEntryBanks


class PreEntryTests(unittest.TestCase):
    image = None

    def peer(self, guard=0x20):
        return PreEntryBanks(self.image[:0x20000], self.image[0x20000:], guard)

    def test_locked_programming_entry_is_rejected_before_storage(self):
        observed=self.peer().dispatch(bytes.fromhex('6d18f034'))
        self.assertEqual([0x33],[v['reason'] for v in observed['negative_helper_calls']])
        self.assertEqual([],observed['storage_calls'])
        self.assertEqual(0,observed['preparation_entry_count'])
        self.assertTrue(observed['banks_unchanged'])

    def test_malformed_programming_length_never_reaches_preparation(self):
        observed=self.peer(0).dispatch(bytes.fromhex('6d18f03400'))
        self.assertEqual([0x12],[v['reason'] for v in observed['negative_helper_calls']])
        self.assertEqual([],observed['storage_calls'])

    def test_read_count_rejected_without_preparation(self):
        observed=self.peer().dispatch(bytes.fromhex('6d18f02300400002'))
        self.assertEqual([0x12],[v['reason'] for v in observed['negative_helper_calls']])
        self.assertEqual('00',observed['mode23_pending'])
        self.assertEqual([],observed['storage_calls'])

    def test_forbidden_boot_words_remain_unreadable(self):
        observed=self.peer().dispatch(bytes.fromhex('6d18f023003fd801'))
        self.assertEqual([0x31],[v['reason'] for v in observed['negative_helper_calls']])
        self.assertEqual('00',observed['mode23_pending'])
        self.assertTrue(observed['banks_unchanged'])

    def test_read_leaves_existing_marker_and_lockout_state_unchanged(self):
        peer=self.peer(0x60)
        peer.uc.mem_write(0xFF8000,bytes.fromhex('1234'))
        peer.uc.mem_write(0xFF9DC0,b'\x64')
        observed=peer.dispatch(bytes.fromhex('6d18f023007ffc01'))
        self.assertEqual('0x1234',observed['marker'])
        self.assertEqual('0x60',observed['guard_flags'])
        self.assertEqual(100,observed['lockout_counter'])
        self.assertEqual('10',observed['mode23_pending'])
        self.assertEqual([],observed['flash_stores'])

    def test_unknown_source_profile_rejected(self):
        bad=bytearray(self.image);bad[0x4000]^=1
        with self.assertRaises(ValueError):PreEntryBanks(bytes(bad[:0x20000]),bytes(bad[0x20000:]))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--full-reference',type=Path,required=True)
    args=parser.parse_args();PreEntryTests.image=args.full_reference.read_bytes()
    unittest.main(argv=['test_trace_preentry_banks.py'])
