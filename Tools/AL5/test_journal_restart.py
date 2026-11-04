"""Validate saved native epoch evidence and fail-closed bank overlay/replay handling."""
import argparse
import hashlib
import json
from pathlib import Path
import unittest
from trace_journal_restart import replay
from trace_resident_main_startup import trace


class JournalTests(unittest.TestCase):
    image=None
    directory=None

    def test_native_epochs_and_different_selected_banks(self):
        report=json.loads((self.directory/'report.json').read_text());rows=report['cases']
        self.assertEqual('al5-native-journal-restart-v1',report['schema']);self.assertEqual(3,len(rows))
        self.assertEqual(hashlib.sha256(self.image).hexdigest(),report['reference_sha256'])
        for name,digest in report['dependencies_sha256'].items():
            self.assertEqual(digest,hashlib.sha256((Path(__file__).parent/name).read_bytes()).hexdigest(),name)
        for row,changed,count,bank in zip(rows,(8,8,6),(13,13,10),(0x4000,0x6000,0x6000)):
            observed=row['observed'];before=(self.directory/(row['case']+'.before.bin')).read_bytes();after=(self.directory/(row['case']+'.after.bin')).read_bytes()
            self.assertEqual(dict(reason='after_native_startup_handshake',pc=0x5004C),observed['stop'])
            self.assertEqual(after,replay(before,observed['synthetic_bank_programs']))
            self.assertEqual(changed,len(observed['bank_comparison']['changed_addresses']))
            self.assertEqual(count,len(observed['synthetic_bank_programs']))
            self.assertTrue(all(bank<=a<bank+0x2000 for a in observed['bank_comparison']['changed_addresses']))
            self.assertTrue(all(call['returned'] for call in observed['small_record_calls']))
            self.assertEqual(320,len(observed['scripted_ticks']))
            self.assertTrue(all(not tick['physical_exception_delivered'] for tick in observed['scripted_ticks']))
        self.assertEqual((self.directory/'prepared_restart.after.bin').read_bytes(),(self.directory/'second_prepared_restart.before.bin').read_bytes())
        for flag in ('hardware_access','physical_reset_verified','physical_journal_transition_verified','host_verification_window_proven','live_upload_enabled','live_execution_enabled','live_write_enabled','ready_to_flash'):self.assertIs(report[flag],False)

    def test_invalid_overlay_does_not_enter_emulator(self):
        from unittest.mock import patch
        with patch('unicorn.Uc') as emulator:
            for data in (b'',b'\xFF'*0x3FFF,b'\xFF'*0x4001,bytearray(0x4000),'bytes'):
                with self.subTest(type=type(data)),self.assertRaises(ValueError):trace(self.image,saved_banks=data)
            emulator.assert_not_called()
        damaged=bytearray(self.image);damaged[0x4000]^=1
        with self.assertRaises(ValueError):trace(bytes(damaged),saved_banks=self.image[0x4000:0x8000])

    def test_replay_rejects_foreign_order_erase_and_span(self):
        before=b'\xFF'*0x4000;row=dict(destination=0x4A1C,before='ffff',after='fffe',bytes=2,implementation_executed=False)
        self.assertEqual(254,replay(before,[row])[0xA1D])
        for changed in ({'before':'0000'},{'after':'ffff','before':'fffe'},{'destination':0x7FFF},
                        {'bytes':1},{'implementation_executed':True}):
            op=dict(row);op.update(changed)
            with self.subTest(changed=changed),self.assertRaises(ValueError):replay(before,[op])
        with self.assertRaises(ValueError):replay(before,[row,row])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--full-reference',type=Path,required=True);parser.add_argument('--native-directory',type=Path,required=True)
    args=parser.parse_args();JournalTests.image=args.full_reference.read_bytes();JournalTests.directory=args.native_directory
    unittest.main(argv=['test_journal_restart.py'])
