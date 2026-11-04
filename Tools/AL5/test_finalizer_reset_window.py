"""Native finalizer/park boundaries; hardware stores suppressed, RAM marker optionally modeled."""
import argparse
from pathlib import Path
import unittest
from trace_finalizer_reset_window import analyze
from emulate_loader_finalize import experiment,fixture,audit


class ResetWindowTests(unittest.TestCase):
    code=None
    full_reference=None

    def test_native_status_to_reset_tail_has_no_receive_window(self):
        report=analyze(self.code);rows={row['case']:row['observed'] for row in report['cases']}
        for name,status in [('success_to_reset_store',0x86),('bad_sum_also_reaches_reset_store',0xFF)]:
            row=rows[name];self.assertEqual('before_retained_marker_store',row['stop'])
            self.assertEqual([status],[item['status'] for item in row['status_bodies']])
            self.assertEqual(2,row['reset_delay_calls'])
            self.assertEqual([0x40,0],[item['value'] for item in row['suppressed_reset_tail_stores']])
            self.assertEqual(dict(pc='0xff924a',address='0xffff8000',declared_24bit_address='0xff8000',size=2,value=0xd0c2,native_instruction_executed=False,host_modeled=False),row['retained_marker_store'])
            self.assertFalse(row['physical_reset_executed'])
        parked=rows['modeled_marker_reaches_park'];self.assertEqual('park_after_modeled_marker_store',parked['stop'])
        self.assertEqual('0xd0c2',parked['modeled_retained_marker'])
        failure=rows['marker_failure_returns_to_receive'];self.assertEqual('receive_boundary',failure['stop'])
        self.assertEqual(-4,failure['stack_delta']);self.assertIsNone(failure['retained_marker_store'])
        self.assertEqual([0xF8],[item['status'] for item in failure['status_bodies']])
        self.assertFalse(report['host_verification_window_proven'])

    def test_default_finalization_corpus_retains_its_original_stops(self):
        rows=audit(self.code)['cases'];self.assertEqual(8,len(rows))
        for row in rows:
            self.assertEqual('stop',row['context']['reset_tail'])
            self.assertEqual(0,row['observed']['reset_delay_calls'])
            self.assertIsNone(row['observed']['retained_marker_store'])
            self.assertFalse(row['observed']['physical_reset_executed'])

    def test_changed_loader_and_unknown_reset_policy_rejected(self):
        bad=bytearray(self.code);bad[0]^=1
        with self.assertRaises(ValueError):experiment(bytes(bad),fixture())
        with self.assertRaises(ValueError):experiment(self.code,fixture(),reset_tail='automatic')

    def test_retained_marker_boot_route_is_an_explicit_separate_hypothesis(self):
        if self.full_reference is None:self.skipTest('No pinned full image selected')
        report=analyze(self.code,self.full_reference)
        self.assertTrue(report['conditional_boot_uses_separate_contexts'])
        self.assertEqual(4,len(report['conditional_boot_cases']))
        for row in report['conditional_boot_cases']:
            self.assertEqual(0xD0C2,row['retained_marker'])
            self.assertEqual('application_transfer_boundary',row['stop'])
            self.assertEqual(0x2FE6,row['reset_marker'])
            self.assertTrue(row['rom_unchanged_from_selected_view'])
        self.assertFalse(report['physical_reset_verified'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--loader',type=Path,required=True)
    parser.add_argument('--full-reference',type=Path)
    args=parser.parse_args();ResetWindowTests.code=args.loader.read_bytes()
    ResetWindowTests.full_reference=None if args.full_reference is None else args.full_reference.read_bytes()
    unittest.main(argv=['test_finalizer_reset_window.py'])
