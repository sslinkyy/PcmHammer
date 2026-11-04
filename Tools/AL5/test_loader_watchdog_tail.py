"""Check native helper/park counts, sender failure branches and offline boundaries."""
import argparse
from pathlib import Path
import unittest
from unittest.mock import patch
from trace_loader_watchdog_tail import analyze,experiment


class WatchdogTailTests(unittest.TestCase):
    code=None

    @classmethod
    def setUpClass(cls):cls.report=analyze(cls.code)

    def test_native_service_delays_and_retained_marker(self):
        rows={row['case']:row for row in self.report['cases']}
        for name,status in (('success_ready',0x86),('bad_sum_ready',0xFF)):
            row=rows[name];out=row['observed']
            self.assertEqual([0x6C,0xF0,0x18,0x76,0,status],out['fifo_data'])
            self.assertEqual({'status':6,'delay_1':20479,'delay_2':20479},out['phases'])
            self.assertEqual(40964,out['watchdog_pairs']);self.assertEqual(81928,out['watchdog_writes_suppressed'])
            self.assertEqual([65535,65535],[d['d5'] for d in out['delay_returns']])
            self.assertEqual((0xD0C2,0xD0C2),(out['marker'],out['marker_alias']))
            self.assertEqual(1,len(out['marker_writes']));self.assertEqual(0xFFFF8000,out['marker_writes'][0]['address'])
            self.assertEqual('bounded_native_park',out['stop']);self.assertEqual(16,out['park_visits'])
            self.assertEqual(0,out['service_pairs_after_park']);self.assertEqual(0,out['receive_entries']);self.assertEqual(0,out['reset_opcodes'])
            self.assertTrue(out['loader_bytes_unchanged']);self.assertEqual(0,out['stack_delta'])
            self.assertLess(out['fifo_writes'][-1]['instruction'],out['delay_entries'][0]['instruction'])
            self.assertLess(out['delay_entries'][1]['instruction'],out['last_service_instruction'])
            self.assertLess(out['last_service_instruction'],out['marker_writes'][0]['instruction'])
            self.assertLess(out['marker_writes'][0]['instruction'],out['first_park_instruction'])
        for name in ('shared_exit_no_status','idle_expiry_boundary'):
            out=rows[name]['observed'];self.assertEqual([],out['fifo_data']);self.assertEqual(40958,out['watchdog_pairs']);self.assertEqual(0xD0C2,out['marker'])

    def test_sender_poll_budget_does_not_prove_a_hardware_reset(self):
        rows={row['case']:row['observed'] for row in self.report['cases']}
        self.assertEqual(40969,rows['success_delayed_ready']['watchdog_pairs'])
        self.assertEqual(45058,rows['last_successful_sender_poll']['watchdog_pairs'])
        for name in ('permanent_sender_busy','sender_countdown_exhausted'):
            out=rows[name];self.assertEqual('sender_busy_loader_restart_boundary',out['stop'])
            self.assertEqual(4095,out['ready_reads']);self.assertEqual(4096,out['watchdog_pairs'])
            self.assertEqual([0x6C],out['fifo_data']);self.assertEqual(0,out['delay_calls']);self.assertEqual([],out['marker_writes'])
            self.assertEqual(0,out['park_visits']);self.assertEqual(0,out['marker'])

    def test_park_bound_changes_no_service_or_time_claim(self):
        one=experiment(self.code,entry='shared_exit',park_visits=1)['observed']
        many=experiment(self.code,entry='shared_exit',park_visits=64)['observed']
        self.assertEqual(one['watchdog_pairs'],many['watchdog_pairs']);self.assertEqual(63,many['instructions']-one['instructions'])
        for row in self.report['cases']:
            for flag in ('hardware_access','physical_reset_verified','physical_timeout_verified','physical_fifo_ready_semantics_verified',
                         'final_status_wire_delivery_verified','host_readback_window_proven','live_upload_enabled','live_execution_enabled','live_write_enabled','ready_to_flash'):
                self.assertIs(row[flag],False)
            self.assertEqual(0,row['mmio_instructions_executed'])

    def test_unknown_inputs_rejected_before_emulator_creation(self):
        with patch('unicorn.Uc') as emulator:
            with self.assertRaises(ValueError):experiment(b'foreign loader')
            for options in ({'entry':[]},{'entry':'reset'},{'busy_reads':True},{'busy_reads':-1},{'busy_reads':4096},
                            {'park_visits':0},{'park_visits':65},{'park_visits':True}):
                with self.subTest(options=options),self.assertRaises(ValueError):experiment(self.code,**options)
            emulator.assert_not_called()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--loader',type=Path,required=True)
    args=parser.parse_args();WatchdogTailTests.code=args.loader.read_bytes();unittest.main(argv=['test_loader_watchdog_tail.py'])
