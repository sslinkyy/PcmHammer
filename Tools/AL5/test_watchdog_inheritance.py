"""Native inherited configuration, post-reset check coverage and negative controls."""
import argparse
from pathlib import Path
import unittest
from unittest.mock import patch
from al5_watchdog_configuration import ConditionalWatchdogConfiguration
from trace_watchdog_inheritance import analyze
from emulate_flash_fault_recovery import experiment


class InheritanceTests(unittest.TestCase):
    image=None;loader=None
    @classmethod
    def setUpClass(cls):cls.report=analyze(cls.image,cls.loader)

    def test_native_boot_and_application_attempts_share_one_reset_context(self):
        for case in self.report['cases'][:3]:
            row=case['observed'];model=case['conditional_configuration']
            self.assertEqual('post_reset_calibration_check_return',row['stop'])
            self.assertEqual([(0x48E,'boot',0x84),(0xC5C3C,'application',0x84)],[(x['pc'],x['phase'],x['value']) for x in row['watchdog_control_attempts']])
            self.assertEqual([True,False],[x['conditionally_accepted'] for x in model['attempts']])
            self.assertEqual(0x84,model['effective_value_under_hypothesis']);self.assertEqual(512,model['timeout_system_clock_cycles_under_hypothesis'])
            self.assertIsNone(model['source_clock_hz']);self.assertIsNone(model['timeout_seconds'])
            self.assertEqual(0x2FE6,row['marker_at_application_entry']);self.assertTrue(case['same_reset_to_application_context'])
            self.assertEqual([0xA96F8,0xA960C,0x994FE],[x['pc'] for x in row['application_check_events']])
            self.assertTrue(row['rom_unchanged_from_selected_view']);self.assertEqual(0,row['flash_writes_blocked'])

    def test_boot_and_application_verification_have_different_coverage(self):
        rows={x['case']:x['observed'] for x in self.report['cases']}
        self.assertEqual('post_reset_calibration_crc_rejected',rows['calibration_crc_corrupt']['stop'])
        self.assertEqual('post_reset_calibration_marker_rejected',rows['calibration_marker_missing']['stop'])
        self.assertEqual('native_boot_failure_wait',rows['retained_marker_lost']['stop'])
        self.assertEqual('native_idle_boundary',rows['os_checksum_fault']['stop'])
        self.assertFalse(rows['retained_marker_lost']['application_entered']);self.assertFalse(rows['os_checksum_fault']['application_entered'])
        for name in ('watchdog_retained','calibration_compensation_corrupt'):
            row=rows[name];self.assertEqual('post_reset_calibration_check_return',row['stop'])
            self.assertEqual(57302,row['application_calibration_read_coverage']['bytes'])
            self.assertEqual([[0x8000,0x15FD6]],row['application_calibration_read_coverage']['ranges'])
            self.assertEqual([0x4AFC],[x['value'] for x in row['application_calibration_read_coverage']['marker_reads']])

    def test_reset_to_native_upload_retains_configuration_until_loader_entry(self):
        row=self.report['reset_to_captured_loader'];upload=row['upload']
        self.assertTrue(row['reset_to_upload_same_context']);self.assertTrue(row['boot_upload_to_loader_entry_same_context'])
        self.assertFalse(row['first_loader_instruction_executed']);self.assertTrue(row['programming_marker_is_synthetic_input'])
        self.assertEqual('before_captured_loader_entry',upload['stop'])
        self.assertEqual([dict(pc=0x48E,phase='boot',address=0xFFFFFA21,size=1,value=0x84)],upload['watchdog_control_attempts'])
        self.assertEqual(1590,upload['offline_captured_loader_copied_bytes'])
        self.assertFalse(upload['offline_captured_loader_handoff']['code_preloaded'])
        self.assertEqual(0x33B8,upload['offline_captured_loader_handoff']['pending_return'])
        self.assertEqual(0x84,row['conditional_configuration']['effective_value_under_hypothesis'])
        for flag in ('hardware_access','physical_watchdog_configuration_verified','physical_reset_verified','independent_readback_verified','host_verification_window_proven','live_upload_enabled','live_execution_enabled','live_write_enabled','ready_to_flash'):
            self.assertIs(self.report[flag],False)

    def test_write_once_hypotheses_do_not_assume_an_enabled_watchdog(self):
        for initial in (None,0x04,0x84):
            model=ConditionalWatchdogConfiguration(fresh_reset=False,inherited_value=initial)
            model.observe(pc=0x48E,phase='boot-attempt',value=0x84)
            self.assertEqual(initial,model.snapshot()['effective_value_under_hypothesis'])
            self.assertFalse(model.snapshot()['attempts'][0]['conditionally_accepted'])
        for value,cycles in ((0x84,512),(0xC4,262144),(0xB4,32768),(0xF4,16777216),(0x04,None)):
            model=ConditionalWatchdogConfiguration(fresh_reset=True);model.observe(pc=1,phase='fixture',value=value)
            self.assertEqual(cycles,model.snapshot()['timeout_system_clock_cycles_under_hypothesis'])
            exported=model.snapshot();exported['attempts'][0]['effective_after']=0
            self.assertEqual(value,model.snapshot()['effective_value_under_hypothesis'])

    def test_application_options_reject_before_cpu_creation(self):
        low,high=self.image[:0x20000],self.image[0x20000:]
        with patch('unicorn.Uc') as cpu:
            for kwargs in ({'post_reset_checks':1},{'post_reset_checks':True},
                {'post_reset_checks':True,'probe_boot_request':False,'retain_context':True},
                {'post_reset_checks':True,'probe_boot_request':False,'application_mmio_inputs':False},
                {'post_reset_checks':True,'probe_boot_request':False,'calibration_overlay':b''},
                {'post_reset_checks':True,'probe_boot_request':False,'calibration_marker':True},
                {'calibration_marker':0xFFFF},{'instruction_limit':1000001}):
                with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):experiment(low,high,**kwargs)
            cpu.assert_not_called()
        with self.assertRaises(ValueError):ConditionalWatchdogConfiguration(fresh_reset=True,inherited_value=0x84)
        model=ConditionalWatchdogConfiguration(fresh_reset=False)
        with self.assertRaises(ValueError):model.observe(pc=0x100000000,phase='fixture',value=0)

    def test_captured_loader_copy_is_pinned_and_one_shot(self):
        low,high=self.image[:0x20000],self.image[0x20000:]
        context=experiment(low,high,reset_status=0x20,retained_marker=0xBFC1,retain_context=True)
        with self.assertRaises(ValueError):context.copy_captured_loader_offline(b'foreign')
        self.assertTrue(context.closed)
        with self.assertRaises(ValueError):context.copy_captured_loader_offline(self.loader)
        self.assertEqual('before_synthetic_irq_rte',context.report['stop'])
        context=experiment(low,high,reset_status=0x20,retained_marker=0xBFC1,retain_context=True)
        context.copy_captured_loader_offline(self.loader)
        with self.assertRaises(ValueError):context.copy_captured_loader_offline(self.loader)
        with self.assertRaises(ValueError):context.copy_readonly_runtime(b'foreign',{})
        with self.assertRaises(ValueError):context.attach_runtime(None)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('full-reference','loader'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();InheritanceTests.image=args.full_reference.read_bytes();InheritanceTests.loader=args.loader.read_bytes()
    unittest.main(argv=['test_watchdog_inheritance.py'])
