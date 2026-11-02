"""Native reset/retained-marker regressions using explicit historical images."""
import argparse
import unittest
from pathlib import Path
from audit_a12_reset_routing import analyze
from emulate_flash_fault_recovery import experiment

class ResetRoutingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.report=analyze(*cls.inputs)

    def test_retained_marker_save_restore_and_gate_reads(self):
        for c in self.report['cases']:
            saved=[m for m in c['marker_accesses'] if m['pc']==0x4E6]
            restored=[m for m in c['marker_accesses'] if m['pc']==0x7C2]
            self.assertEqual([m['value'] for m in saved],[c['retained_marker']])
            self.assertEqual([m['value'] for m in restored],[c['retained_marker']])
            self.assertEqual([a['pc'] for a in c['reset_status_accesses'][:2]],[0x7EA,0x7F2])
            self.assertTrue(all(a['operation']=='read' and a['value']==c['reset_status'] for a in c['reset_status_accesses']))
            if c['vpw_initializer_entered']:
                self.assertEqual(c['reset_status_accesses'][-1]['pc'],0xA82)
                self.assertEqual(c['reset_status_snapshot'],c['reset_status'])

    def test_native_marker_routes(self):
        routes={0:(0,'native_boot_failure_wait'),0xD0C2:(0x2FE6,'application_transfer_boundary'),
                0x6124:(0x23CB,'before_synthetic_irq_rte'),0xBFC1:(0xB094,'before_synthetic_irq_rte'),
                0x30D4:(0x3E91,'before_synthetic_irq_rte'),0x8C9B:(0xA8E1,'before_synthetic_irq_rte'),
                0xA004:(0xB615,'before_synthetic_irq_rte'),0xCC8B:(0xC7D8,'before_synthetic_irq_rte'),
                0x9515:(0xC12A,'before_synthetic_irq_rte'),0x9372:(0x9372,'native_boot_failure_wait'),
                0x0595:(0x0595,'application_transfer_boundary'),0x2FE6:(0x0595,'application_transfer_boundary')}
        for c in self.report['cases']:
            if c['reset_status']==0 and c['window']=='none':
                marker,stop=routes[c['retained_marker']]
                self.assertEqual((c['reset_marker'],c['stop']),(marker,stop))
                self.assertEqual(c['events'],[])
            elif c['window']=='os_check_to_reject':
                if c['retained_marker']==0xD0C2:
                    self.assertEqual(c['events'],[{'pc':0x806,'fault_active':True},{'pc':0x890,'fault_active':False}])
                    self.assertEqual(c['reset_marker'],0xB615)
                else:self.assertEqual(c['events'],[])
                self.assertEqual(c['software_tx_frames'],['6df0187444'])
            else:self.assertEqual(c['stop'],'application_transfer_boundary')
            if c['retained_marker']==0xBFC1:
                self.assertEqual([(o['phase'],o['frame']) for o in c['software_tx_observations']],
                                 [('native_startup','6cf0187444'),('synthetic_irq','6df0187444')])

    def test_boundaries(self):
        for c in self.report['cases']:
            self.assertEqual(c['flash_writes_blocked'],0)
            self.assertTrue(c['rom_unchanged_from_selected_view'])
            self.assertFalse(c['fault_active_at_stop'])
            for flag in ('live_upload_enabled','live_execution_enabled','live_write_enabled','recovery_verified','exception_return_executed'):
                self.assertFalse(c[flag])
        for keyword in ({'reset_status':True},{'reset_status':256},{'retained_marker':True},{'retained_marker':65536},{'instruction_limit':0}):
            with self.assertRaises(ValueError):experiment(*self.inputs,**keyword)
        for flag in ('ready_to_flash','recovery_verified','live_upload_enabled','live_execution_enabled','live_write_enabled'):
            self.assertFalse(self.report[flag])
        self.assertEqual(self.report['would_send'],[])

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('low','high'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    ResetRoutingTests.inputs=(args.low.read_bytes(),args.high.read_bytes())
    unittest.main(argv=[__file__])
