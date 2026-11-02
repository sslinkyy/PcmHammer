"""Offline regression checks; explicit pinned inputs, no device discovery."""
import argparse
import unittest
from pathlib import Path
from emulate_flash_fault_recovery import SIZE, analyze, experiment, fault_bytes

class MappingTests(unittest.TestCase):
    def test_periodic_alias_and_word_lane(self):
        data=bytes(((i>>13) ^ (i>>8) ^ i)&255 for i in range(SIZE))
        view=fault_bytes(data,'a12_direct')
        for address in (0,0x1FFF,0x2000,0x3FFF,0x4000,0x6200,0xFFFFF):
            self.assertEqual(view[address],data[address&~0x2000])
        self.assertNotEqual(view[0x2000],data[0x2000])
        lanes=fault_bytes(bytes([255])*SIZE,'dq13_word')
        self.assertEqual(lanes[:4],bytes.fromhex('dfffdfff'))
    def test_identity_rejected_before_emulator(self):
        with self.assertRaises(ValueError):experiment(bytes(0x20000),bytes(0xE0000))

class NativeTests(unittest.TestCase):
    def test_reset_to_boot_session(self):
        r=analyze(*self.inputs)
        self.assertEqual(r['integrity_oracle'],{'normal':{'boot':0,'os':0},'a12_direct':{'boot':0x531,'os':0x2979}})
        cases={(c['fault'],c['window'],c['external_service_magic']):c for c in r['cases']}
        baseline=cases['a12_direct','none',0]
        self.assertEqual(baseline['stop'],'application_transfer_boundary')
        for window in ('held','release_at_os_reject'):
            self.assertEqual(cases['a12_direct',window,0]['stop'],'native_boot_failure_wait')
        positive=cases['a12_direct','os_check_to_reject',0]
        self.assertEqual(positive['software_tx_frames'],['6df0187444'])
        self.assertEqual(positive['upload_armed_byte'],1)
        self.assertEqual(positive['stop'],'before_synthetic_irq_rte')
        self.assertEqual(positive['idle_interrupt_mask'],0)
        self.assertEqual([o['d4']&65535 for o in positive['integrity_observations']],[0,0x2979])
        self.assertEqual(positive['events'],[{'pc':0x806,'fault_active':True},{'pc':0x890,'fault_active':False}])
        self.assertFalse(positive['fault_active_at_stop'])
        lingering=cases['a12_direct','os_check_to_vpw',0]
        self.assertEqual(lingering['first_changed_fetch']['pc'],0x2C90)
        self.assertEqual(cases['dq13_word','held',0]['first_changed_fetch']['pc'],0x400)
        external=cases['a12_direct','os_check_to_reject',0x5AA5]
        self.assertFalse(external['synthetic_irq_invoked'])
        self.assertEqual(external['software_tx_frames'],[])
        for c in r['cases']:
            self.assertEqual(c['flash_writes_blocked'],0)
            self.assertTrue(c.get('rom_unchanged_from_selected_view',False))
            for key in ('live_upload_enabled','live_execution_enabled','live_write_enabled','recovery_verified','exception_return_executed'):
                self.assertFalse(c[key])
        for c in r['reset_status_cases']:
            expected_reads=[0x7EA] if c['reset_status']&0x80 else [0x7EA,0x7F2]
            self.assertEqual([a['pc'] for a in c['reset_status_accesses'][:len(expected_reads)]],expected_reads)
            self.assertTrue(all(a['operation']=='read' and a['value']==c['reset_status'] for a in c['reset_status_accesses']))
            if c['reset_status']==0:
                self.assertEqual(c['stop'],'native_boot_failure_wait')
                self.assertEqual(c['events'],[])
            elif c['window']=='none':
                self.assertEqual(c['stop'],'application_transfer_boundary')
            else:
                self.assertEqual(c['software_tx_frames'],['6df0187444'])
                self.assertEqual(c['stop'],'before_synthetic_irq_rte')
            self.assertFalse(c['live_write_enabled'])
            self.assertEqual(c['flash_writes_blocked'],0)
        self.assertFalse(r['ready_to_flash'])
        self.assertEqual(r['would_send'],[])

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('low','high','loader'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    NativeTests.inputs=tuple(getattr(args,n).read_bytes() for n in ('low','high','loader'))
    unittest.main(argv=[__file__])
