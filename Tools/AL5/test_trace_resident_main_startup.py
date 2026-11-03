"""Native startup boundaries, explicit peripheral assumptions and preservation."""
import argparse
import json
from pathlib import Path
import unittest
from trace_resident_main_startup import trace


COMPLETION = [
    dict(pc=0xB42FC,address=0xFFFFFE18,size=2,value=0),
    dict(pc=0xB4302,address=0xFFFFFE1A,size=2,value=0),
    dict(pc=0xB430E,address=0xFFFFFE18,size=2,value=0),
]


class StartupTests(unittest.TestCase):
    image = None

    def assert_clear_and_preserved(self, observed):
        self.assertTrue(observed['banks_unchanged'])
        for value in observed['final_state'].values():
            self.assertEqual(set(value), {'0'})
        calls = observed['main_calls']
        self.assertEqual([0xC5B54,0xC5A88,0x21CE0,0xA96F8,0x23018],
                         [row['target'] for row in calls])
        self.assertEqual([True,True,True,True,False], [row['returned'] for row in calls])
        self.assertNotIn(0xBDC38, [row['pc'] for row in observed['boundaries']])

    def test_dirty_ram_patterns_stop_at_same_uncompleted_peripheral(self):
        for pattern in (0xA5,0x5A):
            with self.subTest(pattern=pattern):
                observed=trace(self.image,pattern)
                self.assertEqual(dict(reason='unchanged_peripheral_poll',pc=0xB42FC,
                                      address=0xFFFFFE18,size=2,value=0xFDBF),observed['stop'])
                self.assertEqual([], observed['consumed_mmio_inputs'])
                self.assert_clear_and_preserved(observed)

    def test_completion_hypothesis_exposes_next_unknown_without_zero_filling(self):
        observed=trace(self.image,mmio_inputs=COMPLETION)
        self.assertEqual(COMPLETION,observed['consumed_mmio_inputs'])
        self.assertEqual([],observed['unused_mmio_inputs'])
        self.assertEqual(dict(reason='unknown_mmio_read',pc=0xB4314,
                              address=0xFFFFFE20,size=1),observed['stop'])
        self.assert_clear_and_preserved(observed)

    def test_out_of_order_assumptions_do_not_match_a_different_register(self):
        rows=COMPLETION[1:]+COMPLETION[:1]
        observed=trace(self.image,mmio_inputs=rows)
        self.assertEqual('unchanged_peripheral_poll',observed['stop']['reason'])
        self.assertEqual([],observed['consumed_mmio_inputs'])
        self.assertEqual(rows,observed['unused_mmio_inputs'])
        self.assert_clear_and_preserved(observed)

    def test_assumption_scope_rejects_invalid_address_size_and_values(self):
        for changed in ({'address':-1},{'address':0x1FFFFFE18},{'address':0x4000},
                        {'address':0xFFFFFFFF,'size':2},{'address':0xFFFFE80F,'size':2},{'size':3},
                        {'value':65536},{'pc':0x100000},{'value':False}):
            row=dict(COMPLETION[0]);row.update(changed)
            with self.subTest(changed=changed),self.assertRaises(ValueError):
                trace(self.image,mmio_inputs=[row])

    def test_modified_saved_image_is_rejected(self):
        image=bytearray(self.image);image[0x4000]^=1
        with self.assertRaises(ValueError):trace(bytes(image))

    def communication_inputs(self):
        return json.loads((Path(__file__).parent/'Fixtures/resident_startup_communication_mmio.json').read_text())

    def test_two_register_wait_is_bounded_without_inventing_completion(self):
        rows=self.communication_inputs()[:24]
        observed=trace(self.image,mmio_inputs=rows)
        self.assertEqual(dict(reason='unchanged_peripheral_poll',pc=0x21DAA,
                              address=0xFFFFFE18,size=2,value=0),observed['stop'])
        self.assertTrue(observed['banks_unchanged'])
        self.assertEqual([],observed['synthetic_bank_programs'])

    def test_complete_peripheral_profile_still_traps_storage_by_default(self):
        observed=trace(self.image,mmio_inputs=self.communication_inputs(),stop_after_communication=True)
        self.assertEqual('before_storage_primitive',observed['stop']['reason'])
        self.assertEqual(0x22C3C,observed['stop']['entry'])
        stack=bytes.fromhex(observed['stop']['stack_hex'])
        self.assertEqual(0x229C2,int.from_bytes(stack[:4],'big'))
        self.assertEqual(0x4A1C,int.from_bytes(stack[12:16],'big'))
        self.assertTrue(observed['banks_unchanged'])
        self.assertEqual([],observed['synthetic_bank_programs'])

    def test_conditional_whole_entry_reaches_communication_with_explicit_bank_changes(self):
        for pattern,status in ((0xA5,0x80),(0x5A,0x40)):
            rows=self.communication_inputs()
            reset=next(row for row in rows if row['pc']==0xC599C);reset['value']=status
            with self.subTest(pattern=pattern,status=status):
                observed=trace(self.image,pattern,rows,model_bank_programs=True,stop_after_communication=True)
                self.assertEqual(dict(reason='after_communication_setup_return',pc=0x99604),observed['stop'])
                self.assertEqual([],observed['unused_mmio_inputs'])
                self.assertEqual(25,len(observed['main_calls']))
                self.assertTrue(all(row['returned'] for row in observed['main_calls']))
                self.assertEqual([0xBDC38,0xC02F8],[row['target'] for row in observed['main_calls'][-2:]])
                context=observed['communication_context']
                self.assertEqual('00000001000001',context['receive_flags'])
                self.assertTrue(context['mode23_eligible'])
                self.assertEqual((1,1),(context['producer'],context['consumer']))
                for value in observed['final_state'].values():self.assertEqual({'0'},set(value))
                self.assertFalse(observed['banks_unchanged'])
                self.assertEqual([0x4A1D,0x4A1E,0x4A29,0x4A2F,0x4A41,0x4A42],observed['bank_comparison']['changed_addresses'])
                programs=observed['synthetic_bank_programs']
                self.assertEqual([0x4A1C,0x4A1E,0x4A1C,0x4A28,0x4A2A,0x4A28,0x4A40,0x4A42,0x4A40],[row['destination'] for row in programs])
                self.assertEqual([2,10,2]*3,[row['bytes'] for row in programs])
                self.assertTrue(all(not row['implementation_executed'] for row in programs))
                self.assertEqual(['fffe','ffaa']*3,[row['after'] for row in programs if row['bytes']==2])

    def scheduler_inputs(self):
        return json.loads((Path(__file__).parent/'Fixtures/resident_startup_scheduler_mmio.json').read_text())

    def scheduler_sites(self):
        return json.loads((Path(__file__).parent/'Fixtures/resident_scheduler_sites.json').read_text())

    def test_remaining_initializers_unmask_interrupts_then_wait_for_handshake(self):
        observed=trace(self.image,mmio_inputs=self.scheduler_inputs(),model_bank_programs=True,stop_before_startup_wait=True)
        self.assertEqual(dict(reason='before_startup_handshake_wait',pc=0x5003C),observed['stop'])
        self.assertEqual(85,len(observed['main_calls']))
        self.assertTrue(all(row['returned'] for row in observed['main_calls'][:-1]))
        self.assertEqual(0x4FFE8,observed['main_calls'][-1]['target'])
        self.assertFalse(observed['main_calls'][-1]['returned'])
        boundary=next(row for row in observed['boundaries'] if row['pc']==0x9976E)
        self.assertEqual(0,boundary['scheduling']['sr']&0x700)
        self.assertEqual(1,observed['scheduling_context']['handshake'])
        self.assertEqual('0000',observed['final_state']['tracking'])
        self.assertEqual([],observed['scripted_ticks'])

    def test_native_timer_body_stops_at_unassumed_profiling_completion(self):
        observed=trace(self.image,mmio_inputs=self.scheduler_inputs(),model_bank_programs=True,scheduled_ticks=1)
        self.assertEqual(dict(reason='unchanged_peripheral_poll',pc=0x9D92C,
                              address=0xFFFFFE18,size=2,value=0x300),observed['stop'])
        self.assertEqual([0x40],observed['scripted_ticks'][0]['event_masks'])
        self.assertFalse(observed['scripted_ticks'][0]['returned'])
        self.assertFalse(observed['scripted_ticks'][0]['physical_exception_delivered'])

    def test_native_scheduler_changes_handshake_and_retains_background_response(self):
        observed=trace(self.image,mmio_inputs=self.scheduler_inputs(),model_bank_programs=True,
                       scheduled_ticks=320,mmio_site_inputs=self.scheduler_sites())
        self.assertEqual(dict(reason='after_native_startup_handshake',pc=0x5004C),observed['stop'])
        ticks=observed['scripted_ticks'];self.assertEqual(320,len(ticks))
        self.assertTrue(all(row['returned'] and not row['physical_exception_delivered'] for row in ticks))
        self.assertEqual(1,ticks[-1]['before']['handshake'])
        self.assertEqual(2,ticks[-1]['after']['handshake'])
        self.assertEqual(3,observed['scheduling_context']['handshake'])
        self.assertEqual(80,observed['entry_counts']['0xa4a38'])
        self.assertEqual(80,observed['entry_counts']['0x238ac'])
        self.assertEqual(1,observed['entry_counts']['0x4fee8'])
        self.assertEqual('0000',ticks[62]['state']['tracking'])
        self.assertEqual('0002',ticks[63]['state']['tracking'])
        self.assertEqual([dict(hex='49fe1806',response_index=2,tick=63)],observed['software_submissions'])
        self.assertEqual('0002',observed['final_state']['tracking'])
        self.assertEqual('000000000000',observed['final_state']['body'])
        self.assertEqual(13,len(observed['synthetic_bank_programs']))
        self.assertEqual([0x4A1D,0x4A1E,0x4A23,0x4A29,0x4A2F,0x4A41,0x4A42,0x4A47],observed['bank_comparison']['changed_addresses'])

    def test_scripted_tick_and_site_assumptions_fail_closed(self):
        for count in (-1,321,True):
            with self.subTest(count=count),self.assertRaises(ValueError):trace(self.image,scheduled_ticks=count)
        with self.assertRaises(ValueError):trace(self.image,scheduled_ticks=1,stop_after_communication=True)
        row=self.scheduler_sites()[0]
        with self.assertRaises(ValueError):trace(self.image,mmio_site_inputs=[row,row])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--full-reference',type=Path,required=True)
    args=parser.parse_args();StartupTests.image=args.full_reference.read_bytes()
    unittest.main(argv=['test_trace_resident_main_startup.py'])
