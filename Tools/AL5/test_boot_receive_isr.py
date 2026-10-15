import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_boot_receive_isr as isr


class BootReceiveIsrTests(unittest.TestCase):
    def test_source_pin(self):
        with self.assertRaisesRegex(ValueError,'source pin'):isr.run(bytes(0x20000))

    def test_pc_boundaries(self):
        self.assertTrue(isr.permitted_pc(0x39ac,4))
        self.assertTrue(isr.permitted_pc(0x3b76,2))
        for pc,size in ((0x39f4,2),(0x3b78,2),(0x2e8c,2),(0x341c,4),(0x3074,4),(0x39f2,4)):
            self.assertFalse(isr.permitted_pc(pc,size))

    def test_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)/'keep.json';out.write_text('keep',encoding='utf-8')
            with patch('sys.argv',['tool','--low','missing.bin','--output',str(out)]),patch.object(isr,'audit') as audit:
                with self.assertRaises(SystemExit):isr.main()
            audit.assert_not_called();self.assertEqual(out.read_text(encoding='utf-8'),'keep')

    @unittest.skipUnless(os.environ.get('AL5_LOW_BIN') and importlib.util.find_spec('unicorn'),'requires pinned LOW and Unicorn')
    def test_native_matrix(self):
        low=Path(os.environ['AL5_LOW_BIN']).read_bytes();cases=isr.audit(low)['cases']
        self.assertEqual([c['stop'] for c in cases],['before_rte','before_rte','resident_dispatch_entry','ram_transfer_entry','resident_dispatch_entry','before_rte'])
        self.assertEqual([c['fifo_events_consumed'] for c in cases],[0,1,5,4,5,13])
        self.assertEqual([c['stack_delta'] for c in cases],[0,0,-32,-32,-32,0])
        self.assertEqual(cases[2]['staged_length'],4)
        self.assertEqual(cases[2]['processing_flag'],1)
        self.assertEqual(cases[3]['processing_flag'],0)
        self.assertEqual(cases[5]['flush_calls'],1)
        for c in cases:
            self.assertEqual(c['upload_armed'],int(c['context']['prior_armed']))
            self.assertTrue(c['native_link_movem_executed'])
            for key in ('exception_return_executed','actual_interrupt_delivered','hardware_fifo_qualified',
                        'dispatcher_or_transfer_executed','transport_used','live_write_enabled','ready_to_flash'):
                self.assertFalse(c[key])
            self.assertEqual(c['would_send'],[])

    @unittest.skipUnless(os.environ.get('AL5_LOW_BIN') and importlib.util.find_spec('unicorn'),'requires pinned LOW and Unicorn')
    def test_context_and_fifo_guards(self):
        low=Path(os.environ['AL5_LOW_BIN']).read_bytes()
        for ctx in ({'enabled':1},{'events':[]},{'events':((True,0),)},{'events':((256,0),)},
                    {'events':((0,0),)*33},{'prior_armed':1}):
            with self.assertRaises(ValueError):isr.run(low,**ctx)
        with self.assertRaisesRegex(ValueError,'FIFO exhausted'):isr.run(low,events=())


if __name__=='__main__':unittest.main()
