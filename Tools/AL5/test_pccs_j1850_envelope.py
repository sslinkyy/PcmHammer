import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_j1850_envelope as envelope


class J1850EnvelopeTests(unittest.TestCase):
    def test_pin(self):
        with self.assertRaisesRegex(ValueError,'pin changed'):
            envelope.run(b'wrong source')
        with self.assertRaisesRegex(ValueError,'pin changed'):
            envelope.audit_class_bindings(b'wrong source')

    def test_pc_bounds(self):
        self.assertTrue(envelope.permitted_pc(envelope.START,10))
        self.assertFalse(envelope.permitted_pc(envelope.STOP-1,2))
        self.assertFalse(envelope.permitted_pc(envelope.STOP,1))
        self.assertFalse(envelope.permitted_pc(0x404820,1))

    def test_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'keep.json'
            output.write_text('keep',encoding='utf-8')
            with patch('sys.argv',['tool','missing.exe','--output',str(output)]),patch.object(envelope,'audit') as audit:
                with self.assertRaises(SystemExit):
                    envelope.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'),'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'),'requires pinned PCCS and Unicorn')
    def test_native_matrix(self):
        data=Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        cases=envelope.audit(data)['cases']
        self.assertEqual(len(cases),4)
        for case in cases:
            ctx=case['context']
            payload=bytes.fromhex(ctx['payload_hex'])
            expected=bytes([1,0x8c,ctx['target'],0xf1])+payload
            self.assertEqual(bytes.fromhex(case['constructed_buffer_hex']),expected)
            self.assertEqual(case['constructed_length'],len(payload)+4)
            self.assertEqual(case['pending_callback_args'],[ctx['client'],envelope.THIS+0x528b0,len(expected),0,0])
            self.assertEqual(len(case['synthetic_payload_copies']),1)
            for key in ('send_call_executed','physical_vpw_frame_proven','transport_used','live_write_enabled','ready_to_flash'):
                self.assertFalse(case[key])
            self.assertEqual(case['would_send'],[])

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'),'requires pinned PCCS and Unicorn')
    def test_context_guards(self):
        data=Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        for ctx in ({'target':True},{'target':256},{'payload':[]},{'payload':b''},{'payload':b'x'*129},{'client':-1}):
            with self.assertRaises(ValueError):
                envelope.run(data,**ctx)

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE'),'requires pinned PCCS')
    def test_source_class_bindings(self):
        data=Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        report=envelope.audit_class_bindings(data)
        self.assertEqual(report['class_name']['value'],'TJ1850')
        self.assertEqual(report['j1850_descriptor']['value'],0x723ba0)
        self.assertEqual(report['parent_descriptor']['value'],0x5a4004)
        slots={int(row['slot'],16):row for row in report['selected_slots']}
        for slot,address in ((0x10,0x5b487c),(0x18,0x5b4f80),(0x3c,0x5b87ac),(0x40,0x5b93e4)):
            self.assertTrue(slots[slot]['inherited_same_target'])
            self.assertEqual(slots[slot]['j1850']['value'],address)
        for slot,address in ((0,0x724668),(0x54,0x725350),(0x70,0x726734)):
            self.assertFalse(slots[slot]['inherited_same_target'])
            self.assertEqual(slots[slot]['j1850']['value'],address)
        self.assertFalse(report['base_dispatch_assumptions_valid_for_j1850'])
        self.assertFalse(report['ready_to_flash'])


if __name__=='__main__':
    unittest.main()
