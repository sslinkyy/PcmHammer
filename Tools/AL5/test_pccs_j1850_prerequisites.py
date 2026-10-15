import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_j1850_prerequisites as requests


class J1850PrerequisiteTests(unittest.TestCase):
    def test_pin(self):
        with self.assertRaisesRegex(ValueError,'pin changed'):
            requests.run(b'wrong source')

    def test_pc_bounds(self):
        for phase,(a,b) in requests.RANGES.items():
            self.assertTrue(requests.permitted_pc(phase,a,1))
            self.assertFalse(requests.permitted_pc(phase,b-1,2))
            self.assertFalse(requests.permitted_pc(phase,b,1))
        self.assertFalse(requests.permitted_pc('read',0x724668,1))

    def test_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'keep.json'
            output.write_text('keep',encoding='utf-8')
            with patch('sys.argv',['tool','missing.exe','--output',str(output)]),patch.object(requests,'audit') as audit:
                with self.assertRaises(SystemExit):requests.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'),'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'),'requires pinned PCCS and Unicorn')
    def test_native_matrix(self):
        cases=requests.audit(Path(os.environ['AL5_PCCS_EXE']).read_bytes())['cases']
        self.assertEqual(len(cases),9)
        for case in cases:
            ctx=case['context'];phase=ctx['phase']
            expected=(b'\x22'+ctx['identifier'].to_bytes(2,'big')+b'\x01' if phase=='read'
                      else b'\x01\x8c\x18\xf1\x27'+(b'\x01' if phase=='seed' else b'\x02'+ctx['key'].to_bytes(2,'big')))
            self.assertEqual(bytes.fromhex(case['constructed_buffer_hex']),expected)
            if phase=='read':
                self.assertEqual(case['pending_stack_arguments'],[0x18,0])
                self.assertEqual(case['reply_prefix_length'],3)
            else:
                self.assertEqual(case['pending_stack_arguments'],[ctx['client'],requests.THIS+0x528b0,len(expected),0,1])
            for key in ('send_or_dispatch_executed','key_algorithm_executed','security_authorization_proven','transport_used','live_write_enabled','ready_to_flash'):
                self.assertFalse(case[key])
            self.assertEqual(case['would_send'],[])

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'),'requires pinned PCCS and Unicorn')
    def test_context_guards(self):
        data=Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        for ctx in ({'phase':[]},{'phase':'unknown'},{'identifier':True},{'key':65536},{'client':-1}):
            with self.assertRaises(ValueError):requests.run(data,**ctx)


if __name__=='__main__':unittest.main()
