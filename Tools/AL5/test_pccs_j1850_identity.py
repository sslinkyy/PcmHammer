import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_j1850_identity as identity


class J1850IdentityTests(unittest.TestCase):
    def test_pin_before_layout(self):
        for run in (identity.run_probe_reply,identity.run_reset_prefix):
            with self.assertRaisesRegex(ValueError,'pin changed'):run(b'not the executable')

    def test_pc_bounds(self):
        self.assertTrue(identity.permitted_pc('probe',identity.PROBE,7))
        self.assertTrue(identity.permitted_pc('reset',identity.RESET,1))
        for phase,address,size in (('probe',identity.CLOCK_BOUNDARY-1,2),('probe',0x407208,1),
                                   ('reset',identity.RESET_STOP-1,2),('reset',0x726514,1),('other',identity.RESET,1)):
            self.assertFalse(identity.permitted_pc(phase,address,size))

    def test_existing_output_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'keep.json';output.write_text('keep',encoding='utf-8')
            with patch('sys.argv',['tool','missing.exe','--output',str(output)]),patch.object(identity,'audit') as audit:
                with self.assertRaises(SystemExit):identity.main()
            audit.assert_not_called();self.assertEqual(output.read_text(encoding='utf-8'),'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'),'requires pinned PCCS and Unicorn')
    def test_native_probe_matrix(self):
        data=Path(os.environ['AL5_PCCS_EXE']).read_bytes();cases=identity.audit(data)['probe_cases']
        expected=((1,0,0,'reply_handler_exit',['   ']),(1,0,0,'reply_handler_exit',['BP ']),
                  (3,9,0,'clock_or_retry_boundary',['   ']),(9,9,1,'clock_or_retry_boundary',[]),
                  (9,9,1,'clock_or_retry_boundary',[]),(9,9,1,'clock_or_retry_boundary',[]))
        self.assertEqual(len(cases),len(expected))
        for case,values in zip(cases,expected):
            self.assertEqual((case['family'],case['version'],case['host_status'],case['boundary'],case['identity_assignments']),values)
            self.assertEqual(case['quick_write'],1);self.assertEqual(case['alternate'],1)
            self.assertFalse(case['driver_executed']);self.assertFalse(case['full_probe_executed'])
            self.assertFalse(case['live_write_enabled']);self.assertFalse(case['ready_to_flash']);self.assertEqual(case['would_send'],[])

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'),'requires pinned PCCS and Unicorn')
    def test_native_reset_ownership(self):
        data=Path(os.environ['AL5_PCCS_EXE']).read_bytes();cases=identity.audit(data)['reset_cases']
        self.assertEqual(len(cases),6)
        for case in cases:
            context=case['context'];self.assertEqual(case['cleared_global_owner_indices'],list(range(256)))
            self.assertEqual(case['local_alternate'],0)
            self.assertEqual(case['local_quick_write'],context['quick_write'])
            self.assertEqual(case['global_owner_quick_write'],context['quick_write'])
            self.assertEqual(case['global_owner_flag0'],0)
            self.assertEqual(case['local_flag0'],0 if context['global_same_object'] else 0xaa)
            self.assertFalse(case['probe_call_executed']);self.assertFalse(case['full_reset_executed'])
            self.assertFalse(case['live_write_enabled']);self.assertFalse(case['ready_to_flash']);self.assertEqual(case['would_send'],[])

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'),'requires pinned PCCS and Unicorn')
    def test_invalid_contexts(self):
        data=Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        for context in ({'index':True},{'index':256},{'reply':[]},{'reply':bytes(0x21b)}):
            with self.assertRaises(ValueError):identity.run_probe_reply(data,**context)
        for context in ({'quick_write':True},{'quick_write':256},{'global_same_object':1}):
            with self.assertRaises(ValueError):identity.run_reset_prefix(data,**context)


if __name__=='__main__':unittest.main()
