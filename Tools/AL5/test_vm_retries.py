import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from al5_segment import sha256
from audit_vm_retries import audit,counter_path,decrement_stored
from replay_object_transform import reconstruct
from decode_trace_containers import decode,records


class RetryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root=Path(__file__).resolve().parents[2]
        cls.flow=json.loads((cls.root/'Docs/AL5/VM_PROGRAMMING_FLOW.json').read_text())
        cls.code,cls.data,_=reconstruct(records(decode(Path(cls.flow['trace_path']).read_bytes())),
                                      Path(cls.flow['object_path']).read_bytes(),'AL5_W.obj')

    def test_zero_after_writeback_and_width_wrap_preserve_other_flags(self):
        for width in (8,16,32):
            zero=decrement_stored(1,width,0xFFFF)
            self.assertEqual(0,zero['stored_value'])
            self.assertEqual(0xFFFF,zero['flags'])
            self.assertTrue(zero['opcode47_branch'])
            wrapped=decrement_stored(0,width,0xFFFF)
            self.assertEqual((1<<width)-1,wrapped['stored_value'])
            self.assertEqual(0xFFDF,wrapped['flags'])
            self.assertTrue(wrapped['opcode48_branch'])
        self.assertEqual(0,decrement_stored(0,8,step=256)['stored_value'])
        self.assertEqual(0xFFFF,decrement_stored(0x8000,16,step=0x8001)['stored_value'])
        for width,value in [(7,0),(8,256),(16,-1)]:
            with self.assertRaises(ValueError):decrement_stored(value,width)

    def test_counter_paths_terminate_at_zero_without_borrow_inference(self):
        for initial,width in [(3,16),(8,8),(20,8)]:
            steps=counter_path(initial,width)
            self.assertEqual(list(range(initial-1,-1,-1)),[s['stored_value'] for s in steps])
            self.assertTrue(all(s['opcode48_branch'] for s in steps[:-1]))
            self.assertTrue(steps[-1]['opcode47_branch'])
        for initial in (0,21):
            with self.assertRaises(ValueError):counter_path(initial,8)

    def test_saved_helper_payload_and_failure_paths_keep_all_gates_closed(self):
        result=audit(self.flow,self.code,self.data)
        self.assertEqual('6c fe f0 28 00',result['profile']['helper028e_inline_bytes'])
        self.assertEqual(20,result['helper028e']['maximum_counted_receives'])
        self.assertEqual(0x81,result['helper028e']['clear_flags_mask'])
        self.assertEqual(0x1DCE,result['programming_branches'][1]['target'])
        self.assertEqual(0x1D78,result['programming_branches'][2]['target'])
        self.assertFalse(result['flag20']['global_numeric_meaning_assumed'])
        for key in ('physical_recovery_verified','ready_to_flash','live_write_enabled','automatic_retry_allowed'):
            self.assertFalse(result[key])
        self.assertIsNone(result['erase_scope'])
        self.assertEqual([],result['would_send'])
        self.assertEqual([],result['program_packets'])

    def test_changed_profile_or_reconstruction_is_rejected(self):
        changed=copy.deepcopy(self.flow)
        node=next(n for n in changed['structural_instructions'] if n['offset']==0x1DDE)
        node['operands'][0]['value']=0x1BBC
        with self.assertRaises(ValueError):audit(changed,self.code,self.data)
        with self.assertRaises(ValueError):audit(self.flow,self.code[:-1],self.data)

    def test_report_and_planner_pin_evidence_without_authorizing_retries(self):
        saved=json.loads((self.root/'Docs/AL5/VM_RETRY_FAILURE_AUDIT.json').read_text())
        self.assertEqual(sha256((self.root/'Tools/AL5/audit_vm_retries.py').read_bytes()),saved['generator_sha256'])
        self.assertEqual(self.flow['instruction_buffer_sha256'],saved['instruction_buffer_sha256'])
        for entry in saved['evidence_inputs']:
            self.assertEqual(sha256(Path(entry['path']).read_bytes()),entry['sha256'])
        from write_plan import trace_assessment
        assessment=trace_assessment()['vm_retry_failure_assessment']
        self.assertEqual(sha256((self.root/'Docs/AL5/VM_RETRY_FAILURE_AUDIT.json').read_bytes()),assessment['evidence_sha256'])
        self.assertFalse(assessment['automatic_retry_allowed'])
        self.assertFalse(assessment['physical_recovery_verified'])

    def test_cli_preserves_inputs_and_existing_output_and_rejects_wrong_hash(self):
        paths=[self.root/'Docs/AL5'/name for name in ['VM_PROGRAMMING_FLOW.json','VM_FLAG20_STATIC.json','VM_RETRY_HELPERS_STATIC.json']]
        hashes=[sha256(path.read_bytes()) for path in paths]
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'audit.json'
            command=[sys.executable,str(self.root/'Tools/AL5/audit_vm_retries.py'),'--output',str(output)]
            for name,path,digest in zip(['flow','flag-evidence','helper-evidence'],paths,hashes):
                command+=['--'+name,str(path),'--expected-'+name+'-sha256',digest]
            result=subprocess.run(command,capture_output=True,timeout=20)
            self.assertEqual(0,result.returncode,result.stderr.decode(errors='replace'))
            contents=output.read_bytes()
            self.assertFalse(json.loads(contents)['ready_to_flash'])
            self.assertNotEqual(0,subprocess.run(command,capture_output=True,timeout=20).returncode)
            self.assertEqual(contents,output.read_bytes())
            output.unlink()
            command[command.index('--expected-flow-sha256')+1]='0'*64
            self.assertNotEqual(0,subprocess.run(command,capture_output=True,timeout=20).returncode)
            self.assertFalse(output.exists())
        self.assertEqual(hashes,[sha256(path.read_bytes()) for path in paths])


if __name__=='__main__':unittest.main()
