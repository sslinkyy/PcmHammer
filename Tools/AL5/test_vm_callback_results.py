import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from al5_segment import sha256
from replay_vm_callback_results import receive_outcome,replay


def event(result,payload='',status=None,capacity=4096,flags=0xFFFF):
    return {'id':'supplied','classification_profile':'mode1_selector1','callback_return':result,
            'payload_hex':payload,'exception_status':status,'destination_capacity':capacity,'flags_before':flags}


class CallbackTests(unittest.TestCase):
    def test_exception_status_preserves_raw_code_and_low16_error_semantics(self):
        for returned in (-1,0xFFFFFFFF,0xFFFF):
            result=receive_outcome(event(returned,status=0x101))
            self.assertEqual(-1,result['native_signed_low16'])
            self.assertEqual(0xFFFE,result['modeled_flags'])
            self.assertEqual(0x101,result['supplied_exception_status'])
            self.assertTrue(result['vm_failure_branch_0x1cee'])
            self.assertEqual(0,result['copied_bytes'])
        self.assertIsNone(receive_outcome(event(-1,status=0x10000))['modeled_flags'])

    def test_nonpositive_or_short_results_remain_unknown_without_stale_reads(self):
        for returned,status in [(0,None),(0,0),(-1,None),(-1,0)]:
            result=receive_outcome(event(returned,status=status))
            self.assertIsNone(result['modeled_flags'])
            self.assertIsNone(result['vm_failure_branch_0x1cee'])
        result=receive_outcome(event(3,'6c f0 fe'))
        self.assertEqual(3,result['copied_bytes'])
        self.assertIsNone(result['modeled_flags'])

    def test_negative_frame_truncation_and_separate_length_do_not_prove_ack(self):
        result=receive_outcome(event(6,'6c f0 fe 7f 36 78',capacity=5))
        self.assertEqual(5,result['copied_bytes'])
        self.assertEqual(6,result['length_scalar_value'])
        self.assertEqual(0x36,result['negative_response_code'])
        self.assertEqual(0xFF7F,result['modeled_flags'])
        self.assertTrue(result['destination_truncated'])
        self.assertFalse(result['controller_acknowledgment_verified'])
        result=receive_outcome(event(6,'6c f0 fe 76 00 73'))
        self.assertEqual(0xFF7E,result['modeled_flags'])
        self.assertFalse(result['controller_acknowledgment_verified'])
        self.assertFalse(result['ready_to_flash'])

    def test_malformed_inputs_profiles_and_duplicate_identity_rejected(self):
        for bad in [event(6,'6c f0 fe'),event(-1,'00',status=0x101),event(1,'gg'),event(True),event(0,capacity=0x8000)]:
            with self.assertRaises(ValueError):receive_outcome(bad)
        bad=event(0);bad['classification_profile']='unknown'
        with self.assertRaises(ValueError):receive_outcome(bad)
        with self.assertRaises(ValueError):replay({'schema_version':1,'cases':[event(0),event(0)]})

    def test_evidence_pins_and_planner_keep_cleanup_and_recovery_distinct(self):
        root=Path(__file__).resolve().parents[2]
        saved=json.loads((root/'Docs/AL5/VM_CALLBACK_RESULT_REPLAY.json').read_text())
        self.assertEqual(sha256((root/'Tools/AL5/replay_vm_callback_results.py').read_bytes()),saved['generator_sha256'])
        for item in saved['evidence']:self.assertEqual(sha256(Path(item['path']).read_bytes()),item['sha256'])
        from write_plan import trace_assessment
        assessment=trace_assessment()['vm_callback_result_assessment']
        self.assertEqual(sha256((root/'Docs/AL5/VM_CALLBACK_RESULT_REPLAY.json').read_bytes()),assessment['evidence_sha256'])
        self.assertFalse(assessment['controller_recovery_verified'])
        self.assertEqual([],saved['program_packets'])

    def test_cli_rejects_wrong_identity_and_preserves_inputs_existing_output(self):
        root=Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'events.json';output=Path(directory)/'report.json'
            source.write_bytes(json.dumps({'schema_version':1,'cases':[event(-1,status=0x101)]}).encode())
            digest=sha256(source.read_bytes())
            command=[sys.executable,str(root/'Tools/AL5/replay_vm_callback_results.py'),'--events',str(source),
                     '--expected-events-sha256',digest,'--output',str(output)]
            result=subprocess.run(command,capture_output=True,timeout=10)
            self.assertEqual(0,result.returncode,result.stderr.decode(errors='replace'))
            contents=output.read_bytes()
            self.assertNotEqual(0,subprocess.run(command,capture_output=True,timeout=10).returncode)
            self.assertEqual(contents,output.read_bytes())
            output.unlink();command[command.index('--expected-events-sha256')+1]='0'*64
            self.assertNotEqual(0,subprocess.run(command,capture_output=True,timeout=10).returncode)
            self.assertFalse(output.exists());self.assertEqual(digest,sha256(source.read_bytes()))


if __name__=='__main__':unittest.main()
