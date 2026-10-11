import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from al5_segment import sha256
from inspect_vm_flow import descriptor,listing,analyze_buffers


class VmFlowTests(unittest.TestCase):
    def test_descriptors_bound_variable_data_and_skip_embedded_opcodes(self):
        blob=struct.pack('<HHH',0xB0,4,4)+struct.pack('<HH',0x51,0x52)
        value,end=descriptor(blob,0)
        self.assertEqual(10,end)
        self.assertEqual(4,value['payload_bytes'])
        self.assertNotIn('value',value)
        nodes,covered=listing(struct.pack('<H',9)+blob+struct.pack('<H',0x52))
        self.assertEqual([9,0x52],[n['opcode'] for n in nodes])
        self.assertEqual(14,covered)
        for bad in [blob[:-1],struct.pack('<HH',0xB0,0xFFFF),struct.pack('<H',0xA0),struct.pack('<HH',0xB3,1)]:
            with self.assertRaises(ValueError):descriptor(bad,0)

    def test_signed_targets_unknown_tail_and_stop_without_fallthrough(self):
        stream=struct.pack('<HHHHHH',0x51,0xA1,8,0x52,0x81,0xB1)+struct.pack('<HH',0,0x101)
        result=analyze_buffers(bytes(64),stream,[0,0,64,64,len(stream),0,8,0])
        self.assertEqual([],result['invalid_direct_targets'])
        self.assertEqual(2,result['uninterpreted_tail']['bytes'])
        self.assertFalse(any(e['source']==8 for e in result['control_flow_candidates']))
        negative=struct.pack('<HHH',0x50,0xA1,0xFFFF)
        nodes,_=listing(negative)
        self.assertEqual(-1,nodes[0]['target_offset'])
        self.assertFalse(result['ready_to_flash'])
        self.assertEqual([],result['would_send'])

    def test_target_inside_operand_is_reported_and_invalid_entry_rejected(self):
        stream=struct.pack('<HHHH',0x50,0xA1,2,0x52)
        result=analyze_buffers(bytes(64),stream,[0,0,64,64,8,0,6,0])
        self.assertEqual([{'source':0,'target':2}],result['invalid_direct_targets'])
        with self.assertRaises(ValueError):analyze_buffers(bytes(64),stream,[0,0,64,64,8,2,6,0])
        with self.assertRaises(ValueError):listing(struct.pack('<HH',0x51,0x52))

    def test_saved_control_flow_evidence_pins_sources_and_keeps_gates_closed(self):
        root=Path(__file__).resolve().parents[2]
        r=json.loads((root/'Docs/AL5/VM_PROGRAMMING_FLOW.json').read_text())
        old=json.loads((root/'Docs/AL5/OBJECT_TRANSFORM_REPLAY.json').read_text())
        self.assertEqual(1117,r['instruction_count'])
        self.assertEqual({'initial_entry':0x2AD8,'host_error_entry':0x2A76},r['entries'])
        self.assertEqual([],r['invalid_direct_targets'])
        self.assertEqual({r['instruction_buffer_sha256']},{c['data_sha256'] for c in old['cases']})
        self.assertEqual(sha256((root/'Tools/AL5/inspect_vm_flow.py').read_bytes()),r['generator_sha256'])
        values={v['value'] for v in r['programming_literal_references']}
        self.assertTrue({0x36EE,0x3600,0x36DB,0x36FE,0x36FF,512,0x8000,0x1FFFD}<=values)
        self.assertFalse(r['complete_vm_semantics_verified'])
        self.assertFalse(r['physical_recovery_verified'])
        self.assertIsNone(r['erase_scope'])
        self.assertEqual([],r['program_packets'])
        from write_plan import trace_assessment
        assessment=trace_assessment()['vm_control_flow_assessment']
        self.assertEqual(sha256((root/'Docs/AL5/VM_PROGRAMMING_FLOW.json').read_bytes()),assessment['evidence_sha256'])
        self.assertEqual(r['static_evidence_sha256'],assessment['static_evidence_sha256'])
        self.assertFalse(assessment['automatic_retry_allowed'])

    def test_cli_checks_identity_and_preserves_inputs_and_existing_output(self):
        root=Path(__file__).resolve().parents[2]
        r=json.loads((root/'Docs/AL5/VM_PROGRAMMING_FLOW.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'flow.json'
            command=[sys.executable,str(root/'Tools/AL5/inspect_vm_flow.py'),
                     '--trace',r['trace_path'],'--object',r['object_path'],
                     '--expected-trace-sha256',r['trace_sha256'],
                     '--expected-object-sha256',r['object_sha256'],'--output',str(output)]
            original={path:sha256(Path(path).read_bytes()) for path in [r['trace_path'],r['object_path']]}
            completed=subprocess.run(command,capture_output=True,timeout=20)
            self.assertEqual(0,completed.returncode,completed.stderr.decode(errors='replace'))
            generated=output.read_bytes()
            self.assertEqual(r['instruction_buffer_sha256'],json.loads(generated)['instruction_buffer_sha256'])
            self.assertNotEqual(0,subprocess.run(command,capture_output=True,timeout=20).returncode)
            self.assertEqual(generated,output.read_bytes())
            output.unlink()
            command[command.index('--expected-trace-sha256')+1]='0'*64
            self.assertNotEqual(0,subprocess.run(command,capture_output=True,timeout=20).returncode)
            self.assertFalse(output.exists())
            self.assertEqual(original,{path:sha256(Path(path).read_bytes()) for path in original})


if __name__=='__main__':unittest.main()
