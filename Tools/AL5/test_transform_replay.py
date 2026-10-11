import json
from pathlib import Path
import struct
import unittest
from replay_object_transform import local_transform,replay
from test_object_transforms import record


def fixture():
    obj=struct.pack('<8H',0,0,70,70,4,0,0,0)+bytes(range(58))
    items=[]
    for selector,payload in [(12,obj[42:70]),(13,obj[70:])]:
        items.extend([record(0x8414,bytes((selector,0))+bytes(32)),
                      record(0x8414,b'\0',2,b'\x01\x52'),
                      record(0x8415,payload),
                      record(0x8415,bytes(len(payload)),2,b'\x01\x52')])
    return obj,items


class TransformReplayTests(unittest.TestCase):
    def test_local_word_transform_alignment_and_chunk_local_counter(self):
        self.assertEqual(bytes.fromhex('958e3535948e3535'),local_transform(bytes(8)))
        for value in (bytes(1),bytes(4097)):
            with self.assertRaises(ValueError):local_transform(value)

    def test_synthetic_reply_replay_does_not_claim_object_or_program_validation(self):
        obj,items=fixture()
        result=replay(items,obj,'AL5_W.obj')
        self.assertTrue(result['captured_transform_replay_verified'])
        self.assertFalse(result['object_validation_verified'])
        self.assertFalse(result['independent_device_transform_reproduced'])
        self.assertFalse(result['ready_to_flash'])
        self.assertEqual([],result['would_send'])
        self.assertEqual(4,len(result['exchange_stages']))

    def test_ambiguous_missing_corrupt_and_unmatched_replies_rejected(self):
        obj,items=fixture()
        cases=[items[:-1],items+[items[0]],items[1:],items[:2]+[items[3],items[2]]+items[4:]]
        cases.append(items[:2]+[record(0x8415,b'x'*28)]+items[3:])
        cases.append(items[:3]+[record(0x8415,b'x'*24,2,b'\x01\x52')]+items[4:])
        cases.append([record(0x8414,bytes(34))]+items[1:])
        cases.append(items[:1]+[dict(items[1],payload=items[1]['payload'][:-1])]+items[2:])
        for case in cases:
            with self.assertRaises(ValueError):replay(case,obj,'AL5_W.obj')

    def test_retained_saved_replays_pin_source_and_preserve_closed_gates(self):
        from al5_segment import sha256
        from test_offline import fixture as calibration_fixture
        from write_plan import plan
        root=Path(__file__).resolve().parents[2]
        evidence=json.loads((root/'Docs/AL5/OBJECT_TRANSFORM_REPLAY.json').read_text())
        self.assertEqual(5,len(evidence['cases']))
        self.assertTrue(evidence['all_supplied_buffer_crcs_match'])
        self.assertEqual({0xFCA1},{c['computed_crc16'] for c in evidence['cases']})
        self.assertEqual(1,len({c['data_sha256'] for c in evidence['cases']}))
        for case in evidence['cases']:
            self.assertFalse(case['ready_to_flash'])
            self.assertFalse(case['object_validation_verified'])
            self.assertEqual([],case['program_packets'])
            self.assertEqual(sha256((root/'Tools/AL5/replay_object_transform.py').read_bytes()),case['generator_sha256'])
        current=calibration_fixture()
        assessment=plan(current,current,sha256(current),'AL5',15184109)['existing_trace_assessment']['object_transform_replay_assessment']
        for role in ('evidence','static_evidence'):
            self.assertEqual(sha256((root/assessment[role]).read_bytes()),assessment[role+'_sha256'])
        self.assertFalse(assessment['object_validation_verified'])


if __name__=='__main__':unittest.main()
