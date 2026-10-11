import struct
import unittest
from audit_object_transforms import census


def record(command=0x8414, payload=b'abcd', channel=1, prefix=b'\x01\x54'):
    wrapper=prefix+struct.pack('<H', command)+bytes(6)+struct.pack('<H',len(payload))+payload+bytes(2)
    if channel==2 and prefix==b'\x01\x52':wrapper+=b'\0'
    return {'kind':0x42,'offset':1024,'channel':channel,'subtype':0,'payload':wrapper}


class TransformCensusTests(unittest.TestCase):
    def test_complete_tx_rx_and_all_record_ordinals(self):
        text={'kind':0x54,'payload':b'ignored'}
        result=census([text,record(),record(0x8415,channel=2,prefix=b'\x01\x52')])
        self.assertEqual(2,result['complete_transform_wrapper_records'])
        self.assertEqual([1,2],[r['record_ordinal'] for r in result['records']])
        self.assertEqual(['host_tx_candidate','device_rx_candidate'],[r['direction_inference'] for r in result['records']])
        self.assertTrue(all('payload' not in r for r in result['records']))
        self.assertTrue(all(not r['successful_transform_verified'] for r in result['records']))

    def test_truncated_trailing_wrong_direction_only_signature_candidates(self):
        good=record()
        cases=[record(channel=2)]
        for value in (good['payload'][:4],good['payload'][:-1],good['payload']+b'\0'):
            cases.append(dict(good,payload=value))
        result=census(cases)
        self.assertEqual(4,result['transform_command_signature_records'])
        self.assertEqual(0,result['complete_transform_wrapper_records'])
        self.assertTrue(all(r['data_sha256'] is None for r in result['records']))

    def test_unframed_signatures_and_other_commands_not_promoted(self):
        items=[record(0x1234),dict(record(),payload=b'junk\x14\x84'),
               dict(record(),payload=b'\x01\x54\x14'),dict(record(),kind=0x54)]
        self.assertEqual([],census(items)['records'])


if __name__=='__main__':unittest.main()
