import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from analyze_sps_al5_write import Frames, summarize, verify_modules

def frame(payload, command=17):
    width=2 if command in (9,17) else 1
    b=bytes([command])+len(payload).to_bytes(width,'big')+payload
    return b+bytes([255-sum(b)%256])

class SpsWriteTests(unittest.TestCase):
    def test_extended_frame_survives_arbitrary_usb_fragmentation(self):
        payload=bytes(range(256))*16; raw=frame(payload); d=Frames(); rows=[]
        for i in range(0,len(raw),37): rows+=d.feed(raw[i:i+37])
        d.finish(); self.assertEqual([(0,17,payload)],rows)
    def test_corruption_and_truncation_fail_closed(self):
        raw=bytearray(frame(b'abc'));raw[-1]^=1
        with self.assertRaises(ValueError): Frames().feed(raw)
        d=Frames();d.feed(frame(b'abc')[:-1])
        with self.assertRaises(ValueError): d.finish()
    def test_loader_identity_and_duplicates_are_only_observations(self):
        m=bytes.fromhex('6d18f036800003ff9006')+b'abc'+bytes(2)
        rows=[dict(record=1,direction='T',hex=m.hex())]*2
        r=summarize(rows,b'prefixabc')
        self.assertEqual(6,r['blocks'][0]['utility_offset'])
        self.assertEqual(1,r['literal_duplicate_block_transmissions'])
        self.assertFalse(r['live_write_enabled']); self.assertFalse(r['recovery_verified'])
        with self.assertRaises(ValueError):summarize([dict(record=1,direction='T',hex=m[:-1].hex())],b'abc')
    def test_module_match_requires_padding_and_complete_coverage(self):
        with TemporaryDirectory() as td:
            p=Path(td)/'module';p.write_bytes(b'abc')
            data=b'abc'+bytes(4093)
            m=bytes.fromhex('6d18f036001000ff8000')+data+bytes(2)
            rows=[dict(direction='T',hex=m.hex())]
            r=verify_modules(rows,[p]);self.assertTrue(r['exact_stream_coverage'])
            self.assertTrue(r['modules'][0]['literal_match']);self.assertTrue(r['modules'][0]['zero_padding_matches'])
            p.write_bytes(b'abd');self.assertFalse(verify_modules(rows,[p])['modules'][0]['literal_match'])

if __name__=='__main__':unittest.main()
