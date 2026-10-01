"""Validate high-word evidence and confidence-only XDF changes offline."""
import copy
import json
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from al5_segment import START, LENGTH, ANCHORS
from validate_high_word import verify

DOCS = Path(__file__).resolve().parents[2]/'Docs/AL5/TunerPro'


class HighWordTests(unittest.TestCase):
    def setUp(self):
        self.report = json.loads((DOCS/'H0105_HIGH_WORD_EVIDENCE_v6_1.json').read_text())
        self.stock = bytearray(LENGTH)
        for a, raw in ANCHORS.items():
            self.stock[a-START:a-START+len(raw)] = raw
        for diff in self.report['cases'][0]['diff_ranges']:
            raw = bytes.fromhex(diff['before_hex'])
            a = diff['context_start']-START
            self.stock[a:a+len(raw)] = raw
        self.native = {'H0105':{'cells':[[2485.4839968]],
                               'limits':{'hard_max':2668768119.6254716}}}

    def check(self):
        return verify(self.report,self.stock,self.native)

    def test_nonzero_high_word_and_exact_encoding(self):
        evidence = self.check()
        self.assertEqual('00000FA0',evidence['before_hex'])
        self.assertEqual('000274A6',evidence['after_hex'])
        self.assertEqual(160934,evidence['after_raw'])
        self.assertGreater(evidence['after_raw'],65535)
        self.assertAlmostEqual(evidence['readback'],160934*0.6213709992)
        self.assertFalse(evidence['flash_ready'])

    def test_incomplete_report_and_incorrect_readback_rejected(self):
        original = copy.deepcopy(self.report)
        self.report['completed'] = False
        with self.assertRaises(ValueError): self.check()
        self.report = original
        self.report['cases'][0]['marker']['readback'] += 1
        with self.assertRaises(ValueError): self.check()

    def test_out_of_field_byte_and_native_width_mismatch_rejected(self):
        original = copy.deepcopy(self.report)
        self.report['cases'][0]['changed_bytes'][0]['address'] -= 4
        with self.assertRaises(ValueError): self.check()
        self.report = original
        self.native['H0105']['limits']['hard_max'] = 65535*0.6213709992
        with self.assertRaises(ValueError): self.check()

    def test_all_xdf_encodings_preserved(self):
        def semantic(node):
            return (node.tag,node.attrib,(node.text or '').strip(),
                    [semantic(c) for c in node if c.tag!='description'])
        old = ET.parse(DOCS/'AL5_15184109_15183960_MARKER_EXTENDED_v0_9.xdf').getroot()
        new = ET.parse(DOCS/'AL5_15184109_15183960_MARKER_EXTENDED_v0_9_1.xdf').getroot()
        old_items = {t.get('uniqueid'):semantic(t) for t in old if t.get('uniqueid')}
        new_items = {t.get('uniqueid'):semantic(t) for t in new if t.get('uniqueid')}
        self.assertEqual(old_items,new_items)


if __name__ == '__main__':
    unittest.main()
