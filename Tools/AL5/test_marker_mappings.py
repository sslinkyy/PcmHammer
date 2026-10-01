"""Evidence rejection tests using sparse context fixtures, no user BINs needed."""
import copy
import json
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from al5_segment import START, LENGTH, ANCHORS
from expand_marker_mappings import check_evidence

DOCS = Path(__file__).resolve().parents[2] / 'Docs/AL5/TunerPro'


class MarkerEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.report = json.loads((DOCS/'TARGETED_DIFFERENTIAL_EVIDENCE_v6.json').read_text())
        self.cases = json.loads((DOCS/'TARGETED_MARKER_CASES_v6.json').read_text())['cases']
        self.stock = bytearray(LENGTH)
        for address, raw in ANCHORS.items():
            self.stock[address-START:address-START+len(raw)] = raw
        # Sparse synthetic image: only reported baseline contexts and anchors.
        # The separate audit uses the real complete stock/PPEI images.
        for record in self.report['cases']:
            for diff in record['diff_ranges']:
                raw = bytes.fromhex(diff['before_hex'])
                offset = diff['context_start']-START
                self.stock[offset:offset+len(raw)] = raw
        self.native = {}
        for case in self.cases:
            entry = self.native.setdefault(case['id'], {'cells': [[0]*case['columns'] for _ in range(case['rows'])]})
            entry['cells'][case['row']][case['column']] = case['expected']

    def check(self):
        return check_evidence(self.report, self.cases, self.stock, self.native)

    def test_complete_evidence_resolves_all_83_cells(self):
        verified = self.check()
        self.assertEqual(83, len(verified))
        normal = next(c for c in verified if c['id']=='D5073' and c['row']==0 and c['column']==0)
        self.assertEqual('0x13B7A', normal['address'])

    def test_partial_unsafe_and_unrestored_reports_rejected(self):
        original = copy.deepcopy(self.report)
        for key, value in [('completed',False),('vehicle_io',True),('secondary_closed',False)]:
            self.report = copy.deepcopy(original)
            self.report[key] = value
            with self.assertRaises(ValueError): self.check()
        self.report = original
        self.report['cases'][0]['restored'] = False
        with self.assertRaises(ValueError): self.check()

    def test_duplicate_case_and_wrong_before_byte_rejected(self):
        original = copy.deepcopy(self.report)
        self.report['cases'][-1] = self.report['cases'][0]
        with self.assertRaises(ValueError): self.check()
        self.report = original
        self.report['cases'][0]['changed_bytes'][0]['before'] ^= 1
        with self.assertRaises(ValueError): self.check()

    def test_coupled_change_and_unreported_context_change_rejected(self):
        original = copy.deepcopy(self.report)
        self.report['cases'][0]['changed_bytes'][0]['address'] += 20
        with self.assertRaises(ValueError): self.check()
        self.report = original
        diff = self.report['cases'][0]['diff_ranges'][0]
        diff['after_hex'] = '00'+diff['after_hex'][2:]
        with self.assertRaises(ValueError): self.check()

    def test_wrong_readback_and_missing_case_rejected(self):
        original = copy.deepcopy(self.report)
        self.report['cases'][0]['marker']['readback'] += 1
        with self.assertRaises(ValueError): self.check()
        self.report = original
        self.report['cases'].pop()
        with self.assertRaises(ValueError): self.check()

    def test_v07_items_preserved_except_usage_warning(self):
        def semantic(item):
            return (item.tag, item.attrib, (item.text or '').strip(), [semantic(c) for c in item])
        old = ET.parse(DOCS/'AL5_15184109_15183960_STRUCTURAL_WOT_TCC_v0_7.xdf').getroot()
        new = ET.parse(DOCS/'AL5_15184109_15183960_MARKER_EXTENDED_v0_9.xdf').getroot()
        items = {t.get('uniqueid'):t for t in new if t.get('uniqueid')}
        for item in old:
            if not item.get('uniqueid') or item.findtext('title')=='READ ME - AL5 segment/XDF usage':
                continue
            self.assertEqual(semantic(item), semantic(items[item.get('uniqueid')]))


if __name__ == '__main__':
    unittest.main()
