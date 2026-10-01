"""Reject unsafe/inconsistent evidence and preserve existing XDF encodings."""
import copy
import json
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from test_offline import fixture
from checksum import native_field
from al5_segment import START
from expand_remaining_columns import verify, BASES

DOCS = Path(__file__).resolve().parents[2]/'Docs/AL5/TunerPro'


class RemainingColumnTests(unittest.TestCase):
    def setUp(self):
        self.report = json.loads((DOCS/'REMAINING_COLUMN_EVIDENCE_v9.json').read_text(encoding='utf8'))
        self.prepared = json.loads((DOCS/'REMAINING_COLUMN_CASES_v9.json').read_text(encoding='utf8'))
        manifest = json.loads((DOCS/'REMAINING_COLUMN_MAPPING_v0_12.json').read_text(encoding='utf8'))
        stock = bytearray(fixture())
        self.native = {ident: {'cells': [[0]*8 for _ in range(17)]} for ident in BASES}
        for vector in manifest['vectors']:
            offset = int(vector['address'], 0)-START
            stock[offset-2:offset] = b'\x00\x11'
            for row, value in enumerate(vector['stock_values']):
                stock[offset+row*2:offset+row*2+2] = int(value*128).to_bytes(2, 'big')
                self.native[vector['id']]['cells'][row][vector['column']] = value
        for record in self.report['cases']:
            for context in record['diff_ranges']:
                offset = context['context_start']-START
                raw = bytes.fromhex(context['before_hex'])
                stock[offset:offset+len(raw)] = raw
        stock[-4:] = native_field(stock)
        self.stock = bytes(stock)

    def test_all_markers_and_full_vectors(self):
        evidence = verify(self.report, self.prepared, self.stock, self.native)
        self.assertEqual(136, evidence['stock_compared_cells'])
        self.assertEqual(8, len(evidence['vectors']))
        self.assertFalse(evidence['flash_ready'])

    def test_bad_restore_context_and_marker_rejected(self):
        for mutate in (lambda r: r['cases'][0].update(restored=False),
                       lambda r: r['cases'][0]['diff_ranges'][0].update(after_hex='00'),
                       lambda r: r['cases'][0]['marker'].update(row=1),
                       lambda r: r.update(vehicle_io=True)):
            report = copy.deepcopy(self.report)
            mutate(report)
            with self.assertRaises(ValueError): verify(report, self.prepared, self.stock, self.native)

    def test_unsampled_stock_mismatch_rejected(self):
        self.native['D5000']['cells'][1][4] += 1
        with self.assertRaises(ValueError): verify(self.report, self.prepared, self.stock, self.native)

    def test_full_coverage_and_existing_encodings_preserved(self):
        old = ET.parse(DOCS/'AL5_15184109_15183960_MARKER_EXTENDED_v0_11.xdf').getroot()
        new = ET.parse(DOCS/'AL5_15184109_15183960_MARKER_EXTENDED_v0_12.xdf').getroot()
        items = {t.get('uniqueid'): t for t in new if t.tag in ('XDFTABLE', 'XDFCONSTANT')}
        for item in old:
            if item.tag not in ('XDFTABLE', 'XDFCONSTANT'): continue
            for key in ('EMBEDDEDDATA', 'MATH'):
                self.assertEqual([t.attrib for t in item.iter(key)], [t.attrib for t in items[item.get('uniqueid')].iter(key)])
        coverage = json.loads((DOCS/'V0_12_AUDIT.json').read_text())['coverage']
        self.assertEqual(2517, coverage['compared_unique_numeric_cell_count'])
        self.assertEqual({}, coverage['missing_numeric_cells'])
        self.assertTrue(coverage['numeric_coverage_complete'])


if __name__ == '__main__': unittest.main()
