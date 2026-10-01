"""Final enum evidence rejection and honest numeric-cell coverage checks."""
import copy
import json
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from test_offline import fixture
from al5_segment import START
from checksum import native_field
from expand_d5197 import verify, ADDRESS

DOCS=Path(__file__).resolve().parents[2]/'Docs/AL5/TunerPro'


class D5197Tests(unittest.TestCase):
    def setUp(self):
        self.report=json.loads((DOCS/'D5197_DIFFERENTIAL_EVIDENCE_v8.json').read_text())
        stock=bytearray(fixture())
        for record in self.report['cases']:
            for d in record['diff_ranges']:
                raw=bytes.fromhex(d['before_hex']);offset=d['context_start']-START
                stock[offset:offset+len(raw)]=raw
        stock[-4:]=native_field(stock);self.stock=bytes(stock)
        ppei=bytearray(stock);ppei[ADDRESS-START]=64;ppei[-4:]=native_field(ppei)
        self.ppei=bytes(ppei)

    def test_all_options_and_ppei_identification(self):
        r=verify(self.report,self.stock,self.ppei)
        self.assertEqual('RPM Limit Req Disabled',r['ppei_option'])
        self.assertEqual({0,32,64,96},set(r['options']))
        self.assertFalse(r['flash_ready'])

    def test_wrong_text_and_coupled_change_rejected(self):
        original=copy.deepcopy(self.report)
        self.report['cases'][2]['marker']['readback']='Torque & RPM Limit Req Disabled'
        with self.assertRaises(ValueError):verify(self.report,self.stock,self.ppei)
        self.report=original
        self.report['cases'][0]['changed_bytes'].append({'address':ADDRESS+1,'before':0,'after':1})
        with self.assertRaises(ValueError):verify(self.report,self.stock,self.ppei)

    def test_unrestored_and_bad_context_rejected(self):
        original=copy.deepcopy(self.report)
        self.report['cases'][0]['restored']=False
        with self.assertRaises(ValueError):verify(self.report,self.stock,self.ppei)
        self.report=original
        self.report['cases'][0]['diff_ranges'][0]['before_hex']='00'
        with self.assertRaises(ValueError):verify(self.report,self.stock,self.ppei)

    def test_id_coverage_is_not_numeric_cell_completion(self):
        audit=json.loads((DOCS/'V0_11_AUDIT.json').read_text())
        c=audit['coverage']
        self.assertEqual(127,len(c['represented_ids']))
        self.assertEqual([],c['absent_ids'])
        self.assertEqual(2517,c['native_numeric_cell_count'])
        self.assertEqual(2381,c['compared_unique_numeric_cell_count'])
        self.assertFalse(c['numeric_coverage_complete'])
        self.assertEqual({'D5000','D5005'},set(c['missing_numeric_cells']))
        for coords in c['missing_numeric_cells'].values():
            self.assertEqual({(r,col) for r in range(17) for col in range(4,8)},set(map(tuple,coords)))

    def test_xdf_relabels_one_existing_raw_byte_and_preserves_encodings(self):
        old=ET.parse(DOCS/'AL5_15184109_15183960_MARKER_EXTENDED_v0_10.xdf').getroot()
        new=ET.parse(DOCS/'AL5_15184109_15183960_MARKER_EXTENDED_v0_11.xdf').getroot()
        old_items={t.get('uniqueid'):t for t in old if t.get('uniqueid')}
        new_items={t.get('uniqueid'):t for t in new if t.get('uniqueid')}
        self.assertEqual(set(old_items),set(new_items))
        for uid,item in old_items.items():
            for key in ('EMBEDDEDDATA','MATH'):
                self.assertEqual([t.attrib for t in item.iter(key)],[t.attrib for t in new_items[uid].iter(key)])
        t=new_items['0x2076']
        self.assertTrue(t.findtext('title').startswith('D5197 '))
        self.assertEqual('96',t.findtext('rangehigh'))

    def test_next_pass_samples_all_eight_remaining_columns(self):
        cases=json.loads((DOCS/'REMAINING_COLUMN_CASES_v9.json').read_text())['cases']
        self.assertEqual(24,len(cases))
        self.assertEqual({(id,col,row) for id in ('D5000','D5005')
            for col in range(4,8) for row in (0,8,16)},
            {(c['id'],c['column'],c['row']) for c in cases})
        self.assertTrue(all(c['expected']!=c['target'] for c in cases))


if __name__=='__main__':unittest.main()
