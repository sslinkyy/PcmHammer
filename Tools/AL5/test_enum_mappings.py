"""Check new byte enums and preservation of prior data encodings."""
import json
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
DOCS=Path(__file__).resolve().parents[2]/'Docs/AL5'


class EnumMappingTests(unittest.TestCase):
    def test_new_byte_fields_and_native_checksums(self):
        root=ET.parse(DOCS/'TunerPro/AL5_15184109_15183960_MARKER_EXTENDED_v0_10.xdf').getroot()
        report=json.loads((DOCS/'ENUM_CHECKSUM_EVIDENCE_v7.json').read_text())
        for record in report['enum_cases']:
            id=record['marker']['id'];address={'D5053':0xF6AC,'D5054':0xCCF2}[id]
            self.assertEqual([{'address':address,'before':1,'after':0}],record['changed_bytes'])
            t=next(t for t in root.findall('XDFCONSTANT') if t.findtext('title').startswith(id+' '))
            self.assertEqual(address,int(t.find('EMBEDDEDDATA').get('mmedaddress'),0))
            self.assertEqual('8',t.find('EMBEDDEDDATA').get('mmedelementsizebits'))
            self.assertEqual(('0','1','X'),(t.findtext('rangelow'),t.findtext('rangehigh'),t.find('MATH').get('equation')))
        checked=json.loads((DOCS/'ENUM_CHECKSUM_VALIDATION_v7.json').read_text())
        self.assertTrue(checked['all_checksums_match'])
        self.assertEqual(['732DAAC8','EBA232B3','7B29A38C'],[v['native_finalized_field'] for v in checked['checksum_variants']])
        self.assertFalse(checked['flash_ready'])

    def test_old_encodings_preserved_and_126_ids_represented(self):
        old=ET.parse(DOCS/'TunerPro/AL5_15184109_15183960_MARKER_EXTENDED_v0_9_1.xdf').getroot()
        new=ET.parse(DOCS/'TunerPro/AL5_15184109_15183960_MARKER_EXTENDED_v0_10.xdf').getroot()
        def semantic(t):
            return (t.tag,t.attrib,(t.text or '').strip(),[semantic(c) for c in t if c.tag not in ('title','description')])
        new_items={t.get('uniqueid'):t for t in new if t.get('uniqueid')}
        for t in old:
            if t.get('uniqueid'):self.assertEqual(semantic(t),semantic(new_items[t.get('uniqueid')]))
        audit=json.loads((DOCS/'TunerPro/V0_10_AUDIT.json').read_text())
        self.assertEqual('pass',audit['status'])
        self.assertEqual(126,len(audit['coverage']['represented_ids']))
        self.assertEqual(['D5197'],audit['coverage']['absent_ids'])

    def test_firmware_uses_full_byte_zero_tests(self):
        refs=json.loads((DOCS/'TunerPro/ADAPTIVE_ENABLE_FIRMWARE_REFERENCES.json').read_text())
        tests=[i for w in refs['windows'] for i in w['instructions'] if i['mnemonic']=='tst.b']
        self.assertTrue(any(i['address']=='0x730BC' and i['bytes']=='4a390000f6ac' for i in tests))
        self.assertTrue(any(i['address']=='0x72FFA' and i['bytes']=='4a390000ccf2' for i in tests))

    def test_final_enum_mapper_uses_exact_text_and_no_finalization(self):
        path=Path(__file__).with_name('AL5_D5197_TEXT_MAPPER_v8.lua')
        text=path.read_text()
        cases=text[text.index('local cases = {'):text.index('\nprint("AL5 D5197')]
        self.assertEqual(3,cases.count('id="D5197"'))
        for label in ('Torque Limit Req Disabled','RPM Limit Req Disabled','Torque and RPM Limit Req Disabled'):
            self.assertIn('target="'+label+'"',cases)
        self.assertNotIn('_efiUpdateChecksums',text)
        self.assertNotIn('_efiSaveFile',text)
        self.assertIn('if after~=x.target or after==before',text)
        self.assertIn('if get_value(fd,x.id,x.column,x.row)~=before',text)
        self.assertIn('if clean~=baseline then error',text)
        self.assertIn('fd<=0',text)


if __name__=='__main__':unittest.main()
