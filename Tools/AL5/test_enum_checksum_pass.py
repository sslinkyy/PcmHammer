"""Simulated report checks, not native EFILive checksum/enum evidence."""
import copy
import unittest
from pathlib import Path
import re
from test_offline import fixture
from al5_segment import START, CHECKSUM
from checksum import native_field
from verify_enum_checksum_pass import CASES, verify


def changes(a,b):
    return [{'address':START+i,'before':x,'after':y} for i,(x,y) in enumerate(zip(a,b)) if x!=y]


class EnumChecksumTests(unittest.TestCase):
    def setUp(self):
        stock=bytearray(fixture())
        for _,address,factor,before,_ in CASES:
            stock[address-START:address-START+2]=int(before*factor).to_bytes(2,'big')
        stock[0x9000-START:0x9002-START]=b'\x01\x01'
        stock[-4:]=native_field(stock)
        self.stock=bytes(stock)
        self.report={'tool':'AL5-offline-enum-checksum-evidence-0.7','controller':'AL5',
            'operating_system':15184109,'transmission':15183960,'completed':True,
            'secondary_closed':True,'vehicle_io':False,'gui_descriptor_modified':False,
            'secondary_saved':False,'flash_ready':False,'baseline_checksum':stock[-4:].hex().upper(),
            'validation':{'secondary_baseline_equals_gui':True,
                          'native_stock_finalization_preserves_baseline':True,'gui_raw_unchanged':True},
            'checksum_cases':[],'enum_cases':[]}
        for id,address,factor,before,target in CASES:
            marked=bytearray(stock)
            marked[address-START:address-START+2]=int(target*factor).to_bytes(2,'big')
            final=bytearray(marked);final[-4:]=native_field(final)
            self.report['checksum_cases'].append({'marker':{'id':id,'column':0,'row':0,
                'before':before,'requested':target,'readback':target},'restored':True,
                'checksum_finalization_called':True,'marked_changed_bytes':changes(stock,marked),
                'finalized_changed_bytes':changes(stock,final),'marked_checksum':marked[-4:].hex().upper(),
                'finalized_checksum':final[-4:].hex().upper()})
        for i,id in enumerate(('D5053','D5054')):
            marked=bytearray(stock);offset=0x9000+i-START;marked[offset]=0
            self.report['enum_cases'].append({'marker':{'id':id,'column':0,'row':0,
                'before':'Enable','requested':'Disable','readback':'Disable'},'restored':True,
                'checksum_update_called':False,'changed_bytes':changes(stock,marked),'changed_byte_count':1,
                'diff_ranges':[{'context_start':START+offset,'context_end':START+offset,
                                'before_hex':'01','after_hex':'00'}]})

    def check(self): return verify(self.report,self.stock)

    def test_three_simulated_variants_and_two_enum_candidates(self):
        result=self.check()
        self.assertTrue(result['all_checksums_match'])
        self.assertEqual(3,len(result['checksum_variants']))
        self.assertEqual(2,len(result['enum_candidates']))
        self.assertFalse(result['flash_ready'])

    def test_incomplete_and_unrestored_reports_rejected(self):
        original=copy.deepcopy(self.report)
        self.report['completed']=False
        with self.assertRaises(ValueError): self.check()
        self.report=original
        self.report['checksum_cases'][0]['restored']=False
        with self.assertRaises(ValueError): self.check()

    def test_unexpected_payload_change_rejected(self):
        self.report['checksum_cases'][0]['finalized_changed_bytes'].append(
            {'address':0x9000,'before':1,'after':0})
        with self.assertRaises(ValueError): self.check()

    def test_native_field_mismatch_is_reported_not_corrected(self):
        r=self.report['checksum_cases'][0]
        # Simulate an independently finalized field with one incorrect byte.
        final=bytearray(self.stock)
        _,address,factor,_,target=CASES[0]
        final[address-START:address-START+2]=int(target*factor).to_bytes(2,'big')
        final[-4:]=native_field(final);final[-1]^=1
        r['finalized_changed_bytes']=changes(self.stock,final)
        r['finalized_checksum']=final[-4:].hex().upper()
        self.assertEqual('checksum_mismatch',self.check()['status'])

    def test_bad_enum_context_rejected(self):
        self.report['enum_cases'][0]['diff_ranges'][0]['after_hex']='FF'
        with self.assertRaises(ValueError): self.check()

    def test_v7_calls_only_file_calibration_apis(self):
        text=Path(__file__).with_name('AL5_ENUM_CHECKSUM_EVIDENCE_v7.lua').read_text()
        self.assertEqual({'_efiGetFileProp','_efiGetPartNumber','_efiOpenFile','_efiCloseFile',
            '_efiGetCalId','_efiGetCalProp','_efiGetCalValue','_efiSetCalValue','_efiUpdateChecksums'},
            set(re.findall(r'\b_efi\w+',text)))
        self.assertIn('local rc,e=q(_efiUpdateChecksums,fd)',text)
        self.assertNotIn('q(_efiUpdateChecksums,GUI_FD)',text)
        self.assertIn('fd<=0',text)


if __name__=='__main__': unittest.main()
