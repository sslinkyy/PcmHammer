import json
from pathlib import Path
import unittest
from compare_pccs_resident_can import compare


class ResidentCanTests(unittest.TestCase):
    def test_low_identity_before_execution(self):
        with self.assertRaisesRegex(ValueError,'LOW identity changed'):
            compare(b'',b'unknown firmware',b'')

    def test_saved_contract_and_qualification_limits(self):
        r=json.loads((Path(__file__).resolve().parents[2]/'Docs/AL5/PCCS_RESIDENT_CAN_COMPATIBILITY_20261030.json').read_text())
        self.assertEqual(15,len(r['cases']))
        self.assertEqual(15,len(r['interfaces']))
        self.assertTrue(all(x['Protocol']=='CAN' for x in r['interfaces']))
        names={x['Desc'] for x in r['interfaces']}
        self.assertTrue({'Softing CANusb','NEXIQ USB-Link 2','DPA 5 USB'}<=names)
        for c in r['cases']:
            self.assertTrue(c['host_internal_payload'].startswith('22'))
            calls=c['controller']['flash_calls']
            self.assertEqual(0 if c['internal_identifier']=='0x2f8' else 1,len(calls))
            for call in calls:self.assertFalse(call['primitive_executed'])
        self.assertFalse(r['physical_can_support_proven'])
        self.assertFalse(r['ready_to_flash'])
        self.assertFalse(r['live_write_enabled'])


if __name__=='__main__':unittest.main()
