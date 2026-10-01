"""Service-binding rejection and dry-run separation of static entry evidence."""
import json
import unittest
from pathlib import Path
from emulate_application_boot import service_binding
from test_offline import fixture
from write_plan import plan
from al5_segment import sha256

DOCS = Path(__file__).resolve().parents[2]/'Docs/AL5'


class ApplicationBootTests(unittest.TestCase):
    def setUp(self):
        self.evidence = json.loads((DOCS/'APPLICATION_BOOT_EMULATION.json').read_text(encoding='utf8'))
        table = self.evidence['application_service_table']
        self.image = bytearray(0x100000)
        self.image[0x99A70:0x99AF4] = bytes.fromhex(table['table_hex'])
        self.image[0x99AF4] = 22
        for entry in table['entries']:
            address = int(entry['descriptor'], 0)
            self.image[address:address+6] = bytes.fromhex(entry['descriptor_flags'])+int(entry['handler'], 0).to_bytes(4, 'big')

    def test_service_binding_and_corrupt_handler_rejected(self):
        self.assertEqual('0xbe6d0', service_binding(self.image)['boot_request']['handler'])
        self.image[0x99A32:0x99A36] = bytes.fromhex('00000000')
        with self.assertRaises(ValueError): service_binding(self.image)

    def test_bad_count_and_descriptor_rejected(self):
        self.image[0x99AF4] = 21
        with self.assertRaises(ValueError): service_binding(self.image)
        self.image[0x99AF4] = 22
        self.image[0x99A72:0x99A76] = bytes.fromhex('ffffffff')
        with self.assertRaises(ValueError): service_binding(self.image)

    def test_offline_application_route_does_not_authorize_session(self):
        data = fixture()
        report = plan(data, data, sha256(data), 'AL5', 15184109)
        boot = report['boot_loader_assessment']
        evidence = boot['application_transition_evidence']
        self.assertTrue(evidence['offline_cases_pass'])
        self.assertEqual(sha256((DOCS/'APPLICATION_BOOT_EMULATION.json').read_bytes()), evidence['evidence_sha256'])
        self.assertFalse(evidence['startup_response_proves_upload_armed'])
        self.assertFalse(evidence['reset_hardware_verified'])
        self.assertFalse(boot['application_entry_verified'])
        self.assertFalse(report['ready_to_flash'])
        self.assertEqual([], report['would_send'])


if __name__ == '__main__': unittest.main()
