"""Constrain the storage model and keep recovery evidence from enabling writes."""
import json
import unittest
from pathlib import Path
from al5_segment import sha256
from emulate_storage_recovery import require_programmable
from test_offline import fixture
from write_plan import plan


class StorageRecoveryTests(unittest.TestCase):
    def test_nor_model_rejects_zero_to_one_and_length_mismatch(self):
        require_programmable(bytes.fromhex('ffff fffe ffaa'), bytes.fromhex('fffe ffaa 0000'))
        with self.assertRaises(ValueError):
            require_programmable(bytes.fromhex('ffaa'), bytes.fromhex('ffff'))
        with self.assertRaises(ValueError):
            require_programmable(b'\xff\xff', b'\xfe')

    def test_repair_and_crc_failure_evidence_do_not_enable_recovery(self):
        data = fixture()
        result = plan(data, data, sha256(data), 'AL5', 15184109)
        evidence = result['boot_preparation_assessment']['storage_recovery_evidence']
        path = Path(__file__).resolve().parents[2]/evidence['evidence']
        self.assertEqual(sha256(path.read_bytes()), evidence['evidence_sha256'])
        report = json.loads(path.read_text(encoding='utf8'))
        crc_failure = next(c for c in report['validation_cases'] if c['case'] == 'committed_bad_crc')
        self.assertEqual('0x8c9b', crc_failure['observed']['marker'])
        self.assertEqual('0x5b96c', crc_failure['observed']['stop_pc'])
        for active in ('0x4000', '0x6000'):
            interrupted = next(c for c in report['transaction_cases'] if c['active_bank'] == active and c['interrupt_after_operations'] == 1)
            self.assertIsNone(interrupted['reboot_selection']['selected_record'])
            self.assertEqual('0x22b18', interrupted['reboot_selection']['storage_trap']['entry'])
        self.assertFalse(evidence['physical_recovery_verified'])
        self.assertFalse(evidence['flash_implementation_executed'])
        self.assertFalse(result['ready_to_flash'])
        self.assertFalse(result['live_write_enabled'])
        self.assertIsNone(result['erase_scope'])
        for key in ('would_send', 'erase_packets', 'program_packets'):
            self.assertEqual([], result[key])


if __name__ == '__main__': unittest.main()
