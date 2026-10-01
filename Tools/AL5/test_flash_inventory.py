"""Check blocked planning and selector decoding from committed static evidence."""
import json
import unittest
from pathlib import Path
from resident_flash_inventory import extract

DOCS = Path(__file__).resolve().parents[2]/'Docs'/'AL5'


class FlashInventoryTests(unittest.TestCase):
    def setUp(self):
        self.low = bytearray(0x20000)
        evidence = json.loads((DOCS/'RESIDENT_FLASH_STATIC_EVIDENCE.json').read_text())
        for window in evidence['windows']:
            for ins in window['instructions']:
                address = int(ins['address'], 0)
                data = bytes.fromhex(ins['bytes'])
                self.low[address:address+len(data)] = data
        inventory = json.loads((DOCS/'RESIDENT_FLASH_INVENTORY.json').read_text())
        table = bytes.fromhex(inventory['selector_table_hex'])
        self.low[0x2A88:0x2A88+len(table)] = table

    def test_selector_bounds_and_collateral_cannot_enable_writing(self):
        report = extract(self.low)
        self.assertFalse(report['selectors'][0]['accepted'])
        self.assertEqual(len(report['selectors']), 19)
        intervals = report['candidate_calibration_intervals']
        self.assertEqual([r['selector'] for r in intervals], [3, 4])
        self.assertEqual(sum(r['calibration_bytes'] for r in intervals), 57304)
        self.assertEqual(sum(r['outside_calibration_bytes'] for r in intervals), 41000)
        self.assertFalse(report['ready_to_flash'])
        self.assertFalse(report['live_write_enabled'])
        self.assertEqual(report['would_send'], [])

    def test_unscaled_dispatch_is_rejected(self):
        self.low[0x2A82] = 0
        with self.assertRaises(ValueError):
            extract(self.low)

    def test_unrecognized_selector_target_is_rejected(self):
        self.low[0x2AB2:0x2AB4] = b'\x4E\x71'
        with self.assertRaises(ValueError):
            extract(self.low)


if __name__ == '__main__':
    unittest.main()
