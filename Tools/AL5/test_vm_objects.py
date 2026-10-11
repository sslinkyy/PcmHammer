"""Boundary regressions for observed VM framing; no installed code execution."""
import unittest
import struct
import json
from pathlib import Path
from al5_segment import sha256
from test_offline import fixture as segment_fixture
from write_plan import plan
from inspect_vm_objects import inspect_bytes


def fixture():
    return struct.pack('<8H', 123, 0, 46, 46, 4, 12, 34, 56) + bytes(34)


class VmObjectTests(unittest.TestCase):
    def test_saved_objects_and_planner_preserve_source_identity_and_closed_gates(self):
        root = Path(__file__).resolve().parents[2]
        inventory = json.loads((root / 'Docs/AL5/EFILIVE_VM_OBJECT_INVENTORY.json').read_text())
        self.assertEqual(4, inventory['object_count'])
        self.assertEqual(sha256((root / 'Tools/AL5/inspect_vm_objects.py').read_bytes()), inventory['generator_sha256'])
        for item in inventory['objects']:
            self.assertEqual(item['bytes'], item['data_offset'] + item['data_section_bytes'])
            self.assertFalse(item['object_contents_decoded'])
            self.assertFalse(item['object_executed'])
        data = segment_fixture()
        result = plan(data, data, sha256(data), 'AL5', 15184109)
        assessment = result['existing_trace_assessment']['vm_object_loading_assessment']
        for name in ('evidence', 'static_evidence'):
            self.assertEqual(sha256((root / assessment[name]).read_bytes()), assessment[name + '_sha256'])
        self.assertFalse(result['ready_to_flash'])
        self.assertEqual([], result['would_send'])

    def test_bounded_sections_preserve_unknown_words_without_decoding(self):
        result = inspect_bytes(fixture(), 'AL5_W.obj')
        self.assertEqual([123, 0, 46, 46, 4, 12, 34, 56], result['header_words_le16'])
        self.assertEqual([4, 4], [section['bytes'] for section in result['sections']])
        for key in ('object_contents_decoded', 'callback_transform_reproduced',
                    'object_crc_verified', 'object_executed'):
            self.assertFalse(result[key])

    def test_truncation_trailing_gaps_overlap_and_alignment_rejected(self):
        good = fixture()
        bad = [good[:-1], good + b'\0', good[:15]]
        for word, value in [(1, 16), (2, 41), (2, 0x2e01), (3, 44),
                            (3, 48), (4, 0), (4, 0x3e01), (2, 45)]:
            data = bytearray(good)
            struct.pack_into('<H', data, word * 2, value)
            bad.append(bytes(data))
        for data in bad:
            with self.subTest(length=len(data), header=data[:16].hex()):
                with self.assertRaises(ValueError):
                    inspect_bytes(data, 'AL5_W.obj')

    def test_unselected_controller_or_object_format_rejected(self):
        for name in ('E54_W.obj', 'AL5_W.bix', 'AL5_W.obj.exe'):
            with self.assertRaises(ValueError):
                inspect_bytes(fixture(), name)


if __name__ == '__main__':
    unittest.main()
