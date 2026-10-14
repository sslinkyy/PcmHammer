"""Malformed PE/descriptor and identity regressions; no installed app required."""
import struct
import unittest
from inspect_pccs_methods import inspect_bytes


def fixture():
    data = bytearray(1024)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HH', data, 0x84, 0x14c, 1)
    struct.pack_into('<H', data, 0x94, 0xe0)
    struct.pack_into('<H', data, 0x98, 0x10b)
    struct.pack_into('<I', data, 0x98+28, 0x400000)
    section = 0x98+0xe0
    struct.pack_into('<IIII', data, section+8, 0x100, 0x1000, 0x100, 0x200)
    struct.pack_into('<I', data, section+36, 0x20000000)
    name = b'EraseFlash'
    descriptor = struct.pack('<HIB', 7+len(name), 0x401020, len(name))+name
    data[0x300:0x300+len(descriptor)] = descriptor
    return data


class PccsMethodTests(unittest.TestCase):
    def test_pointer_mapping_and_closed_gates(self):
        result = inspect_bytes(fixture(), ['EraseFlash'])
        self.assertEqual(len(result['candidates']), 1)
        self.assertEqual(result['candidates'][0]['code_file_offset'], 0x220)
        self.assertFalse(result['candidates'][0]['provider_function_verified'])
        self.assertFalse(result['live_write_enabled'])
        self.assertFalse(result['ready_to_flash'])
        self.assertIsNone(result['controller_compatibility'])
        self.assertEqual(result['would_send'], [])

    def test_unmapped_pointer_does_not_become_function(self):
        raw = fixture(); struct.pack_into('<I', raw, 0x302, 0x500000)
        result = inspect_bytes(raw, ['EraseFlash'])
        self.assertFalse(result['candidates'])
        self.assertEqual(result['rejected_match_counts']['address_unmapped_or_ambiguous'], 1)

    def test_truncated_descriptor_rejected(self):
        raw = fixture(); struct.pack_into('<H', raw, 0x300, 0xffff)
        self.assertFalse(inspect_bytes(raw, ['EraseFlash'])['candidates'])

    def test_plain_resource_name_not_promoted(self):
        raw = fixture(); raw[0x306] = 0
        self.assertFalse(inspect_bytes(raw, ['EraseFlash'])['candidates'])

    def test_ambiguous_executable_mapping_rejected(self):
        raw = fixture(); struct.pack_into('<H', raw, 0x86, 2)
        section = 0x178
        raw[section+40:section+80] = raw[section:section+40]
        self.assertFalse(inspect_bytes(raw, ['EraseFlash'])['candidates'])

    def test_invalid_and_truncated_pe(self):
        for raw in [b'', bytes(fixture()[:0x190]), b'MZ'+bytes(62)]:
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                inspect_bytes(raw)

    def test_raw_section_out_of_bounds_rejected(self):
        raw = fixture(); struct.pack_into('<I', raw, 0x178+20, 0x10000)
        with self.assertRaisesRegex(ValueError, 'beyond file'):
            inspect_bytes(raw)

    def test_native_emulator_rejects_other_build_before_loading_engine(self):
        from emulate_pccs_erase import run
        with self.assertRaisesRegex(ValueError, 'pin changed'):
            run(bytes(fixture()))

    def test_repeated_queries_preserve_caller_input_without_duplicate_candidates(self):
        result = inspect_bytes(fixture(), ['EraseFlash', 'EraseFlash'])
        self.assertEqual(result['requested_names'], ['EraseFlash', 'EraseFlash'])
        self.assertEqual(len(result['candidates']), 1)


if __name__ == '__main__': unittest.main()
