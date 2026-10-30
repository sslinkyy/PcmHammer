"""Offline bounds/provenance regressions for the native backend/init collector."""
from pathlib import Path
import struct
import tempfile
import types
import unittest
from unittest.mock import patch

import inspect_autocal_backend_init as tool


class BackendInitEvidenceTests(unittest.TestCase):
    def test_two_stage_selector_resolves_data_not_linear_disassembly(self):
        index = bytes(29)
        first = struct.pack('<I', 0xA542DC)
        second = bytearray(27 * 4)
        struct.pack_into('<I', second, (0x18 - 3) * 4, 0xA548D1)
        actual = tool.resolve_selector(0x18, index, first, second)
        self.assertEqual('0xa548d1', actual['final_target'])
        self.assertEqual(21, actual['second_index'])
        # A different raw target must remain different, not silently hardcode the finding.
        struct.pack_into('<I', second, (0x18 - 3) * 4, 0xA54900)
        self.assertEqual('0xa54900', tool.resolve_selector(0x18, index, first, second)['final_target'])

    def test_dispatch_rejects_incomplete_outside_or_wrong_route(self):
        good = (bytes(29), struct.pack('<I', 0xA542DC), bytes(27 * 4))
        for selector in [-1, 0, 2, 29, True, '24']:
            with self.subTest(selector=selector), self.assertRaises(ValueError):
                tool.resolve_selector(selector, *good)
        bad_tables = [
            (bytes(28), good[1], good[2]), (good[0], b'', good[2]),
            (good[0], good[1], bytes(26 * 4)),
            (bytes([1] * 29), good[1], good[2]),
            (good[0], struct.pack('<I', 0xA548D1), good[2]),
        ]
        for tables in bad_tables:
            with self.subTest(tables=tables), self.assertRaises(ValueError):
                tool.resolve_selector(0x18, *tables)

    def test_exception_descriptor_preserves_handler_and_signed_jump(self):
        va = 0xA16B6C
        raw = b'\xE9' + struct.pack('<iIII', 0x40B700 - va - 5, 1, 0x425398, 0xA16B7D)
        decoded = tool.decode_exception_descriptor(raw, va)
        self.assertEqual('0x40b700', decoded['runtime_jump_target'])
        self.assertEqual('0xa16b7d', decoded['handler_va'])
        for invalid in [raw[:-1], raw + b'\0', b'\x90' + raw[1:], raw[:5] + struct.pack('<I', 2) + raw[9:]]:
            with self.subTest(raw=invalid), self.assertRaises(ValueError):
                tool.decode_exception_descriptor(invalid, va)

    def test_pe_ranges_reject_virtual_only_cross_section_and_truncated_data(self):
        image = object.__new__(tool.Image)
        image.base, image.raw = 0x400000, bytes(range(32))
        image.pe = types.SimpleNamespace(sections=[types.SimpleNamespace(
            VirtualAddress=0x1000, SizeOfRawData=16, PointerToRawData=8, Name=b'.text\0')])
        where, raw = image.location(0x401008, 8)
        self.assertEqual(bytes(range(16, 24)), raw)
        self.assertEqual(16, where['file_offset'])
        for start, count in [(0x40100F, 2), (0x401010, 1), (0x400FFF, 1), (0x401000, 0), (0x401000, True)]:
            with self.subTest(start=start, count=count), self.assertRaises(ValueError):
                image.location(start, count)
        image.raw = bytes(10)
        with self.assertRaisesRegex(ValueError, 'Truncated'):
            image.location(0x401000, 8)

    def test_wrong_binary_identity_fails_before_pe_or_disassembler(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'different.exe'
            path.write_bytes(b'not the pinned binary')
            with patch.object(tool.pefile, 'PE') as pe, patch.object(tool.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'identity differs'):
                    tool.Image(path, tool.HAPI_SHA256)
                pe.assert_not_called()
                run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
