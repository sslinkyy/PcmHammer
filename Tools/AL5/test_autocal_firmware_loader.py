"""Native-layout boundary tests with inert synthetic byte strings only."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import inspect_autocal_firmware_loader as tool


def pack(*payloads):
    return b''.join(len(p).to_bytes(4, 'little') + p for p in payloads)


class FirmwareLoaderTests(unittest.TestCase):
    def test_two_region_branch_offsets_do_not_include_file_lengths(self):
        result = tool.program_layout(pack(b'ab', b'xyz'))
        self.assertEqual(10, result['native_branch_value'])
        self.assertEqual([4, 10], [r['payload_file_offset'] for r in result['regions']])
        self.assertEqual([0, 2], [r['concatenated_buffer_offset'] for r in result['regions']])
        self.assertEqual(5, result['concatenated_payload_bytes'])
        self.assertFalse(result['firmware_contents_validated'])
        self.assertEqual([], result['would_send'])

    def test_optional_middle_exact_value_and_maximum_native_extent(self):
        result = tool.program_layout(pack(bytes(0x20000), bytes(0x8000), bytes(0x40000)))
        self.assertEqual(14, result['native_branch_value'])
        self.assertEqual(0x68000, result['concatenated_payload_bytes'])
        self.assertEqual([0, 0x20000, 0x28000], [r['concatenated_buffer_offset'] for r in result['regions']])
        with self.assertRaisesRegex(ValueError, 'following final'):
            tool.program_layout(pack(b'x', bytes(0x8000)))
        with self.assertRaisesRegex(ValueError, 'following final'):
            tool.program_layout(pack(b'x', bytes(0x7fff), b'z'))

    def test_truncated_zero_and_extra_input_are_not_native_success(self):
        for raw in (pack(b'x'), pack(b'x', b'y')[:-1], pack(b'x', b'y') + b'x',
                    pack(b'x', b'y', b'z', b'q'), pack(b'', b'y'), pack(b'x', b'')):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                tool.program_layout(raw)

    def test_size_guards_reject_before_any_native_execution(self):
        for raw in (pack(bytes(0x20001), b'y'), pack(b'x', bytes(0x40001)),
                    bytes(0x6800D), bytearray(pack(b'x', b'y'))):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                tool.program_layout(raw)

    def test_wrong_native_identity_does_not_launch_disassembler(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'unrelated.exe'; path.write_bytes(b'unrelated')
            with patch.object(tool.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'identities'):
                    tool.inspect(path, path, directory)
                run.assert_not_called()

    def test_existing_input_as_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'evidence'; path.write_bytes(b'preserve')
            with patch.object(tool, 'inspect') as inspect:
                with self.assertRaises(FileExistsError):
                    tool.main(['--hapi', str(path), '--dumpbin', str(path),
                               '--firmware-root', directory, '--output', str(path)])
                inspect.assert_not_called()
            self.assertEqual(b'preserve', path.read_bytes())


if __name__ == '__main__':
    unittest.main()
