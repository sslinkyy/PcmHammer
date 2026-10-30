"""Collector identity regressions; fake disassembly never executes a target.

The synthetic mapped bytes exercise the collector's actual input boundaries.
They establish rejection of changed evidence, not real HAPI behavior.
"""
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import inspect_autocal_transport as collector


class AutoCalStaticInputStabilityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='autocal_static_identity_')
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.hapi = root / 'synthetic-hapi.bin'
        self.dumpbin = root / 'synthetic-disassembler.bin'
        # Keep the production collector's actual addresses; model only the PE
        # mapping, which is unrelated to the changed-file regression.
        base = 0x6E0000
        source = bytearray(0xAD2CE4 + 512 - base)
        table = struct.pack('<256H', *collector.reflected_table(0xA001))
        source[0xAD2CE4 - base:0xAD2CE4 - base + len(table)] = table
        for va, value in ((0x6EC4B8, 'ftd2xx.dll'), (0x6EC66C, 'FT_Read'),
                          (0x6EC67C, 'FT_Write'), (0x6EC644, 'FT_OpenEx')):
            encoded = (value + '\0').encode('utf-16le')
            source[va - base:va - base + len(encoded)] = encoded
        self.source = bytes(source)
        self.tool_bytes = b'synthetic disassembler identity'
        self.hapi.write_bytes(self.source)
        self.dumpbin.write_bytes(self.tool_bytes)
        self.pe = SimpleNamespace(
            OPTIONAL_HEADER=SimpleNamespace(ImageBase=base),
            sections=[SimpleNamespace(VirtualAddress=0, PointerToRawData=0,
                                      SizeOfRawData=len(source), Name=b'.test\0')])

    def collect(self, change=None):
        calls = []

        def disassemble(command, **kwargs):
            calls.append(command)
            if len(calls) == 2 and change is not None:
                change()
            start = int(command[2].split(':', 1)[1].split(',')[0], 16)
            return SimpleNamespace(stdout=f'  {start:08X}: nop\n')

        with patch.object(collector, 'HAPI_SHA256', collector.digest(self.source)), \
                patch.object(collector.pefile, 'PE', return_value=self.pe), \
                patch.object(collector.subprocess, 'run', side_effect=disassemble):
            return collector.inspect(self.hapi, self.dumpbin)

    def test_stable_inputs_preserve_the_verified_snapshot_hashes(self):
        result = self.collect()
        self.assertEqual(collector.digest(self.source), result['source']['sha256'])
        self.assertEqual(collector.digest(self.tool_bytes), result['disassembler']['sha256'])
        self.assertEqual(len(collector.WINDOWS), len(result['disassembly_windows']))
        self.assertFalse(result['target_executed'])
        self.assertFalse(result['adapter_opened'])

    def test_hapi_changed_between_disassembler_calls_is_rejected(self):
        def change():
            modified = bytearray(self.source)
            modified[0xA16DE4 - self.pe.OPTIONAL_HEADER.ImageBase] ^= 0x90
            self.hapi.write_bytes(modified)

        with self.assertRaisesRegex(ValueError, 'HAPI source changed during collection'):
            self.collect(change)

    def test_disassembler_changed_between_calls_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Disassembler changed during collection'):
            self.collect(lambda: self.dumpbin.write_bytes(b'different tool identity'))

    def test_wrong_hapi_identity_is_rejected_before_disassembly(self):
        self.hapi.write_bytes(b'unreviewed input')
        with patch.object(collector.subprocess, 'run') as disassemble:
            with self.assertRaisesRegex(ValueError, 'HAPI identity differs'):
                collector.inspect(self.hapi, self.dumpbin)
            disassemble.assert_not_called()


if __name__ == '__main__':
    unittest.main()
