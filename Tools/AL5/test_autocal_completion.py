"""Count-path regressions are synthetic; they exercise no driver or target."""
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

import inspect_autocal_completion as tool


class CompletionEvidenceTests(unittest.TestCase):
    def test_half_complete_guard_is_distinct_from_all_bytes(self):
        for direction, timeout in [('read', 250), ('write', 1000)]:
            with self.subTest(direction=direction):
                below = tool.count_path(10, timeout, direction, [4])
                half = tool.count_path(10, timeout, direction, [5])
                above = tool.count_path(10, timeout, direction, [9])
                complete = tool.count_path(10, timeout, direction, [10])
                self.assertFalse(below['native_final_count_guard_passes'])
                self.assertTrue(half['native_final_count_guard_passes'])
                self.assertFalse(half['all_requested_bytes_accounted_for'])
                self.assertTrue(above['native_final_count_guard_passes'])
                self.assertFalse(above['all_requested_bytes_accounted_for'])
                self.assertTrue(complete['all_requested_bytes_accounted_for'])
                self.assertFalse(complete['physical_transfer_observed'])

    def test_logical_budgets_and_exact_completion_stop(self):
        for direction, quantum in [('read', 250), ('write', 1000)]:
            for timeout, calls in [(1, 1), (quantum, 1), (quantum + 1, 2), (2 * quantum, 2)]:
                with self.subTest(direction=direction, timeout=timeout):
                    result = tool.count_path(10, timeout, direction, [0] * (calls - 1) + [10])
                    self.assertEqual(calls, result['maximum_driver_calls'])
                    self.assertTrue(result['all_requested_bytes_accounted_for'])
            complete_early = tool.count_path(10, quantum + 1, direction, [10])
            self.assertEqual(1, len(complete_early['steps']))
        partials = tool.count_path(14, 2000, 'write', [5, 9])
        self.assertEqual([5, 14], [s['cumulative_count'] for s in partials['steps']])
        self.assertEqual([9, 0], [s['remaining_count'] for s in partials['steps']])

    def test_incomplete_or_impossible_driver_samples_are_not_invented(self):
        for args in [(10, 500, 'read', [1]), (10, 500, 'read', [10, 0]),
                     (10, 250, 'read', [11]), (10, 250, 'read', [-1]),
                     (10, 250, 'read', [True]), (0, 250, 'read', [0]),
                     (10, 0, 'read', [10]), (10, 250, 'unknown', [10])]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                tool.count_path(*args)

    def test_changed_source_rejects_mixed_static_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hapi, dumpbin = root / 'hapi', root / 'dumpbin'
            hapi.write_bytes(b'a' * 256); dumpbin.write_bytes(b'disassembler')
            pe = types.SimpleNamespace(OPTIONAL_HEADER=types.SimpleNamespace(ImageBase=0x400000),
                sections=[types.SimpleNamespace(VirtualAddress=0, SizeOfRawData=256, PointerToRawData=0)])
            def disassemble(*_args, **_kwargs):
                hapi.write_bytes(b'changed')
                return types.SimpleNamespace(stdout='  00400010: nop\n')
            with (patch.object(tool, 'HAPI_SHA256', tool.digest(hapi.read_bytes())),
                  patch.object(tool, 'PRIOR', ()),
                  patch.object(tool, 'WINDOWS', (('fixture', 0x400010, 0x400011),)),
                  patch.object(tool.pefile, 'PE', return_value=pe),
                  patch.object(tool.subprocess, 'run', side_effect=disassemble)):
                with self.assertRaisesRegex(ValueError, 'changed during collection'):
                    tool.inspect(hapi, dumpbin, root)


if __name__ == '__main__':
    unittest.main()
