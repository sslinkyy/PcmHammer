"""Offline speed-helper condition and receive-drain boundaries only."""
import unittest
from pathlib import Path
import tempfile
from unittest.mock import patch

import inspect_autocal_speed_vm as tool


class SpeedVmTests(unittest.TestCase):
    def test_two_gates_are_independent_and_do_not_qualify_bus(self):
        for word, byte, expected in ((0, 1, False), (0x10, 1, True), (0x10, 0, False),
                                     (0x10, 2, False), (0xFFFF, 1, True), (0x20, 1, False)):
            with self.subTest(word=word, byte=byte):
                result = tool.gate_from_supplied_values(word, byte)
                self.assertEqual(expected, result['a0_a1_send_path_selected'])
                self.assertFalse(result['physical_speed_proven'])
                self.assertFalse(result['would_send'])

    def test_incomplete_outcomes_do_not_fabricate_completion(self):
        for values in ([], [0], [0] * 19):
            result = tool.drain_from_supplied_receive_flags(values)
            self.assertFalse(result['completed'])
            self.assertFalse(result['purge_callback_requested'])
            self.assertIsNone(result['flags_after_explicit_81_clear'])
            self.assertEqual(len(values), result['receive_calls'])

    def test_error_exits_before_decrement_and_is_explicitly_cleared(self):
        result = tool.drain_from_supplied_receive_flags([0, 0x85, 0])
        self.assertEqual(2, result['receive_calls'])
        self.assertEqual(19, result['remaining_counter'])
        self.assertEqual('receive_flag80_exit', result['exit_reason'])
        self.assertEqual(4, result['flags_after_explicit_81_clear'])
        self.assertFalse(result['payload_acknowledgement_validated'])

    def test_negative_response_flag_does_not_stop_or_validate_drain(self):
        result = tool.drain_from_supplied_receive_flags([1] * 20)
        self.assertEqual('twenty_receive_budget_exhausted', result['exit_reason'])
        self.assertEqual(20, result['receive_calls'])
        self.assertEqual(0x20, result['flags_after_explicit_81_clear'])
        self.assertFalse(result['payload_acknowledgement_validated'])
        self.assertFalse(result['adapter_opened'])

    def test_width_and_budget_constraints_fail_closed(self):
        for pair in ((True, 1), (-1, 1), (0x10000, 1), (0x10, 0x100), (0x10, False)):
            with self.subTest(pair=pair), self.assertRaises(ValueError):
                tool.gate_from_supplied_values(*pair)
        for values in ([0] * 21, [True], [-1], [0x10000], '0'):
            with self.subTest(values=values), self.assertRaises(ValueError):
                tool.drain_from_supplied_receive_flags(values)

    def test_wrong_input_identity_prevents_disassembly(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [root / name for name in ('code.bin', 'data.bin', 'listing.json',
                                             'trace.htx', 'vm.dll', 'hapi.exe', 'dumpbin.exe')]
            for path in paths:
                path.write_bytes(b'unrelated')
            with patch.object(tool.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'Exact pinned input identity required: code'):
                    tool.inspect(*paths, root)
                run.assert_not_called()

    def test_existing_output_or_input_is_preserved_before_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / 'source.bin'
            evidence.write_bytes(b'preserve exact evidence')
            arguments = []
            for name in ('code', 'data', 'listing', 'trace', 'vm', 'hapi', 'dumpbin', 'docs', 'output'):
                arguments.extend(['--' + name, str(evidence)])
            with patch.object(tool, 'inspect') as inspect:
                with self.assertRaises(FileExistsError):
                    tool.main(arguments)
                inspect.assert_not_called()
            self.assertEqual(b'preserve exact evidence', evidence.read_bytes())


if __name__ == '__main__':
    unittest.main()
