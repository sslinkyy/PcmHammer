"""Synthetic file-only setup/reconstruction boundaries; no callbacks execute."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from checksum import crc16
import inspect_autocal_vm_setup as tool


def record(command, payload, channel=1):
    prefix = b'\x01\x54' if channel == 1 else b'\x01\x52'
    raw = prefix + command.to_bytes(2, 'little') + bytes(6) + len(payload).to_bytes(2, 'little') + payload
    raw += crc16(raw, 0).to_bytes(2, 'little') + (b'\x19' if channel == 2 else b'')
    return {'offset': 1024, 'kind': 0x42, 'channel': channel, 'payload': raw}


def transforms():
    return [record(0x8414, bytes((12, 0)) + bytes(32)), record(0x8414, b'\x01', 2),
            record(0x8415, b'abcd'), record(0x8415, bytes(4), 2)]


class VmSetupTests(unittest.TestCase):
    def test_recorded_setup_payload_forms_without_success_claim(self):
        self.assertEqual([{'command_le16': 0x8604, 'payload_hex': '000000000000', 'callback_argument4': 1000}],
                         tool.setup_payload_observations(0, 0, 0, 0))
        result = tool.setup_payload_observations(1, 1500, 0, 16)
        self.assertEqual(['0100f401', '010010000000'], [x['payload_hex'] for x in result])
        self.assertEqual([100, 1000], [x['callback_argument4'] for x in result])
        self.assertEqual('0601ffffffff', tool.setup_payload_observations(6, 0, 1, 0xFFFFFFFF)[0]['payload_hex'])
        self.assertEqual(2000, tool.setup_payload_observations(6, 0, 1, 0)[0]['callback_argument4'])
        self.assertEqual('010000000000', tool.setup_payload_observations(1, 0, 0x100, 0)[0]['payload_hex'])
        self.assertEqual('01ff00000000', tool.setup_payload_observations(1, 0, 0xFFFFFFFF, 0)[0]['payload_hex'])

    def test_interval_word_boundaries_and_explicit_widths(self):
        for value, payload in [(1, '00000100'), (999, '0000e703'), (1000, '01000000'), (65535, '41001702')]:
            self.assertEqual(payload, tool.setup_payload_observations(1, value, 0, 0)[0]['payload_hex'])
        for values in [(256, 1, 0, 0), (1, 65536, 0, 0), (1, -1, 0, 0),
                       (1, 0, 0x100000000, 0), (1, 0, 0, 0x100000000), (True, 0, 0, 0)]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                tool.setup_payload_observations(*values)

    def test_cleanup_words_narrow_to_four_bytes_without_status_claim(self):
        self.assertEqual('00010000', tool.cleanup_payload_observations([0, 1, 0, 0])[0]['payload_hex'])
        self.assertEqual('01010000', tool.cleanup_payload_observations([1, 1, 0, 0])[0]['payload_hex'])
        self.assertEqual('00ff0203', tool.cleanup_payload_observations([256, 0xFFFFFFFF, 258, 259])[0]['payload_hex'])
        for values in ([], [1, 2, 3], [1, 2, 3, -1], [1, 2, 3, 0x100000000], [1, 2, 3, True]):
            with self.subTest(values=values), self.assertRaises(ValueError):
                tool.cleanup_payload_observations(values)

    def test_strict_replay_association_and_failure_evidence(self):
        sections = [('code', 12, 0, 4)]
        buffers, stages = tool.replay_sections(transforms(), b'abcd', sections)
        self.assertEqual([4], [len(b) for b in buffers])
        self.assertEqual([0x8414, 0x8415], [s['command_le16'] for s in stages])
        self.assertEqual(tool.sha256(b'abcd'), stages[1]['tx_sha256'])
        cases = []
        wrong_source = transforms(); wrong_source[2] = record(0x8415, b'ABCD'); cases.append(wrong_source)
        wrong_status = transforms(); wrong_status[1] = record(0x8414, b'\x00', 2); cases.append(wrong_status)
        wrong_order = transforms(); wrong_order[3] = record(0x8415, bytes(4)); cases.append(wrong_order)
        wrong_size = transforms(); wrong_size[3] = record(0x8415, bytes(8), 2); cases.append(wrong_size)
        bad_crc = transforms(); raw = bytearray(bad_crc[3]['payload']); raw[-2] ^= 1; bad_crc[3]['payload'] = bytes(raw); cases.append(bad_crc)
        cases.extend([transforms()[:-1], transforms() + transforms(), transforms()[2:]])
        for index, rows in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ValueError):
                tool.replay_sections(rows, b'abcd', sections)

    def test_wrong_artifacts_rejected_before_disassembler(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trace, obj, vm = root / 'saved.htx', root / 'E54_R.obj', root / 'vm.dll'
            trace.write_bytes(b'unrelated'); obj.write_bytes(bytes(32)); vm.write_bytes(b'vm')
            with patch.object(tool.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'Exact E54'):
                    tool.inspect(trace, obj, vm, root / 'missing_dumpbin', root)
                run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
