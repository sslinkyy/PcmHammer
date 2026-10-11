"""Validator input selection, provenance and closed-gate regressions."""
import unittest
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from al5_segment import sha256
from checksum import crc16
from validate_vm_buffers import inspect_buffers


class BufferValidationTests(unittest.TestCase):
    def inspect(self, code, data):
        return inspect_buffers(code, data, sha256(code), sha256(data))

    def fixture(self):
        code = bytearray(range(80))
        data = bytes(range(128))
        crc = crc16(data, crc16(code[64:], crc16(code[2:48], 0xB27D)))
        code[:2] = crc.to_bytes(2, 'little')
        return code, data

    def test_independent_crc_vectors_and_seed_chaining(self):
        self.assertEqual(0xBB3D, crc16(b'123456789'))
        self.assertEqual(0x4B37, crc16(b'123456789', 0xFFFF))
        self.assertEqual(crc16(b'123456789', 0xB27D),
                         crc16(b'56789', crc16(b'1234', 0xB27D)))

    def test_matching_supplied_crc_does_not_validate_object_or_open_gate(self):
        code, data = self.fixture()
        result = self.inspect(code, data)
        self.assertTrue(result['supplied_buffer_crc_matches'])
        self.assertEqual([(2, 48), (64, 80), (0, 128)],
                         [(s['offset'], s['end_exclusive']) for s in result['stages']])
        for key in ('buffer_transform_provenance_verified', 'object_validation_verified',
                    'object_contents_decoded', 'ready_to_flash', 'live_write_enabled'):
            self.assertFalse(result[key])
        self.assertEqual([], result['would_send'])
        self.assertIsNone(result['erase_scope'])

    def test_covered_corruption_detected_and_excluded_interval_preserved(self):
        code, data = self.fixture()
        for offset in (0, 2, 47, 64, 79):
            changed = bytearray(code)
            changed[offset] ^= 1
            self.assertFalse(self.inspect(changed, data)['supplied_buffer_crc_matches'])
        changed = bytearray(code)
        changed[48:64] = bytes(16)
        self.assertTrue(self.inspect(changed, data)['supplied_buffer_crc_matches'])
        self.assertNotEqual(sha256(code), self.inspect(changed, data)['code_sha256'])
        self.assertFalse(self.inspect(code, data[:-1] + b'\0')['supplied_buffer_crc_matches'])

    def test_capacity_and_identity_rejections(self):
        code, data = self.fixture()
        for bad_code, bad_data in [(bytes(63), data), (bytes(0x2E01), data),
                                   (code, b''), (code, bytes(0x3E01))]:
            with self.assertRaises(ValueError):
                self.inspect(bad_code, bad_data)
        for expected in ('x', '0' * 64):
            with self.assertRaises(ValueError):
                inspect_buffers(code, data, expected, sha256(data))

    def test_cli_preserves_inputs_and_existing_outputs(self):
        code, data = self.fixture()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            code_path, data_path, output = root/'code.bin', root/'data.bin', root/'report.json'
            code_path.write_bytes(code)
            data_path.write_bytes(data)
            args = [sys.executable, str(Path(__file__).with_name('validate_vm_buffers.py')),
                    '--code', str(code_path), '--data', str(data_path),
                    '--expected-code-sha256', sha256(code), '--expected-data-sha256', sha256(data),
                    '--output', str(output)]
            self.assertEqual(0, subprocess.run(args, capture_output=True).returncode)
            report = json.loads(output.read_text())
            self.assertTrue(report['supplied_buffer_crc_matches'])
            saved = output.read_bytes()
            self.assertNotEqual(0, subprocess.run(args, capture_output=True).returncode)
            self.assertEqual(saved, output.read_bytes())
            self.assertNotEqual(0, subprocess.run(args[:-1]+[str(code_path)], capture_output=True).returncode)
            self.assertEqual(bytes(code), code_path.read_bytes())
            self.assertEqual(data, data_path.read_bytes())

    def test_planner_pins_callback_evidence_without_enabling_write(self):
        from test_offline import fixture
        from write_plan import plan
        data = fixture()
        result = plan(data, data, sha256(data), 'AL5', 15184109)
        assessment = result['existing_trace_assessment']['host_callback_assessment']
        root = Path(__file__).resolve().parents[2]
        for role in ('evidence', 'implementation'):
            self.assertEqual(sha256((root/assessment[role]).read_bytes()), assessment[role+'_sha256'])
        self.assertFalse(assessment['object_validation_verified'])
        self.assertFalse(result['live_write_enabled'])
        self.assertEqual([], result['program_packets'])


if __name__ == '__main__':
    unittest.main()
