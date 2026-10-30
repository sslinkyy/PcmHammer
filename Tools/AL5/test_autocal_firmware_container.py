"""Offline EFW framing/opacity/provenance boundary tests."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import inspect_autocal_firmware_container as tool


def framed(*regions):
    return b''.join(len(payload).to_bytes(4, 'little') + payload for payload in regions)


class FirmwareContainerTests(unittest.TestCase):
    def test_exact_positive_le_lengths_preserve_offsets_and_complete_coverage(self):
        source = framed(bytes(256), bytes(range(256)) * 2)
        result = tool.analyze_bytes(source)
        self.assertEqual(2, result['region_count'])
        self.assertTrue(result['framing_covers_complete_file'])
        first, second = result['regions']
        self.assertEqual((0, 4, 260), (first['length_field_file_offset'], first['payload_file_offset'], first['end_file_offset_exclusive']))
        self.assertEqual((260, 264, len(source)), (second['length_field_file_offset'], second['payload_file_offset'], second['end_file_offset_exclusive']))
        self.assertEqual('00010000', first['length_field_le32_hex'])
        self.assertEqual(tool.sha256(bytes(range(256)) * 2), second['payload_sha256'])

    def test_malformed_length_never_resynchronizes_or_allocates_declared_extent(self):
        for raw in (b'', b'\x01\x00\x00', bytes(4), b'\xff' * 4,
                    framed(b'ab') + b'x', (256).to_bytes(4, 'big') + bytes(256)):
            with self.subTest(raw=raw[:8].hex()), self.assertRaises(ValueError):
                tool.analyze_bytes(raw)

    def test_entropy_and_signatures_never_claim_codec_or_architecture(self):
        result = tool.analyze_bytes(framed(bytes(range(256)) * 3))['regions'][0]
        self.assertEqual(8., result['byte_entropy_bits'])
        self.assertEqual(256, result['distinct_byte_values'])
        self.assertIsNone(result['instruction_architecture'])
        self.assertIsNone(result['encryption_format'])
        self.assertIsNone(result['compression_format'])
        self.assertEqual(['zlib_header_candidate'], tool.prefix_signatures(b'\x78\x9cnot_a_stream'))
        self.assertEqual(['ELF'], tool.prefix_signatures(b'\x7fELFnot_executable'))

    def test_period_suffix_is_bounded_and_preserves_region_relative_offset(self):
        result = tool.bounded_tail_period(b'prefix!' + b'abcd' * 2000)
        self.assertEqual(4, result['period_bytes'])
        self.assertEqual(4096, result['matched_suffix_bytes'])
        self.assertEqual(8007 - 4096, result['suffix_offset_within_region'])
        self.assertEqual(4096, result['examined_tail_bytes'])
        self.assertIsNone(tool.bounded_tail_period(b'x' * 63))
        self.assertIsNone(tool.bounded_tail_period(b''))

    def test_no_firmware_body_export_or_short_command_pattern_inference(self):
        private = b'private-firmware-payload-not-for-export' + bytes.fromhex('038604866cfef0a1')
        result = tool.analyze_bytes(framed(private * 20))
        rendered = json.dumps(result)
        self.assertNotIn((private * 20).hex(), rendered)
        self.assertIn(tool.sha256(private * 20), rendered)
        self.assertFalse(result['physical_protocol_or_handler_identified'])
        self.assertEqual(32, len(result['regions'][0]['payload_prefix_up_to_16_bytes_hex']))
        self.assertEqual(32, len(result['source_prefix_up_to_16_bytes_hex']))

    def test_comparison_distinguishes_common_prefix_from_equal_regions(self):
        left = framed(b'ABCxxxx', b'tail')
        right = framed(b'ABCyyyyextra')
        result = tool.compare_regions(left, right)
        first = result['regions_compared_by_ordinal'][0]
        self.assertEqual(3, first['common_prefix_bytes'])
        self.assertEqual(3, first['equal_bytes_at_same_region_offset'])
        self.assertEqual(7, first['same_offset_overlap_bytes_examined'])
        self.assertFalse(first['exact_region_bytes_equal'])
        self.assertEqual([1], result['unpaired_left_regions'])
        self.assertFalse(result['same_function_or_memory_mapping_inferred'])
        self.assertTrue(tool.compare_regions(left, left)['regions_compared_by_ordinal'][0]['exact_region_bytes_equal'])

    def test_artifact_identity_and_existing_source_output_fail_before_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / tool.ARTIFACTS['autocal_program'][0]
            source.write_bytes(framed(b'wrong firmware'))
            with patch.object(tool, 'analyze_bytes') as analyze:
                with self.assertRaisesRegex(ValueError, 'Exact installed artifact identity required'):
                    tool.inspect(root)
                analyze.assert_not_called()
            with patch.object(tool, 'inspect') as inspect:
                with self.assertRaises(FileExistsError):
                    tool.main(['--firmware-root', str(root), '--output', str(source)])
                inspect.assert_not_called()
            self.assertEqual(framed(b'wrong firmware'), source.read_bytes())


if __name__ == '__main__':
    unittest.main()
