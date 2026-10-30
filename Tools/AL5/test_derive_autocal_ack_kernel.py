"""Fixed-file derivation, independent decode and evidence-only CLI regressions."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import derive_autocal_ack_kernel as tool


@unittest.skipUnless(tool.KERNEL_PATH.is_file(), 'Private pinned kernel is not distributed with source')
class AckKernelDerivationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = tool.KERNEL_PATH.read_bytes()

    def test_exact_asset_copy_ownership_and_only_fixed_spans_change(self):
        caller = bytearray(self.original)
        effective, result = tool.derive(caller)
        self.assertEqual(self.original, caller)
        self.assertEqual(2027, len(effective))
        self.assertEqual(tool.ACK_SHA, tool.sha(effective))
        self.assertEqual(25, result['changed_bytes_vs_original'])
        self.assertEqual(24, result['changed_bytes_vs_zero_only_control'])
        allowed = {i for o, before, after in tool.PATCHES for i in range(o, o + len(before))}
        self.assertTrue(all(a == b or i in allowed for i, (a, b) in enumerate(zip(self.original, effective))))
        self.assertEqual(bytes.fromhex('0000'), effective[0x792:0x794])
        self.assertEqual(bytes.fromhex('4e71'), effective[0x7A8:0x7AA])
        self.assertEqual(self.original[0x7B4:], effective[0x7B4:])
        self.assertEqual(0xFF98EB, result['message_buffer_address_unchanged'])
        caller[0] ^= 1
        self.assertEqual(tool.ACK_SHA, tool.sha(effective))

    def test_no_alternative_input_or_already_modified_asset_is_accepted(self):
        effective, _ = tool.derive(self.original)
        changed = bytearray(self.original); changed[0x7AE] = 0
        for source in (b'', self.original[:-1], self.original + b'\0', changed, effective):
            with self.subTest(length=len(source)), self.assertRaisesRegex(ValueError, 'Source kernel'):
                tool.derive(source)
        for index in (0x90, 0x794, 0x7AA, 0x7AE, 0x7EA):
            changed = bytearray(self.original); changed[index] ^= 1
            with self.subTest(index=index), self.assertRaises(ValueError): tool.derive(changed)

    def test_branch_pc_bases_and_ack_extent_reconstructed_independently(self):
        effective, result = tool.derive(self.original)
        targets = result['derived_targets']
        self.assertEqual(0xFF9894, targets['mode35_dispatch'])
        self.assertEqual(0xFF98A2, targets['ack_data'])
        self.assertEqual(0xFF96E8, targets['existing_vpw_send'])
        self.assertEqual(0xFF95DA, targets['original_mode35'])
        self.assertEqual(bytes.fromhex('6df010750154'), effective[0x7A2:0x7A8])
        self.assertEqual(6, effective[0x799])
        for index in (0x92, 0x796, 0x799, 0x79C, 0x7A0, 0x7A2, 0x7A8):
            corrupt = bytearray(effective); corrupt[index] ^= 1
            with self.subTest(index=index), self.assertRaises(ValueError): tool.validate_effective(corrupt)

    def test_old_context_guard_is_distinct_from_asset_pin(self):
        wrong = list(tool.PATCHES); offset, old, new = wrong[0]
        wrong[0] = (offset, b'\0' * len(old), new)
        with patch.object(tool, 'PATCHES', tuple(wrong)):
            with self.assertRaisesRegex(ValueError, 'old bytes'): tool.derive(self.original)

    def test_exact_upload_extents_and_recomputed_checksums(self):
        effective, result = tool.derive(self.original)
        copy, execute = tool.upload(effective, True), tool.upload(effective, False)
        self.assertEqual([279, 1772], [len(copy), len(execute)])
        self.assertEqual(bytes.fromhex('6d10f03600010bff97e0'), copy[:10])
        self.assertEqual(bytes.fromhex('6d10f0368006e0ff9100'), execute[:10])
        self.assertEqual(effective, execute[10:-2] + copy[10:-2])
        for wire, metadata in zip((copy, execute), result['effective_ram_messages']):
            self.assertEqual(sum(wire[4:-2]) & 0xFFFF, int.from_bytes(wire[-2:], 'big'))
            self.assertEqual(tool.sha(wire), metadata['sha256'])
        self.assertEqual(self.original[0x94:1760], effective[0x94:1760])
        self.assertFalse(result['binary_output_supported'])

    def test_independent_disassembly_excludes_alignment_and_metadata(self):
        effective, _ = tool.derive(self.original)
        audit = tool.decode_audit(self.original, effective, tool.CAPSTONE_ROOT)
        self.assertEqual(1938, audit['original_executable_bytes'])
        self.assertEqual(516, audit['decoded_instructions'])
        self.assertEqual(0, audit['undecoded_words'])
        self.assertEqual([], audit['literal_address_references_to_metadata'])
        self.assertEqual(['lea.l', 'moveq', 'bsr.w', 'bra.w'], [i['mnemonic'] for i in audit['stub']])
        self.assertEqual('0000', audit['alignment_bytes_excluded_from_instruction_scan']['hex'])

    def test_saved_trace_has_128_ack_then_data_pairs_and_pinned_opcode_windows(self):
        audit = tool.trace_audit(tool.TRACE_PATH)
        self.assertEqual(128, audit['ordered_request_ack_data_triplets'])
        self.assertEqual(0, audit['host_commands_between_ack_and_data'])
        self.assertEqual([158, 160, 165], audit['first_triplet_record_ordinals'])
        self.assertEqual([1174, 1176, 1181], audit['last_triplet_record_ordinals'])
        self.assertEqual(4, len(audit['checked_instruction_windows']))
        self.assertEqual('unknown', audit['firmware_requires_ack'])
        wrong = list(tool.EFILIVE_WINDOWS); name, address, _, instruction = wrong[0]
        wrong[0] = (name, address, '00000000', instruction)
        with patch.object(tool, 'EFILIVE_WINDOWS', tuple(wrong)):
            with self.assertRaisesRegex(ValueError, 'instruction window'): tool.trace_audit(tool.TRACE_PATH)

    def test_report_provenance_and_cli_never_export_an_image_or_overwrite_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'report.json'
            with contextlib.redirect_stdout(io.StringIO()):
                tool.main(['--output', str(output)])
            result = json.loads(output.read_text())
            self.assertFalse(result['binary_exported'])
            self.assertFalse(result['kernel_executed'])
            self.assertFalse(result['flash_programming_enabled'])
            self.assertIn('pcmhacking.net', result['attribution_preserved'])
            self.assertEqual(4, len(result['source_provenance']))
            self.assertEqual([output], list(Path(directory).iterdir()))
            self.assertNotIn(self.original.hex(), output.read_text())
            self.assertEqual(self.original, tool.KERNEL_PATH.read_bytes())
            for item in result['implementation']:
                self.assertEqual(item['sha256'], tool.sha(Path(item['path']).read_bytes()))
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                tool.main(['--output', str(output)])


if __name__ == '__main__':
    unittest.main()
