"""Supplied-state cleanup branches and offline evidence preservation."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import inspect_autocal_cleanup_vm as tool


class CleanupVmTests(unittest.TestCase):
    def test_normal_success_clears_error_and_selects_common_cleanup(self):
        result = tool.cleanup_route('normal', 0x536, 0x31, 1, 0x123)
        self.assertEqual(0, result['status_word'])
        self.assertTrue(result['shared_cleanup_selected'])
        self.assertFalse(result['hardware_reset_proven'])
        self.assertFalse(result['would_send'])

    def test_first_script_error_preserves_or_encodes_negative_status(self):
        self.assertEqual(0x536, tool.cleanup_route('script_error', 0x536)['status_word'])
        self.assertEqual(0x331, tool.cleanup_route('script_error', 0x536, 0x31)['status_word'])
        self.assertEqual(0x2FF, tool.cleanup_route('script_error', 0x536, 0xFFFF)['status_word'])
        self.assertEqual(1, tool.cleanup_route('script_error')['entered_byte_after_gate'])

    def test_reentered_error_returns_cached_status_without_common_cleanup(self):
        result = tool.cleanup_route('script_error', 0x536, 0x31, 1, 0x222)
        self.assertFalse(result['shared_cleanup_selected'])
        self.assertEqual(0x222, result['status_word'])
        self.assertFalse(result['existing_pending_frames_unwound'])

    def test_host_error_entry_and_bailout_are_distinct(self):
        direct = tool.cleanup_route('host_error_entry', 0x536, entered_byte=1)
        self.assertTrue(direct['shared_cleanup_selected'])
        self.assertEqual(0x536, direct['status_word'])
        abort = tool.cleanup_route('host_bailout')
        self.assertFalse(abort['shared_cleanup_selected'])
        self.assertTrue(abort['direct_host_zero_setup_requested'])
        self.assertEqual(0x508, abort['status_word'])

    def test_matching_negative_reply_ends_exchange_without_positive_ack(self):
        result = tool.classify_3c55_receive(1, bytes.fromhex('6cf0107f3c5531'))
        self.assertEqual('return_with_negative_flag', result['next_branch'])
        self.assertFalse(result['matching_positive_service_pid'])
        self.assertFalse(result['controller_acknowledgement_verified'])
        self.assertFalse(result['automatic_retry_performed'])
        result = tool.classify_3c55_receive(0x81, bytes.fromhex('6cf0107f3c5531'))
        self.assertEqual('return_with_negative_flag', result['next_branch'])

    def test_transport_error_positive_and_mismatch_branches(self):
        self.assertEqual('decrement_transmit_budget', tool.classify_3c55_receive(0x80, b'')['next_branch'])
        self.assertEqual('return_with_matching_service_pid',
                         tool.classify_3c55_receive(0, bytes.fromhex('6cf0107c55'))['next_branch'])
        self.assertEqual('decrement_receive_budget',
                         tool.classify_3c55_receive(0, bytes.fromhex('6cf0107c54'))['next_branch'])
        self.assertEqual('decrement_receive_budget',
                         tool.classify_3c55_receive(1, bytes.fromhex('6cf0107f27'))['next_branch'])

    def test_invalid_or_unavailable_state_fails_closed(self):
        for entry, kwargs in [('other', {}), ('normal', {'error_word': -1}),
                              ('normal', {'negative_word': 65536}), ('normal', {'entered_byte': True})]:
            with self.subTest(entry=entry, kwargs=kwargs), self.assertRaises(ValueError):
                tool.cleanup_route(entry, **kwargs)
        for flags, payload in ((True, b''), (65536, b''), (1, b'1234'), (0, b'1234'), (0, '12345')):
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                tool.classify_3c55_receive(flags, payload)

    def test_existing_source_output_is_preserved_before_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'source.bin'; path.write_bytes(b'original evidence')
            args = []
            for name in ('code', 'data', 'listing', 'trace', 'vm', 'scan', 'dumpbin', 'docs', 'output'):
                args.extend(['--' + name, str(path)])
            with patch.object(tool, 'inspect') as inspect, self.assertRaises(FileExistsError):
                tool.main(args)
            inspect.assert_not_called()
            self.assertEqual(b'original evidence', path.read_bytes())

    def test_wrong_identity_never_launches_disassembly(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'unrelated'; path.write_bytes(b'unrelated')
            with patch.object(tool.subprocess, 'run') as run, self.assertRaisesRegex(ValueError, 'Exact pinned input'):
                tool.inspect(path, path, path, path, path, path, path, directory)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
