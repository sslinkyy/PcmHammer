import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_loader_finalize as finalize


class LoaderFinalizeTests(unittest.TestCase):
    def test_pin_before_context(self):
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            finalize.experiment(b'wrong loader', b'')

    def test_pc_coverage(self):
        for start, end in finalize.RANGES:
            self.assertTrue(finalize.permitted_pc(start, 1))
            self.assertFalse(finalize.permitted_pc(end-1, 2))
        self.assertFalse(finalize.permitted_pc(0xff9236, 1))
        self.assertFalse(finalize.permitted_pc(0xff91d6, 0))
        self.assertFalse(finalize.permitted_pc(0xff903a, 1))

    def test_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', '--loader', 'missing.bin', '--output', str(output)]), patch.object(finalize, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    finalize.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_CAPTURED_LOADER') and importlib.util.find_spec('unicorn'), 'requires pinned loader and Unicorn')
    def test_native_finalization_failures_and_checksum_distinction(self):
        report = finalize.audit(Path(os.environ['AL5_CAPTURED_LOADER']).read_bytes())
        cases = {c['case']: c for c in report['cases']}
        self.assertEqual(len(cases), 8)
        for name, case in cases.items():
            observed = case['observed']
            for field in ('flash_command_instructions_executed', 'mmio_instructions_executed', 'physical_reset_executed'):
                self.assertFalse(observed[field])
            for field in ('physical_marker_programming_proven', 'full_receive_or_session_executed', 'physical_recovery_proven', 'transport_used', 'live_write_enabled', 'ready_to_flash'):
                self.assertFalse(case[field])
            self.assertEqual(case['would_send'], [])
            statuses = [body['status'] for body in observed['status_bodies']]
            if name in ('valid', 'zero_sum_bad_crc'):
                self.assertEqual(statuses, [0x86])
                self.assertEqual(observed['marker_after'], '0x4afc')
                self.assertEqual(observed['stop'], 'before_shared_reset_exit')
                self.assertEqual(observed['stack_delta'], 0)
                self.assertEqual(observed['flash_reset_sequences_skipped'], 1)
            elif name == 'marker_readback_failure':
                self.assertEqual(statuses, [0xf8])
                self.assertEqual(observed['stop'], 'receive_boundary')
                self.assertEqual(observed['stack_delta'], -4)
                self.assertEqual(observed['retained_error_bits'], 0x40)
                self.assertGreater(observed['poll_reads'], 12000)
                self.assertEqual(observed['flash_reset_sequences_skipped'], 1)
            elif name == 'before_marker_command':
                self.assertEqual(statuses, [])
                self.assertEqual(observed['stop'], 'marker_command_boundary')
                self.assertEqual(observed['marker_after'], '0xffff')
            else:
                self.assertEqual(statuses, [0xff])
                self.assertEqual(observed['stop'], 'before_shared_reset_exit')
                self.assertEqual(observed['synthetic_marker_readbacks'], [])
                self.assertEqual(observed['marker_after'], '0x4afc' if name == 'bad_sum_old_marker' else '0xffff')
        self.assertTrue(cases['valid']['context']['image_native_checksum_valid'])
        self.assertFalse(cases['zero_sum_bad_crc']['context']['image_native_checksum_valid'])
        self.assertEqual(cases['zero_sum_bad_crc']['context']['image_be16_sum'], 0)

    @unittest.skipUnless(os.environ.get('AL5_CAPTURED_LOADER') and importlib.util.find_spec('unicorn'), 'requires pinned loader and Unicorn')
    def test_context_guards(self):
        code = Path(os.environ['AL5_CAPTURED_LOADER']).read_bytes()
        for context in ({'marker': True}, {'marker': -1}, {'marker': 65536}, {'readback': []}, {'readback': 'hardware'}):
            with self.assertRaises(ValueError):
                finalize.experiment(code, finalize.fixture(), **context)
        for image in (b'', b'\x00'*1048576, bytearray(finalize.fixture())):
            with self.assertRaises(ValueError):
                finalize.experiment(code, image)

    @unittest.skipUnless(all(os.environ.get(k) for k in ('AL5_CAPTURED_LOADER', 'AL5_LOW_DUMP', 'AL5_HIGH_DUMP')) and importlib.util.find_spec('unicorn'), 'requires pinned loader/LOW/HIGH and Unicorn')
    def test_independent_application_checks_after_finalization(self):
        # Explicit synthetic handoffs between independent native slices. This
        # does not run hardware reset, scheduling, receive or a continuous session.
        from emulate_calibration_marker import marker_case, reset_marker_branch
        from al5_segment import START, LENGTH, word_sum
        code = Path(os.environ['AL5_CAPTURED_LOADER']).read_bytes()
        low = Path(os.environ['AL5_LOW_DUMP']).read_bytes()
        high = Path(os.environ['AL5_HIGH_DUMP']).read_bytes()
        stock = low[START:START+LENGTH]
        bad_crc = bytearray(stock)
        bad_crc[-4] ^= 1
        bad_crc[-2:] = b'\0\0'
        bad_crc[-2:] = ((-word_sum(bad_crc))&65535).to_bytes(2, 'big')
        finished = finalize.experiment(code, bytes(bad_crc))
        self.assertEqual([b['status'] for b in finished['observed']['status_bodies']], [0x86])
        app = marker_case(low, high, calibration=bytes(bad_crc), marker=int(finished['observed']['marker_after'], 0))
        self.assertEqual(app['stop'], 'calibration_crc_rejected')
        self.assertEqual(app['reset_marker'], '0x30d4')
        branch = reset_marker_branch(low, 0x30d4)
        self.assertEqual((branch['stop_pc'], branch['marker_after']), ('0x97c', '0x3e91'))
        bad_compensation = bytearray(stock)
        bad_compensation[-1] ^= 1
        rejected = finalize.experiment(code, bytes(bad_compensation), marker=0x4afc)
        self.assertEqual([b['status'] for b in rejected['observed']['status_bodies']], [0xff])
        app = marker_case(low, high, calibration=bytes(bad_compensation), marker=0x4afc)
        self.assertEqual(app['stop'], 'returned')
        self.assertFalse(app['physical_recovery_verified'])


if __name__ == '__main__':
    unittest.main()
