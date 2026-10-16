"""Native RAM upload/JSR continuity with pinned-code and no-send boundaries."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import emulate_boot_loader_handoff as model


class HandoffGuards(unittest.TestCase):
    def test_source_and_synthetic_options(self):
        with self.assertRaisesRegex(ValueError, 'pinned LOW'):
            model.BootLoaderSession(b'wrong', b'wrong')
        with self.assertRaisesRegex(ValueError, 'pinned loader'):
            model.captured_upload_events(b'wrong')

    def test_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'keep.json'
            path.write_text('keep', encoding='utf-8')
            with patch.object(model, 'audit') as audit, patch('sys.stderr'):
                with self.assertRaises(SystemExit):
                    model.main(['--low', 'absent', '--loader', 'absent', '--output', str(path)])
                audit.assert_not_called()
            self.assertEqual('keep', path.read_text(encoding='utf-8'))


@unittest.skipUnless(os.environ.get('AL5_LOW_DUMP') and os.environ.get('AL5_CAPTURED_LOADER') and
                     importlib.util.find_spec('unicorn'), 'requires pinned LOW/loader and Unicorn')
class NativeHandoff(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.low = Path(os.environ['AL5_LOW_DUMP']).read_bytes()
        cls.code = Path(os.environ['AL5_CAPTURED_LOADER']).read_bytes()
        cls.report = model.audit(cls.low, cls.code)
        cls.cases = {c['name']: c['steps'] for c in cls.report['cases']}

    def test_actual_boot_copy_jsr_and_loader_stack_replacement(self):
        arm, upload, program = self.cases['armed_upload_then_program']
        self.assertEqual(['6df0187444'], arm['boot_responses'])
        handoff = upload['handoff']
        self.assertEqual(model.EXPECTED_SHA, handoff['uploaded_sha256'])
        self.assertEqual(1590, handoff['native_uploaded_bytes'])
        self.assertEqual(-72, handoff['boot_stack_delta'])
        self.assertEqual('0x33b8', handoff['pending_boot_return'])
        self.assertTrue(handoff['native_jsr_reached'])
        self.assertFalse(handoff['loader_bytes_preloaded'])
        self.assertEqual('0xffa7fe', upload['stack_pointer'])
        self.assertEqual('receive_boundary', upload['stop'])
        self.assertEqual('0xff903a', upload['stop_pc'])
        self.assertEqual(255, upload['receive_budget'])
        self.assertEqual(1, upload['suppressed_setup_stores'])
        self.assertEqual(['760073'], program['responses'])
        self.assertEqual('12345678', program['synthetic_flash_hex'])
        self.assertEqual(1, program['native_sender_returns'])
        self.assertEqual(0, program['stack_delta'])

    def test_real_boot_d7_survives_loader_entry_until_program_clears_it(self):
        arm, upload, program = self.cases['armed_upload_then_program']
        self.assertEqual('0x680', upload['handoff']['d7_at_loader_entry'])
        self.assertEqual(upload['handoff']['d7_at_loader_entry'], upload['d7'])
        self.assertEqual('0x0', program['d7'])

    def test_checksum_failure_then_native_upload_retry(self):
        arm, bad, upload, program = self.cases['checksum_failure_then_upload_retry']
        self.assertEqual(['6cf018768077'], bad['boot_responses'])
        self.assertEqual('boot', bad['phase'])
        self.assertIsNone(bad['handoff'])
        self.assertEqual(1590, bad['uploaded_bytes_observed'])
        self.assertEqual(1590, upload['handoff']['native_uploaded_bytes'])
        self.assertEqual('loader', upload['phase'])
        self.assertEqual(['7600f8'], program['responses'])
        self.assertEqual(-4, program['stack_delta'])

    def test_unarmed_copy_never_enters_loader(self):
        result = self.cases['unarmed_upload_rejected'][0]
        self.assertEqual(1590, result['uploaded_bytes_observed'])
        self.assertEqual(['6cf0187f36800636ff9022'], result['boot_responses'])
        self.assertEqual('before_boot_rte', result['stop'])
        self.assertEqual('0x208000', result['stack_pointer'])
        self.assertIsNone(result['handoff'])

    def test_plain_transfer_ack_is_not_loader_entry(self):
        result = self.cases['upload_without_execution'][-1]
        self.assertEqual(['6cf018760073'], result['boot_responses'])
        self.assertEqual('boot', result['phase'])
        self.assertIsNone(result['handoff'])

    def test_checksum_valid_modified_kernel_is_blocked_before_entry(self):
        session = model.BootLoaderSession(self.low, self.code)
        self.assertEqual(bytes(len(self.code)), bytes(session.uc.mem_read(model.BASE, len(self.code))))
        session.boot_interrupt(model.frame_events(bytes.fromhex('6d18f034')))
        original = model.captured_upload_events(self.code)
        data = bytearray(v for status, v in original[:-2])
        data[110] ^= 1
        data[-2:] = (sum(data[4:-2]) & 65535).to_bytes(2, 'big')
        events = tuple((0x20, v) for v in data)+original[-2:]
        with self.assertRaisesRegex(RuntimeError, 'handoff context mismatch'):
            session.boot_interrupt(events)
        self.assertEqual('boot', session.phase)
        self.assertTrue(session.closed)
        self.assertIsNone(session.handoff)
        trailing = model.BootLoaderSession(self.low, self.code)
        trailing.boot_interrupt(model.frame_events(bytes.fromhex('6d18f034')))
        events = model.captured_upload_events(self.code)[:-1]+((0x20, 0x55),)
        with self.assertRaisesRegex(RuntimeError, 'non-idle boot data'):
            trailing.boot_interrupt(events)
        self.assertTrue(trailing.closed)

    def test_context_phase_and_size_guards(self):
        session = model.BootLoaderSession(self.low, self.code)
        with self.assertRaises(RuntimeError):
            session.frame()
        with self.assertRaisesRegex(RuntimeError, 'MMIO read'):
            session.read_hook(session.uc, None, 0xFFE800, 1, 0, None)
        for events in ([], ((True, 0),), ((256, 0),), ((0, 0),)*(len(self.code)+15)):
            with self.assertRaises(ValueError):
                session.boot_interrupt(events)
        for args in ({'execute': 1}, {'corrupt_checksum': 1}):
            with self.assertRaises(ValueError):
                model.captured_upload_events(self.code, **args)
        session.boot_interrupt(model.frame_events(bytes.fromhex('6d18f034')))
        session.boot_interrupt(model.captured_upload_events(self.code))
        with self.assertRaises(RuntimeError):
            session.boot_interrupt(((0, 0),))

    def test_no_hardware_or_recovery_qualification(self):
        for case in self.report['cases']:
            for result in case['steps']:
                self.assertTrue(result['same_native_session'])
                for field in ('physical_loader_execution_verified', 'transport_used',
                              'physical_recovery_verified', 'live_write_enabled', 'ready_to_flash'):
                    self.assertFalse(result[field])
                self.assertEqual([], result['would_send'])


if __name__ == '__main__':
    unittest.main()
