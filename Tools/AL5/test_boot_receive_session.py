"""Same-session native ISR/caller cleanup, upload guards and retry evidence."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import emulate_boot_receive_session as model


class ReceiveSessionGuards(unittest.TestCase):
    def test_source_pin_before_runtime(self):
        with self.assertRaisesRegex(ValueError, 'pinned LOW'):
            model.ReceiveSession(b'wrong')

    def test_owned_instruction_and_write_spans(self):
        for a, b in (model.DISPATCH, model.TRANSFER, model.NEGATIVE):
            self.assertTrue(model.executable_span(a, 2))
            self.assertFalse(model.executable_span(b-1, 2))
        for pc in (0x39F4, model.RTE, 0x2E8C, 0xFF9000, 0x2E30):
            self.assertFalse(model.executable_span(pc, 2))
        for address, size in ((0xFF9000, 4), (0xFF8185, 1), (model.STACK-512, 4)):
            self.assertTrue(model.writable_span(address, size))
        for address, size in ((0xFF903F, 2), (0xFFFA26, 2), (0x1FFFE, 2),
                              (0x8000, 2), (model.STACK, 4), (0xFF8010, 1)):
            self.assertFalse(model.writable_span(address, size))

    def test_synthetic_event_construction_guards(self):
        for payload in (b'', b'abc', b'12345', bytearray(b'1234')):
            with self.assertRaises(ValueError):
                model.transfer_events(payload=payload)
        for subtype in (True, 1, 0x100, -1):
            with self.assertRaises(ValueError):
                model.transfer_events(subtype=subtype)
        with self.assertRaises(ValueError):
            model.transfer_events(corrupt_checksum=1)
        for frame in (b'', bytes(3), bytes(12), bytearray(4)):
            with self.assertRaises(ValueError):
                model.frame_events(frame)
        for status in (True, -1, 256):
            with self.assertRaises(ValueError):
                model.frame_events(bytes(4), completion_status=status)

    def test_cli_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch.object(model, 'audit') as audit, patch('sys.stderr'):
                with self.assertRaises(SystemExit):
                    model.main(['--low', 'absent', '--output', str(output)])
                audit.assert_not_called()
            self.assertEqual('keep', output.read_text(encoding='utf-8'))


@unittest.skipUnless(os.environ.get('AL5_LOW_DUMP') and importlib.util.find_spec('unicorn'),
                     'requires pinned LOW and Unicorn')
class NativeReceiveSession(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.low = Path(os.environ['AL5_LOW_DUMP']).read_bytes()
        cls.report = model.audit(cls.low)
        cls.cases = {c['name']: c['steps'] for c in cls.report['cases']}

    def test_native_arm_transfer_and_caller_cleanup(self):
        arm, transfer = self.cases['arm_then_transfer']
        self.assertEqual(['6df0187444'], arm['responses'])
        self.assertEqual(['6cf018760073'], transfer['responses'])
        self.assertEqual(['0x341c'], arm['handler_entries'])
        self.assertEqual(['0x3074'], transfer['handler_entries'])
        self.assertEqual('12345678', transfer['synthetic_ram_hex'][:8])
        self.assertGreater(transfer['suppressed_watchdog_stores'], 0)
        for case in self.report['cases']:
            for step in case['steps']:
                self.assertFalse(step['actual_interrupt_delivered'])
                self.assertFalse(step['exception_return_executed'])
                self.assertFalse(step['uploaded_code_executed'])
                self.assertFalse(step['transport_used'])
                self.assertFalse(step['live_write_enabled'])
                self.assertFalse(step['ready_to_flash'])
                self.assertEqual([], step['would_send'])
                if step['stop'] == 'before_rte':
                    self.assertEqual(0, step['stack_delta'])
                    self.assertEqual(0, step['processing_flag'])
        self.assertEqual(0, transfer['staged_length'])
        self.assertEqual('00'*14, transfer['staged_buffer_hex'])
        self.assertEqual(1, transfer['upload_armed'])

    def test_failed_transfer_copies_ram_before_final_checks(self):
        unarmed = self.cases['unarmed_transfer'][0]
        self.assertEqual(0, unarmed['upload_armed'])
        self.assertEqual(['6cf0187f36000004ff9022'], unarmed['responses'])
        self.assertEqual('12345678', unarmed['synthetic_ram_hex'][:8])
        arm, bad, retried = self.cases['checksum_failure_then_retry']
        self.assertEqual(['6cf018760077'], bad['responses'])
        self.assertEqual(['6cf018760073'], retried['responses'])
        self.assertEqual(1, bad['upload_armed'])
        self.assertEqual('62616421', bad['synthetic_ram_hex'][:8])
        self.assertEqual('12345678', retried['synthetic_ram_hex'][:8])
        self.assertEqual(0, bad['stack_delta'])
        self.assertFalse(self.report['automatic_retry_allowed'])
        self.assertFalse(self.report['physical_recovery_verified'])

    def test_duplicate_transfer_and_bad_arm_preserve_state(self):
        steps = self.cases['duplicate_transfer']
        self.assertEqual([1, 1, 1], [s['upload_armed'] for s in steps])
        self.assertEqual([['6cf018760073']]*2, [s['responses'] for s in steps[1:]])
        bad = self.cases['bad_arm_length_preserves_arm'][-1]
        self.assertEqual(['6cf0187f340012'], bad['responses'])
        self.assertEqual(1, bad['upload_armed'])
        ignored = self.cases['wrong_destination'][0]
        self.assertEqual([], ignored['responses'])
        self.assertEqual(0, ignored['upload_armed'])

    def test_partial_frame_survives_native_interrupt_epilogue(self):
        first, second = self.cases['split_arm_across_interrupt_entries']
        self.assertEqual(2, first['staged_length'])
        self.assertEqual(0, first['upload_armed'])
        self.assertEqual(['6df0187444'], second['responses'])
        self.assertEqual(1, second['upload_armed'])
        self.assertEqual(0, second['staged_length'])

    def test_uploaded_execution_is_terminal_and_trapped(self):
        session = model.ReceiveSession(self.low)
        session.interrupt(model.frame_events(bytes.fromhex('6d18f034')))
        result = session.interrupt(model.transfer_events(subtype=0x80))
        self.assertEqual('before_uploaded_execution', result['stop'])
        self.assertEqual('0xff9000', result['stop_pc'])
        self.assertEqual(-72, result['stack_delta'])
        self.assertEqual([], result['responses'])
        with self.assertRaisesRegex(RuntimeError, 'session stopped'):
            session.interrupt(((0, 0),))

    def test_disabled_context_and_failure_guards(self):
        disabled = model.ReceiveSession(self.low, enabled=False)
        result = disabled.interrupt(model.frame_events(bytes.fromhex('6d18f034')))
        self.assertEqual(0, result['fifo_events_consumed'])
        self.assertEqual(0, result['upload_armed'])
        with self.assertRaises(ValueError):
            model.ReceiveSession(self.low, enabled=1)
        session = model.ReceiveSession(self.low)
        for events in ([], ((True, 0),), ((256, 0),), ((0, 0),)*97):
            with self.assertRaises(ValueError):
                session.interrupt(events)
        with self.assertRaisesRegex(RuntimeError, 'FIFO exhausted'):
            session.interrupt(())
        with self.assertRaisesRegex(RuntimeError, 'session stopped'):
            session.interrupt(((0, 0),))

    def test_callback_caller_and_write_guards(self):
        from unicorn.m68k_const import UC_M68K_REG_A7
        session = model.ReceiveSession(self.low)
        session.uc.reg_write(UC_M68K_REG_A7, model.STACK-4)
        session.uc.mem_write(model.STACK-4, model.START.to_bytes(4, 'big'))
        with self.assertRaisesRegex(RuntimeError, 'callback caller'):
            session.callback_return(0x2ED0)
        with self.assertRaisesRegex(RuntimeError, 'write escaped'):
            session.write_hook(session.uc, None, 0xFFFA26, 2, 0x55, None)
        with self.assertRaisesRegex(RuntimeError, 'MMIO read'):
            session.read_hook(session.uc, None, 0xFFFA26, 2, 0, None)


if __name__ == '__main__':
    unittest.main()
