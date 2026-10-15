import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_boot_interface_gate as gate


class BootInterfaceGateTests(unittest.TestCase):
    def test_source_pin(self):
        with self.assertRaisesRegex(ValueError, 'pinned LOW'):
            gate.experiment(b'wrong source')

    def test_pc_boundaries(self):
        for start, end in gate.RANGES:
            self.assertTrue(gate.permitted_pc(start, 1))
            self.assertFalse(gate.permitted_pc(end-1, 2))
        self.assertFalse(gate.permitted_pc(0xcc0, 6))
        self.assertFalse(gate.permitted_pc(0x3b7c, 1))

    def test_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', '--low', 'missing.bin', '--output', str(output)]), patch.object(gate, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    gate.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_LOW_DUMP') and importlib.util.find_spec('unicorn'), 'requires pinned LOW and Unicorn')
    def test_native_low_byte_gate(self):
        report = gate.audit(Path(os.environ['AL5_LOW_DUMP']).read_bytes())
        self.assertEqual(len(report['cases']), 261)
        for case in report['cases']:
            expected = (case['context']['synthetic_hardware_word']&255) <= 20
            self.assertEqual(case['interface_flag'], int(expected))
            self.assertEqual(case['reaches_initializer_call'], expected)
            self.assertEqual(case['idle_interrupt_mask'], 0)
            self.assertEqual(case['idle_stack_delta'], -8)
            self.assertFalse(case['actual_interrupt_delivered'])
            for field in ('physical_read_executed', 'initializer_executed', 'full_startup_executed', 'hardware_register_meaning_verified', 'vpw_reentry_verified', 'transport_used', 'live_write_enabled', 'ready_to_flash'):
                self.assertFalse(case[field])
            self.assertEqual(case['would_send'], [])

    @unittest.skipUnless(os.environ.get('AL5_LOW_DUMP') and importlib.util.find_spec('unicorn'), 'requires pinned LOW and Unicorn')
    def test_context_guards(self):
        low = Path(os.environ['AL5_LOW_DUMP']).read_bytes()
        for value in (-1, 65536, True, None, []):
            with self.assertRaises(ValueError):
                gate.experiment(low, hardware_word=value)

    @unittest.skipUnless(os.environ.get('AL5_LOW_DUMP') and importlib.util.find_spec('unicorn'), 'requires pinned LOW and Unicorn')
    def test_independent_isr_to_resident_arming_handoff(self):
        # Explicit handoffs, not a physical interrupt or uninterrupted startup.
        from emulate_boot_receive_isr import run as interrupt
        from emulate_boot_session import BootSession
        low = Path(os.environ['AL5_LOW_DUMP']).read_bytes()
        configured = gate.experiment(low, hardware_word=20)
        events = tuple((0x20, value) for value in (0x6d, 0x18, 0xf0, 0x34))+((0xa0, 0),)
        received = interrupt(low, enabled=bool(configured['interface_flag']), events=events)
        self.assertEqual(received['stop'], 'resident_dispatch_entry')
        self.assertFalse(received['actual_interrupt_delivered'])
        self.assertFalse(received['dispatcher_or_transfer_executed'])
        buffer = bytes.fromhex(received['staged_buffer_hex'])
        session = BootSession(low)
        result = session.dispatch(buffer[1:1+received['staged_length']], status=buffer[0])
        self.assertEqual(result['upload_armed'], 1)
        self.assertEqual(result['responses'], ['6df0187444'])
        self.assertFalse(result['uploaded_execution_trapped'])
        disabled = gate.experiment(low, hardware_word=21)
        ignored = interrupt(low, enabled=bool(disabled['interface_flag']), events=events)
        self.assertEqual(ignored['fifo_events_consumed'], 0)
        self.assertEqual(ignored['stop'], 'before_rte')


if __name__ == '__main__':
    unittest.main()
