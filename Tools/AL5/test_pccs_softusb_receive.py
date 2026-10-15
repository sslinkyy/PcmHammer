import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_softusb_receive as receive


class SoftUsbReceiveTests(unittest.TestCase):
    def test_pin_before_layout(self):
        with self.assertRaisesRegex(ValueError, 'pin changed'):
            receive.run(b'not the DLL')

    def test_execution_bounds(self):
        for start, stop in receive.BRANCHES:
            self.assertTrue(receive.permitted_pc(start, 1))
            self.assertFalse(receive.permitted_pc(stop-1, 2))
        for address in (0x40226b, 0x40227f, 0x40202c, 0x401218, 0x402528):
            self.assertFalse(receive.permitted_pc(address, 1))

    def test_write_ownership(self):
        self.assertTrue(receive.permitted_write(0x404720, 4))
        self.assertTrue(receive.permitted_write(receive.BUFFER+4, 1))
        for address, size in ((receive.BUFFER, 4), (receive.BUFFER+5, 4),
                              (0x4046f0, 2), (0x405104, 4)):
            self.assertFalse(receive.permitted_write(address, size))

    def test_existing_output_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', 'missing.dll', '--output', str(output)]), patch.object(receive, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    receive.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_SOFTUSB_DLL') and importlib.util.find_spec('unicorn'), 'requires pinned local SoftUSB and Unicorn')
    def test_native_receive_matrix(self):
        data = Path(os.environ['AL5_SOFTUSB_DLL']).read_bytes()
        report = receive.audit(data)
        self.assertEqual(len(report['cases']), 6)
        for case in report['cases']:
            context = case['context']
            frame_format = context['frame_format']
            expected = (context['timestamp'].to_bytes(4, 'big')+bytes([frame_format])
                        +context['identifier'].to_bytes(2 if frame_format == 0 else 4, 'big')
                        +bytes.fromhex(context['payload_hex']))
            self.assertEqual(case['host_buffer_hex'], expected.hex())
            self.assertEqual(case['reported_length'], len(expected))
            self.assertEqual(case['event_reads'][0]['event_code'], 1 if frame_format == 0 else 9)
            self.assertTrue(case['export_entry_and_dispatch_executed'])
            self.assertFalse(case['hardware_event_production_proven'])
            self.assertIsNone(case['actual_driver_loaded_in_pccs'])
            self.assertFalse(case['transport_used'])
            self.assertFalse(case['live_write_enabled'])
            self.assertFalse(case['ready_to_flash'])
            self.assertEqual(case['would_send'], [])
        for context in ({'frame_format': True}, {'identifier': 0x800}, {'payload': bytearray(8)},
                        {'payload': bytes(9)}, {'timestamp': -1}, {'frame_format': 1, 'identifier': 0x20000000}):
            with self.assertRaises(ValueError):
                receive.run(data, **context)


if __name__ == '__main__':
    unittest.main()
