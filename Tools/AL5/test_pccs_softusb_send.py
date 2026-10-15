import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_softusb_send as send


class SoftUsbSendTests(unittest.TestCase):
    def test_pin_before_layout(self):
        with self.assertRaisesRegex(ValueError, 'pin changed'):
            send.run(b'not the DLL')

    def test_execution_bounds(self):
        self.assertTrue(send.permitted_pc(send.START, 1))
        self.assertTrue(send.permitted_pc(send.SWAP, 1))
        for address, size in ((send.STOP-1, 2), (send.SWAP_STOP-1, 2),
                              (0x402034, 1), (0x402054, 1), (send.START, 0)):
            self.assertFalse(send.permitted_pc(address, size))

    def test_write_ownership(self):
        self.assertTrue(send.permitted_write(send.STACK, 4))
        for address, size in ((send.STACK+0xffff, 2), (0x404738, 4),
                              (send.BUFFER, 1), (0x405100, 4)):
            self.assertFalse(send.permitted_write(address, size))

    def test_existing_output_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', 'missing.dll', '--output', str(output)]), patch.object(send, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    send.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_SOFTUSB_DLL') and importlib.util.find_spec('unicorn'), 'requires pinned local SoftUSB and Unicorn')
    def test_native_outgoing_matrix(self):
        data = Path(os.environ['AL5_SOFTUSB_DLL']).read_bytes()
        report = send.audit(data)
        self.assertEqual(len(report['cases']), 8)
        for position, case in enumerate(report['cases']):
            context = case['context']
            if context['queue_level'] >= 70:
                self.assertEqual(case['boundary'], 'returned')
                self.assertEqual(case['return_word'], 0x89)
                self.assertIsNone(case['constructed_CAN_arguments'])
            else:
                self.assertEqual(case['boundary'], 'lower_CAN_call')
                arguments = case['constructed_CAN_arguments']
                if position in (1, 7):
                    self.assertEqual(arguments['identifier'], 0x7e2)
                    self.assertEqual(arguments['extended_selector'], 0)
                else:
                    self.assertEqual(arguments['identifier'], 0x18ef03f9)
                    self.assertEqual(arguments['extended_selector'], 1)
                    self.assertEqual(arguments['payload_hex'], '35')
                if position == 1:
                    self.assertEqual(arguments['payload_length'], 8)
                if position == 7:
                    self.assertEqual(arguments['payload_length'], 0)
            self.assertFalse(case['lower_driver_executed'])
            self.assertIsNone(case['actual_driver_loaded_in_pccs'])
            self.assertFalse(case['transport_used'])
            self.assertFalse(case['live_write_enabled'])
            self.assertFalse(case['ready_to_flash'])
            self.assertEqual(case['would_send'], [])
        for context in ({'frame': b''}, {'frame': b'\x00\x07'}, {'frame': bytes(12)},
                        {'frame': bytearray(8)}, {'queue_level': True}, {'queue_level': 2**31}):
            with self.assertRaises(ValueError):
                send.run(data, **context)


if __name__ == '__main__':
    unittest.main()
