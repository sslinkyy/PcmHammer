import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_transport_envelope as envelope


class TransportEnvelopeTests(unittest.TestCase):
    def test_pin_before_loading(self):
        with self.assertRaisesRegex(ValueError, 'pin changed'):
            envelope.run(b'not the executable')

    def test_execution_bounds(self):
        self.assertTrue(envelope.permitted_pc('initial', 'header', 0x5a8bb8, 1))
        self.assertTrue(envelope.permitted_pc('ordinary', 'packet', envelope.PACK_START, 7))
        for mode, phase, address, size in (('initial', 'header', 0x5a8bb7, 1),
                                         ('ordinary', 'header', 0x5a8d1c, 2),
                                         ('ordinary', 'packet', envelope.PACK_STOP-1, 2),
                                         ('unknown', 'header', 0x5a8bb8, 1),
                                         ('ordinary', 'unknown', envelope.PACK_START, 1)):
            self.assertFalse(envelope.permitted_pc(mode, phase, address, size))

    def test_write_bounds(self):
        self.assertTrue(envelope.permitted_write('header', envelope.THIS+0x528b0, 1))
        self.assertTrue(envelope.permitted_write('packet', envelope.STACK, 4))
        for phase, address, size in (('packet', envelope.THIS+0x528b0, 1),
                                     ('header', envelope.THIS+0x72d90, 1),
                                     ('header', envelope.THIS+8, 4),
                                     ('unknown', envelope.STACK, 4)):
            self.assertFalse(envelope.permitted_write(phase, address, size))

    def test_existing_output_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', 'missing.exe', '--output', str(output)]), patch.object(envelope, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    envelope.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned local PCCS and Unicorn')
    def test_native_envelope_matrix(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        report = envelope.audit(data)
        self.assertEqual(len(report['cases']), 6)
        initial, ordinary, changed_address, ccp_standard, ccp_extended, alternate_off = report['cases']
        self.assertEqual(initial['header_hex'], '0007e0')
        self.assertEqual(initial['format'], 0)
        self.assertIsNone(initial['ordinary_packet'])
        self.assertEqual(ordinary['header_hex'], '0118ef03f9')
        self.assertEqual(ordinary['ordinary_packet']['hex'], '0118ef03f935')
        self.assertEqual(ordinary['ordinary_packet']['length'], 6)
        self.assertEqual(changed_address['ordinary_packet']['hex'], '0118ef04f835')
        self.assertEqual(ccp_standard['ordinary_packet']['hex'], '0007e035')
        self.assertEqual(ccp_standard['ordinary_packet']['length'], 4)
        self.assertEqual(ccp_extended['ordinary_packet']['hex'], '0118da03f935')
        self.assertEqual(alternate_off['header_hex'], ordinary['header_hex'])
        self.assertEqual(alternate_off['final_alternate_bytes'], '00010101')
        for case in report['cases']:
            self.assertFalse(case['transport_used'])
            self.assertFalse(case['full_dispatcher_executed'])
            self.assertFalse(case['initial_packet_builder_executed'])
            self.assertEqual(case['would_send'], [])
            if case['ordinary_packet']:
                packet = case['ordinary_packet']
                self.assertEqual(packet['connection_argument'], 0x3456)
                self.assertEqual(packet['callback_object_offset'], 8)
                self.assertFalse(packet['driver_callback_executed'])
        signed_edge = envelope.run(data, ccp_control=1, ccp_id=0xffffffff)
        self.assertEqual(signed_edge['format'], 0)  # Native signed JLE, not unsigned CAN-ID validation.
        self.assertEqual(signed_edge['header_hex'], '00ffff')
        for context in ({'mode': 'unknown'}, {'mode': []}, {'ccp_control': True}, {'target': 256},
                        {'source': -1}, {'initial_id': 0x10000}, {'ccp_id': 1 << 32}):
            with self.assertRaises(ValueError):
                envelope.run(data, **context)


if __name__ == '__main__':
    unittest.main()
