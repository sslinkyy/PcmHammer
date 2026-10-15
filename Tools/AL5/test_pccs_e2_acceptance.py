import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_e2_acceptance as gate


class E2AcceptanceTests(unittest.TestCase):
    def test_pin_before_layout(self):
        with self.assertRaisesRegex(ValueError, 'pin changed'):
            gate.run(b'not the executable')

    def test_execution_bounds(self):
        for stage, start, stop in (('frame', gate.FRAME_START, gate.FRAME_STOP),
                                   ('service', gate.SERVICE_START, gate.UNMATCHED),
                                   ('copy', gate.COPY_START, gate.COPY_STOP)):
            self.assertTrue(gate.permitted_pc(stage, start, 1))
            for address, size in ((start-1, 1), (stop-1, 2), (start, 0)):
                self.assertFalse(gate.permitted_pc(stage, address, size))
        self.assertFalse(gate.permitted_pc('other', gate.FRAME_START, 1))

    def test_write_ownership(self):
        self.assertTrue(gate.permitted_write('copy', gate.THIS+3*0xa4+0x84, 2, 3))
        self.assertFalse(gate.permitted_write('copy', gate.THIS+2*0xa4+0x84, 2, 3))
        for stage in ('frame', 'service', 'copy'):
            self.assertFalse(gate.permitted_write(stage, gate.THIS+0x72d90, 1, 3))
            self.assertFalse(gate.permitted_write(stage, 0x81d104, 1, 3))

    def test_existing_output_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', 'missing.exe', '--output', str(output)]), patch.object(gate, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    gate.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned local PCCS and Unicorn')
    def test_native_receive_matrix(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        report = gate.audit(data)
        self.assertEqual(len(report['cases']), 14)
        for position, case in enumerate(report['cases']):
            accepted = position in (0, 1, 2, 4, 6, 7, 12, 13)
            self.assertEqual(case['positive_e2_accepted'], accepted, case['context'])
            self.assertEqual(case['identifier_copy_executed'], accepted)
            self.assertEqual(case['final_identifier_word'], case['context']['identifier'] if accepted else 0xffff)
            self.assertEqual(case['final_host_status'], 0 if accepted else 1)
            self.assertEqual(case['final_alternate'], case['context']['alternate'])
            self.assertFalse(case['continuous_helper_execution'])
            self.assertFalse(case['driver_or_transport_executed'])
            self.assertFalse(case['live_write_enabled'])
            self.assertFalse(case['ready_to_flash'])
            self.assertEqual(case['would_send'], [])
        self.assertEqual(report['cases'][10]['service_boundary'], 'read_again')
        self.assertEqual(report['cases'][11]['service_boundary'], 'unmatched_service_handoff')
        for context in ({'identifier': True}, {'identifier': 256}, {'length': -1},
                        {'received_id': 65536}, {'format_byte': True}, {'index': 7}):
            with self.assertRaises(ValueError):
                gate.run(data, **context)


if __name__ == '__main__':
    unittest.main()
