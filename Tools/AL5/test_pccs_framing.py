import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from emulate_pccs_framing import (COPY, RANGES, SEND, STACK, THIS, audit, main,
                                  permitted_pc, permitted_write, run)


class PccsFramingTests(unittest.TestCase):
    def test_pin_refused_before_layout_or_execution(self):
        with patch('emulate_pccs_framing.executable_sections') as layout:
            with self.assertRaisesRegex(ValueError, 'pin changed'):
                run(b'changed')
            layout.assert_not_called()

    def test_model_context_refused_before_layout(self):
        data = b'context-only'
        with patch('emulate_pccs_framing.SOURCE_SHA256', hashlib.sha256(data).hexdigest()), \
                patch('emulate_pccs_framing.executable_sections') as layout:
            for context in ({'payload': b''}, {'payload': bytes(9)}, {'target': -1},
                            {'source': 256}, {'identifier': 0x20000000},
                            {'fil': 'other'}, {'fil': 'extended', 'override': True},
                            {'fil': 'standard', 'identifier': 0x800}):
                with self.subTest(context=context), self.assertRaises(ValueError):
                    run(data, **context)
            layout.assert_not_called()

    def test_native_execution_and_write_bounds(self):
        for start, end in RANGES:
            self.assertTrue(permitted_pc(start, 1))
            self.assertFalse(permitted_pc(end-1, 2))
        self.assertTrue(permitted_pc(COPY, 1))
        self.assertTrue(permitted_pc(SEND, 3))
        self.assertFalse(permitted_pc(0x5aedc4, 1))  # Whole dispatcher never runs.
        self.assertFalse(permitted_pc(SEND+1, 1))
        self.assertFalse(permitted_pc(COPY, 2))
        self.assertFalse(permitted_pc(RANGES[0][0], 0))
        for address, size in ((STACK, 4), (0, 4), (THIS+0x528b0, 7),
                              (THIS+0x528a4, 1), (THIS+0x528a8, 4)):
            self.assertTrue(permitted_write(address, size, 2))
        for address, size in ((THIS+8, 4), (THIS+0x52250, 2),
                              (THIS+0x528b7, 1), (4, 1), (STACK+0x1ffff, 2),
                              (THIS+0x528a4, 2), (STACK, 0)):
            self.assertFalse(permitted_write(address, size, 2))

    def test_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'existing'
            path.write_bytes(b'keep')
            with patch('sys.argv', ['tool', str(path), '--output', str(path)]), \
                    patch('sys.stderr'), patch('emulate_pccs_framing.audit') as runner, \
                    self.assertRaises(SystemExit):
                main()
            runner.assert_not_called()
            self.assertEqual(path.read_bytes(), b'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'),
                         'Set AL5_PCCS_EXE and provide optional Unicorn for pinned real input')
    def test_pinned_native_framing_and_separate_fil_callbacks(self):
        report = audit(Path(os.environ['AL5_PCCS_EXE']).read_bytes())
        expected = ('0118ef03f91203', '0118ef18f81203', '0007ff1203',
                    '01000008001203', '0118ef03f91203', '0118ef03f91203',
                    '0118da03f93601', '0007e13601')
        self.assertEqual(len(report['cases']), 8)
        for case, buffer in zip(report['cases'], expected):
            with self.subTest(context=case['context']):
                self.assertEqual(case['calls'][0]['internal_callback_buffer_hex'], buffer)
                self.assertEqual(case['calls'][0]['arguments'][2], len(bytes.fromhex(buffer)))
                self.assertLess(case['instruction_observations'], 1000)
                self.assertFalse(case['transport_used'])
                self.assertFalse(case['windows_apis_executed'])
                self.assertFalse(case['ready_to_flash'])
                self.assertFalse(case['live_write_enabled'])
                self.assertEqual(case['would_send'], [])
        self.assertEqual(report['cases'][-2]['stages'], ['0x5a8ad8', '0x5a8d20'])
        self.assertEqual(report['cases'][-1]['stages'], ['0x5a8bb8', '0x5a8d20'])
        self.assertTrue(report['cases'][-1]['context']['synthetic_prefilled_fil_payload'])
        self.assertFalse(report['ready_to_flash'])


if __name__ == '__main__':
    unittest.main()
