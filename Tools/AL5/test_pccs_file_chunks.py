import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from emulate_pccs_file_chunks import (START, END, STOP, STACK, STATE, BUFFER, CALLBACKS, ROUND,
                                      audit, main, permitted_pc, permitted_write, run)


class PccsFileChunkTests(unittest.TestCase):
    def test_pin_rejected_before_layout(self):
        with patch('emulate_pccs_file_chunks.executable_sections') as layout:
            with self.assertRaisesRegex(ValueError, 'pin changed'):
                run(b'changed')
            with self.assertRaisesRegex(ValueError, 'pin changed'):
                audit(b'changed')
            layout.assert_not_called()

    def test_context_rejected_before_imports(self):
        data = b'context'
        with patch('emulate_pccs_file_chunks.SOURCE_SHA256', hashlib.sha256(data).hexdigest()):
            for context in ({'interpreter': 5}, {'payload': b''}, {'payload': bytes(257)},
                            {'chunk_size': 0}, {'address': 0xffffffff},
                            {'failure_at': 0}, {'failure_at': 4}, {'fixed_address': 1},
                            {'final_flag': 2}, {'cancel': 1}):
                with self.subTest(context=context), self.assertRaises(ValueError):
                    run(data, **context)

    def test_pc_write_boundaries(self):
        self.assertTrue(permitted_pc(START, 1))
        self.assertFalse(permitted_pc(END-1, 2))
        self.assertFalse(permitted_pc(STOP, 1))
        self.assertFalse(permitted_pc(START-1, 1))
        for pc, cleanup in CALLBACKS.items():
            self.assertTrue(permitted_pc(pc, 2 if pc == ROUND else 3 if cleanup else 1))
            self.assertFalse(permitted_pc(pc+1, 1))
        for address, size in ((STACK, 4), (STATE+0xf7, 1), (STATE+0x600, 1), (BUFFER, 4)):
            self.assertTrue(permitted_write(address, size, 4))
        for address, size in ((STATE, 4), (STATE+0xf7, 2), (BUFFER+3, 2), (STACK+0xffff, 2), (STACK, 0)):
            self.assertFalse(permitted_write(address, size, 4))

    def test_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'existing'
            path.write_bytes(b'keep')
            with patch('sys.argv', ['tool', str(path), '--output', str(path)]), \
                    patch('sys.stderr'), patch('emulate_pccs_file_chunks.audit') as runner, \
                    self.assertRaises(SystemExit):
                main()
            runner.assert_not_called()
            self.assertEqual(path.read_bytes(), b'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'),
                         'Set AL5_PCCS_EXE and provide optional Unicorn for pinned real input')
    def test_native_slice_success_failure_and_boundary(self):
        report = audit(Path(os.environ['AL5_PCCS_EXE']).read_bytes())
        self.assertEqual(len(report['cases']), 8)
        for case in report['cases']:
            self.assertEqual(case['stop_before_cleanup'], hex(STOP))
            self.assertFalse(case['transport_used'])
            self.assertFalse(case['ready_to_flash'])
            self.assertFalse(case['live_write_enabled'])
            self.assertEqual(case['would_send'], [])
        modern, old, exact, fixed, fail, oldfail, cancel, many = report['cases']
        self.assertEqual([x['counter'] for x in modern['transfers']], [1, 2, 3])
        self.assertEqual([x['counter'] for x in old['transfers']], [0, 0, 0])
        for case in (modern, old):
            self.assertEqual([x['length'] for x in case['transfers']], [4, 4, 2])
            self.assertEqual([x['flag'] for x in case['transfers']], [0, 0, 1])
            self.assertEqual(case['final_address'], 0x1000c)
            self.assertEqual(case['done_byte'], 1)
            self.assertEqual(''.join(x['payload_hex'] for x in case['transfers']), case['context']['payload_hex'])
        self.assertEqual([x['flag'] for x in exact['transfers']], [0, 0])
        self.assertEqual([x['length'] for x in exact['transfers']], [4, 4])
        self.assertEqual(exact['final_address'], 0x10008)
        self.assertEqual([x['address'] for x in fixed['transfers']], [0x10000]*3)
        self.assertEqual(fixed['final_address'], 0x10000)
        for case in (fail, oldfail):
            self.assertEqual(len(case['transfers']), 1)
            self.assertEqual(case['final_status'], 1)
            self.assertEqual(case['done_byte'], 0)
            self.assertEqual(case['final_address'], 0x10000)
            self.assertNotIn({'helper': 'synthetic_exit'}, case['calls'])
        self.assertEqual(cancel['transfers'], [])
        self.assertEqual(cancel['done_byte'], 0)
        self.assertEqual(modern['calls'][-1], {'helper': 'synthetic_exit'})
        self.assertEqual(old['calls'], [])
        self.assertEqual(len(many['transfers']), 10)
        self.assertEqual(many['done_byte'], 1)
        self.assertEqual(many['final_address'], 0x1000a)


if __name__ == '__main__':
    unittest.main()
