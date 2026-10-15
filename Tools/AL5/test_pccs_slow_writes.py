import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_slow_writes as slow


class SlowWritesTests(unittest.TestCase):
    def test_pin_before_loading(self):
        with self.assertRaisesRegex(ValueError, 'pin changed'):
            slow.run(b'not the executable')

    def test_bounds(self):
        self.assertTrue(slow.permitted_pc('toggle', 0x7e1a1f, 6))
        self.assertTrue(slow.permitted_write(slow.FLAG, 1))
        for kind, address, size in (('toggle', 0x7e1a1e, 1), ('toggle', 0x7e1a31, 3),
                                    ('unknown', 0x7e1a1f, 1), ('config_store', 0x7e1a1f, 6)):
            self.assertFalse(slow.permitted_pc(kind, address, size))
        for address, size in ((slow.FLAG, 2), (slow.POINTER, 4), (slow.STACK, 4)):
            self.assertFalse(slow.permitted_write(address, size))

    def test_existing_output_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'keep.json'
            path.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', 'missing.exe', '--output', str(path)]), patch.object(slow, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    slow.main()
            audit.assert_not_called()
            self.assertEqual(path.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned local PCCS and Unicorn')
    def test_native_slices(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        result = slow.audit(data)
        self.assertEqual(len(result['cases']), 10)
        for case in result['cases']:
            context = case['context']
            if context['kind'] == 'toggle':
                expected = context['prior'] ^ 1
            elif context['kind'] == 'config_store':
                expected = context['comparison_equal']
            else:
                expected = 1
            self.assertEqual(case['final_flag'], expected, context)
            self.assertFalse(case['transport_used'])
            self.assertFalse(case['live_write_enabled'])
        for context in ({'kind': 'unknown'}, {'prior': 2}, {'comparison_equal': True}):
            with self.assertRaises(ValueError):
                slow.run(data, **context)


if __name__ == '__main__':
    unittest.main()
