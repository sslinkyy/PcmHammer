import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_standard_lct_identity as identity


class StandardLctIdentityTests(unittest.TestCase):
    def test_pin_before_loading(self):
        with self.assertRaisesRegex(ValueError, 'pin changed'):
            identity.run(b'not the executable')

    def test_pc_bounds(self):
        self.assertTrue(identity.permitted_pc(identity.START, 7))
        for address, size in ((identity.START-1, 1), (identity.STOP-1, 2), (0x407208, 1)):
            self.assertFalse(identity.permitted_pc(address, size))

    def test_write_bounds(self):
        self.assertTrue(identity.permitted_write(identity.THIS+3*0xa4+0x80, 1, 3))
        self.assertTrue(identity.permitted_write(identity.STACK, 4, 3))
        for address, size in ((identity.THIS+0x72d90, 1), (identity.THIS+0x68c60, 1),
                              (identity.THIS+3*0xa4+0x80, 2), (identity.THIS+0x80, 1)):
            self.assertFalse(identity.permitted_write(address, size, 3))

    def test_existing_output_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', 'missing.exe', '--output', str(output)]), patch.object(identity, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    identity.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned local PCCS and Unicorn')
    def test_native_classification_keeps_prior_alternate(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        report = identity.audit(data)
        self.assertEqual(len(report['cases']), 6)
        for case in report['cases']:
            self.assertEqual(case['final_family'], 1)
            self.assertEqual(case['final_version'], 0)
            self.assertEqual(case['final_alternate'], case['context']['prior_alternate'])
            self.assertFalse(case['full_identification_executed'])
            self.assertFalse(case['transport_used'])
            self.assertEqual(case['would_send'], [])
        for context in ({'prior_alternate': 256}, {'prior_alternate': True}, {'index': -1}, {'index': 7}):
            with self.assertRaises(ValueError):
                identity.run(data, **context)


if __name__ == '__main__':
    unittest.main()
