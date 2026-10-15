import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_quick_route as route


class QuickRouteTests(unittest.TestCase):
    def test_pin_before_emulation(self):
        with patch.object(route, 'executable_sections') as layout:
            for operation in (route.run, route.audit):
                with self.assertRaisesRegex(ValueError, 'pin changed'):
                    operation(b'not the executable')
            layout.assert_not_called()

    def test_execution_bounds(self):
        self.assertTrue(route.permitted_pc(route.START, 7))
        self.assertTrue(route.permitted_pc(route.GETTER_START, 1))
        for address, size in ((route.START-1, 1), (0x5da890, 2), (route.GETTER_STOP-1, 2), (route.STOP, 1)):
            self.assertFalse(route.permitted_pc(address, size))

    def test_write_bounds(self):
        self.assertTrue(route.permitted_write(route.THIS+0x68c60, 1))
        self.assertTrue(route.permitted_write(route.STACK, 4))
        for address, size in ((route.THIS+0x68c60, 2), (0x81d16c, 1), (route.THIS+0x50, 1)):
            self.assertFalse(route.permitted_write(address, size))

    def test_output_existing_refused_before_input(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'existing.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', 'missing.exe', '--output', str(output)]), \
                    patch('sys.stderr'), patch.object(route, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    route.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned local PCCS and Unicorn')
    def test_native_route_matrix(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        result = route.audit(data)
        self.assertEqual(len(result['cases']), 76)
        for case in result['cases']:
            context = case['context']
            version, index = context['version'], context['index']
            prior, disabled = context['prior_route_flag'], context['global_disabled']
            identity = bytes.fromhex(context['identity_bytes'])
            value = int.from_bytes(identity, 'big') if context['family'] == 1 else identity[0] & 0x3f
            expected = prior
            if version == 3 or 8 <= version <= 12:
                expected = 0
            elif index == 3 and version == 0:
                if value >= 16 and not disabled:
                    expected = 1
            elif not disabled and version not in (6, 13):
                expected = 1
            self.assertEqual(case['final_route_flag'], expected, context)
            self.assertEqual(bool(case['calls']), index == 3 and version == 0)
            self.assertFalse(case['transport_used'])
            self.assertFalse(case['windows_apis_executed'])
            self.assertFalse(case['live_write_enabled'])
            self.assertFalse(case['ready_to_flash'])
            self.assertEqual(case['would_send'], [])
        for context in ({'index': 4}, {'version': 256}, {'prior': -1}, {'identity': 1 << 24}, {'family': True}):
            with self.assertRaises(ValueError):
                route.run(data, **context)


if __name__ == '__main__':
    unittest.main()
