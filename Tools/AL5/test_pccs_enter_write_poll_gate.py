import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import emulate_pccs_enter_write_poll_gate as poll


class EnterWritePollTests(unittest.TestCase):
    def test_source_pin_before_loading(self):
        with self.assertRaisesRegex(ValueError, 'pin changed'):
            poll.run(b'not the executable')

    def test_pc_bounds(self):
        self.assertTrue(poll.permitted_pc(poll.START, 7))
        self.assertTrue(poll.permitted_pc(0x5b0af0, 7))
        for address, size in ((poll.START-1, 1), (poll.STOP-1, 2), (0x5b0af7, 2), (poll.VIRTUAL+0x100, 1)):
            self.assertFalse(poll.permitted_pc(address, size))

    def test_write_bounds(self):
        self.assertTrue(poll.permitted_write(poll.STACK, 4))
        self.assertTrue(poll.permitted_write(0x81d104, 1))
        self.assertTrue(poll.permitted_write(poll.THIS+0x528a4, 1))
        for address, size in ((poll.THIS+0x68c60, 1), (0x81d104, 2), (poll.VIRTUAL, 4)):
            self.assertFalse(poll.permitted_write(address, size))

    def test_existing_output_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'keep.json'
            output.write_text('keep', encoding='utf-8')
            with patch('sys.argv', ['tool', 'missing.exe', '--output', str(output)]), patch.object(poll, 'audit') as audit:
                with self.assertRaises(SystemExit):
                    poll.main()
            audit.assert_not_called()
            self.assertEqual(output.read_text(encoding='utf-8'), 'keep')

    @unittest.skipUnless(os.environ.get('AL5_PCCS_EXE') and importlib.util.find_spec('unicorn'), 'requires pinned local PCCS and Unicorn')
    def test_native_poll_matrix(self):
        data = Path(os.environ['AL5_PCCS_EXE']).read_bytes()
        result = poll.audit(data)
        self.assertEqual(len(result['cases']), 10)
        for case in result['cases']:
            self.assertFalse(case['full_enter_write_executed'])
            self.assertFalse(case['identification_body_executed'])
            self.assertFalse(case['transport_used'])
            self.assertEqual(case['would_send'], [])
        base, alternate = result['cases'][:2]
        self.assertEqual((base['identification_count'], base['final_host_status'], base['final_d104']), (1, 0, 1))
        self.assertEqual(alternate['identification_count'], 0)
        self.assertEqual(alternate['calls'], [{'kind': 'synthetic_alternate_identity_assignment'}])
        for case in result['cases'][2:6]:
            self.assertEqual(case['boundary'], 'prior_host_status_error')
            self.assertEqual(case['calls'], [])
        long_wait, two_polls, exhausted, failing = result['cases'][6:]
        self.assertEqual(long_wait['calls'][0], {'kind': 'synthetic_delay', 'milliseconds': 3000})
        self.assertEqual((two_polls['identification_count'], two_polls['final_d104']), (2, 0))
        self.assertEqual(two_polls['native_d104_writes'], [0, 0, 0])
        self.assertEqual((exhausted['identification_count'], exhausted['final_host_status'], exhausted['final_d104']), (12, 8, 0))
        self.assertEqual((failing['identification_count'], failing['boot_predicate_count'], failing['final_host_status']), (12, 0, 9))
        self.assertEqual([c['milliseconds'] for c in failing['calls'] if c['kind'] == 'synthetic_delay'], [2000])
        for alternate_byte in (2, 255):
            case = poll.run(data, alternate=alternate_byte)
            self.assertEqual(case['context']['alternate_route'], alternate_byte)
            self.assertEqual(case['identification_count'], 0)
            self.assertEqual(case['calls'], [{'kind': 'synthetic_alternate_identity_assignment'}])
        for context in ({'status': 256}, {'alternate': 256}, {'prior_d104': True}, {'identify_statuses': ()}, {'identify_statuses': None}, {'identify_statuses': [0]},
                        {'boot_states': None}, {'boot_states': (1,)}):
            with self.assertRaises(ValueError):
                poll.run(data, **context)
        for context in ({'identify_statuses': (9,)}, {'boot_states': (False,)}):
            with self.assertRaisesRegex(ValueError, 'exhausted|Exhausted'):
                poll.run(data, **context)


if __name__ == '__main__':
    unittest.main()
