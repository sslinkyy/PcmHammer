import itertools
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import bench_adapter_battery as battery
from test_bench_dual_adapter_probe import SX
from test_obdx_capture import FakePort


class Requester(SX):
    def write(self, wire):
        if wire in (b'ATH1\r', b'ATIFR0\r'):
            self.writes.append(wire)
            self.pending = b'OK\r>'
        else:
            super().write(wire)


class Tests(unittest.TestCase):
    def test_second_port_open_failure_closes_first_port(self):
        class Port:
            closed = False
            def close(self):
                self.closed = True
        gt = Port()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'evidence.jsonl'
            args = ['battery', '--gt-port', 'COM9', '--sx-port', 'COM8',
                    '--bench-ecm-confirmed', '--output', str(output)]
            with patch('sys.argv', args), patch.object(battery, 'WindowsSerial',
                    side_effect=[gt, OSError('port unavailable')]):
                self.assertEqual(battery.main(), 1)
            self.assertTrue(gt.closed)
            self.assertEqual(json.loads(output.read_text().splitlines()[-1])['error'],
                             'port unavailable')

    def test_matrix_bounded_queries_and_exact_cleanup(self):
        gt, sx, rows = FakePort(), Requester(), []
        original = dict(gt.settings)
        def on(session, command, payload):
            self.assertEqual((command, payload), (0x31, b'\x02\x01'))
            gt.state = 1
        with patch.object(battery, 'gt_fixed', side_effect=on), patch(
                'time.monotonic', side_effect=(n * .01 for n in itertools.count())):
            results = battery.run(gt, sx, rows.append)
        self.assertEqual(len(results), 16)
        self.assertTrue(all(r['completed'] for r in results))
        self.assertEqual(sx.writes.count(b'0100\r'), 48)
        self.assertEqual(gt.state, 0)
        self.assertEqual(gt.settings, original)
        self.assertTrue(rows[-1]['network_off_acknowledged'])

    def test_configuration_mismatch_blocks_requests(self):
        gt, sx, rows = FakePort(), Requester(), []
        gt.stuck_mask = True
        gt.settings[0x33, 4] = b'\x04\x00\xff\x00\x01'
        with patch.object(battery, 'CASES', battery.CASES[:1]), patch(
                'time.monotonic', side_effect=(n * .01 for n in itertools.count())):
            results = battery.run(gt, sx, rows.append)
        self.assertTrue(results[0]['completed'])
        self.assertFalse(results[1]['completed'])
        self.assertEqual(results[1]['requests'], [])
        self.assertEqual(sx.writes.count(b'0100\r'), 3)
        self.assertEqual(gt.state, 0)


if __name__ == '__main__':
    unittest.main()
