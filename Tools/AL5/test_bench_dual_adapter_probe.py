import threading
import itertools
import unittest
from unittest.mock import patch

import bench_dual_adapter_probe as probe
from test_obdx_capture import FakePort
from obdx_capture import Session, packet


class SX:
    def __init__(self):
        self.pending = b''
        self.writes = []
        self.queried = threading.Event()

    def read(self):
        value, self.pending = self.pending, b''
        return value

    def write(self, wire):
        self.writes.append(wire)
        self.pending = {
            b'STI\r': b'STN1130 v4.0.1\r>',
            b'STDI\r': b'OBDLink SX r4.2\r>',
            b'ATDPN\r': b'2\r>',
            b'ATSH686AF1\r': b'OK\r>',
            b'0100\r': b'41 00 BE 1F B8 10\r>',
        }[wire]
        if wire == b'0100\r':
            self.queried.set()


class Tests(unittest.TestCase):
    def test_unknown_source_speed_stops_before_ports(self):
        with self.assertRaises(ValueError):
            probe.run_sx_monitor(object(), object(), lambda row: None, 'auto')

    def test_4x_source_only_preserves_settings_and_stops_monitor(self):
        class Monitor(SX):
            def write(self, wire):
                if wire in (b'ATH1\r', b'ATIFR0\r', b'STMA\r', b'x'):
                    self.writes.append(wire)
                    self.pending = b'STMA\r' if wire == b'STMA\r' else (
                        b'\r>' if wire == b'x' else b'OK\r>')
                else:
                    super().write(wire)
        gt, sx, rows, sent = FakePort(), Monitor(), [], []
        original = dict(gt.settings)
        def send(session, command, payload):
            sent.append((command, bytes(payload)))
            if command == 0x31:
                gt.state = 1
            else:
                sx.pending = b'68 6A F1 01 00 17\r'
        with patch.object(probe, 'gt_fixed', side_effect=send), patch(
                'time.monotonic', side_effect=(n * .01 for n in itertools.count())):
            probe.run_sx_monitor(gt, sx, rows.append, '4x')
        self.assertIn(packet(0x33, [6, 1]), gt.writes)
        self.assertEqual(sent, [(0x31, b'\x02\x01'),
                                (0x10, bytes.fromhex('686af10100'))])
        self.assertEqual(gt.settings, original)
        self.assertEqual(gt.state, 0)
        self.assertEqual(sx.writes[-1], b'x')
        self.assertTrue(any(r.get('prompt_observed') for r in rows))

    def test_gt_bench_guard_rejects_programming_before_send(self):
        port = FakePort()
        session = Session(port, lambda row: None)
        for command, payload in ((0x10, b'\x6c\x10\xf0\x36'),
                                 (0x10, b'\x68\x6a\xf1\x04'),
                                 (0x31, b'\x02\x02'), (0x11, b'')):
            with self.assertRaises(PermissionError):
                probe.gt_fixed(session, command, payload)
        self.assertEqual(port.writes, [])

    def test_listener_preserves_reported_off_mask_flag(self):
        port = FakePort()
        port.stuck_mask = True
        session = Session(port, lambda row: None)
        session.connect('dvi')
        session.capture('1x', 0)
        self.assertIn(packet(0x33, [4, 0, 0, 0, 0]), port.writes)
        self.assertNotIn(packet(0x33, [4, 0, 0, 0, 1]), port.writes)
        self.assertEqual(port.state, 0)

    def test_rejects_programming_and_arbitrary_commands_before_send(self):
        for command in ('34', '36', '2701', 'ATZ', '', '0100\r36', 'ATSP0'):
            sx = SX()
            with self.assertRaises(PermissionError):
                probe.exchange(sx, command, [])
            self.assertEqual(sx.writes, [])

    def test_query_waits_for_listener_ready(self):
        sx = SX()
        class Listener:
            def __init__(self, port, emit):
                self.emit = emit
            def connect(self, api):
                self.assert_api = api
            def capture(self, speed, seconds):
                assert not sx.queried.is_set()
                assert self.assert_api == 'dvi' and speed == '1x'
                self.emit({'kind': 'capture_started'})
                assert sx.queried.wait(1)
        rows = []
        with patch.object(probe, 'Session', Listener):
            probe.run(object(), sx, rows.append)
        self.assertEqual(sx.writes[-2:], [b'ATSH686AF1\r', b'0100\r'])
        self.assertIsNone(rows[-1]['error'])

    def test_pending_input_stops_before_commands(self):
        sx = SX()
        sx.pending = b'unsolicited'
        with self.assertRaises(ValueError):
            probe.run(object(), sx, lambda row: None)
        self.assertEqual(sx.writes, [])

    def test_wrong_protocol_prevents_header_and_query(self):
        sx = SX()
        with patch.object(probe.LocalQueries, 'query', side_effect=[
                'STN1130 v4.0.1', 'OBDLink SX r4.2', 'A0']):
            with self.assertRaises(ValueError):
                probe.run(object(), sx, lambda row: None)
        self.assertEqual(sx.writes, [])


if __name__ == '__main__':
    unittest.main()
