import unittest
from unittest.mock import patch

from probe_obdlink_monitor import probe


class FakePort:
    def __init__(self, reject=False, stop=b'STOPPED\r>'):
        self.writes, self.incoming = [], []
        self.reject, self.stop = reject, stop

    def write(self, wire):
        self.writes.append(wire)
        replies = {b'STI\r': b'STN1130 v4.0.1\r>',
                   b'STDI\r': b'OBDLink SX r4.2\r>',
                   b'ATDPN\r': b'2\r>', b'ATRV\r': b'0.0V\r>',
                   b'STMA\r': b'?\r>' if self.reject else b'STMA\r',
                   b'x': self.stop}
        self.incoming = [replies[wire]]

    def read(self):
        return self.incoming.pop(0) if self.incoming else b''


class MonitorTests(unittest.TestCase):
    def test_requires_disconnection(self):
        port = FakePort()
        with self.assertRaises(PermissionError):
            probe(port, {'queries': []})
        self.assertEqual(port.writes, [])

    def run_probe(self, port):
        report = {'queries': []}
        # Deterministic clock advances keep empty-bus waits bounded offline.
        with patch('time.monotonic', side_effect=(x * 0.01 for x in range(1000))):
            probe(port, report, usb_only_confirmed=True, duration=0.05)
        return report

    def test_monitor_and_single_noncr_stop(self):
        port = FakePort()
        report = self.run_probe(port)
        self.assertTrue(report['monitor_entry_exit_confirmed'])
        self.assertEqual(port.writes, [b'STI\r', b'STDI\r', b'ATDPN\r',
                                      b'ATRV\r', b'STMA\r', b'x', b'STI\r'])

    def test_unsupported_monitor_does_not_interrupt_prompt(self):
        port = FakePort(reject=True)
        report = self.run_probe(port)
        self.assertFalse(report['monitor_entry_exit_confirmed'])
        self.assertEqual(port.writes[-1], b'STMA\r')

    def test_stop_timeout_no_followup_or_retry(self):
        port = FakePort(stop=b'')
        with self.assertRaises(ValueError):
            self.run_probe(port)
        self.assertEqual(port.writes[-1], b'x')
        self.assertEqual(port.writes.count(b'x'), 1)

    def test_old_firmware_prompt_only_then_local_identity(self):
        port = FakePort(stop=b'\r>')
        report = self.run_probe(port)
        self.assertTrue(report['monitor_entry_exit_confirmed'])
        self.assertFalse(report['stop_message_present'])
        self.assertIn('STN1130', report['post_stop_identity'])

    def test_unexpected_stop_text_rejected(self):
        with self.assertRaises(ValueError):
            self.run_probe(FakePort(stop=b'ERROR\r>'))

    def test_extra_stop_prompt_rejected(self):
        with self.assertRaises(ValueError):
            self.run_probe(FakePort(stop=b'STOPPED\r>>'))


if __name__ == '__main__':
    unittest.main()
