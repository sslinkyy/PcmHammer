import unittest
from inspect_obdlink import LocalQueries, QUERIES, inspect


class FakePort:
    def __init__(self, firmware=b'STN1130 v5.10.0', initial=b''):
        self.firmware, self.initial = firmware, initial
        self.response, self.writes = [], []

    def write(self, wire):
        self.writes.append(wire)
        self.response = [self.firmware + b'\r', b'>']

    def read(self):
        if self.initial:
            value, self.initial = self.initial, b''
            return value
        return self.response.pop(0) if self.response else b''


class InspectionTests(unittest.TestCase):
    def test_reject_nonlocal_and_repeat(self):
        port = FakePort()
        client = LocalQueries(port, [])
        for command in ('', '\r', '0100', 'ATZ', 'ATMA', 'STPO', 'STP 1',
                        'STPBR 41600', 'ATI\r0100', 'sti'):
            with self.assertRaises(PermissionError):
                client.query(command)
        self.assertEqual(port.writes, [])

    def test_fragmented_local_queries(self):
        port, report = FakePort(), {'queries': []}
        inspect(port, report)
        self.assertTrue(report['inspection_complete'])
        self.assertEqual(port.writes, [(x + '\r').encode() for x in QUERIES])
        self.assertTrue(all(x['complete'] for x in report['queries']))

    def test_wrong_identity_stops(self):
        port = FakePort(b'STN2120 v5.0.0')
        with self.assertRaises(ValueError):
            inspect(port, {'queries': []})
        self.assertEqual(len(port.writes), 2)

    def test_pending_traffic_stops_without_send(self):
        port = FakePort(initial=b'active')
        with self.assertRaises(ValueError):
            inspect(port, {'queries': []})
        self.assertEqual(port.writes, [])

    def test_timeout_preserves_partial_no_retry(self):
        port, rows = FakePort(), []
        with self.assertRaises(TimeoutError):
            LocalQueries(port, rows, timeout=0).query('ATI')
        self.assertEqual(port.writes, [b'ATI\r'])
        self.assertFalse(rows[0]['complete'])

    def test_prompt_trailing_data_rejected(self):
        port = FakePort(firmware=b'ID>unexpected')
        with self.assertRaises(ValueError):
            LocalQueries(port, []).query('ATI')


if __name__ == '__main__':
    unittest.main()
