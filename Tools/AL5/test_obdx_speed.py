import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import obdx_capture as c
from obdx_speed import SpeedEvidence
from test_obdx_capture import network


class SpeedTests(unittest.TestCase):
    def make(self):
        events = []
        return SpeedEvidence(events.append), events

    def rx(self, speed, command, payload, line=1):
        speed.received({'kind': 'network' if command in (8, 9) else 'adapter',
                        'command': command, 'payload_hex': bytes(payload).hex(),
                        'source_line_end': line})

    def test_set_echo_does_not_establish_speed(self):
        speed, events = self.make()
        speed.outgoing(0x33, [6, 1], 2)
        self.rx(speed, 0x43, [6, 1], 3)
        self.assertIsNone(speed.adapter_speed)
        self.assertEqual(events[-1]['event'], 'adapter_speed_set_acknowledged')
        speed.outgoing(0x33, [6], 4)
        self.rx(speed, 0x43, [6, 1], 5)
        self.assertEqual(speed.adapter_speed, '4x')
        self.assertEqual(events[-1]['request_source_line'], 4)
        self.assertEqual(speed.summary()['actual_bus_speed'], 'unknown')

    def test_readback_mismatch_and_unfinished_request_are_explicit(self):
        speed, events = self.make()
        speed.outgoing(0x33, [6, 1], 1)
        self.rx(speed, 0x43, [6, 1])
        speed.outgoing(0x33, [6], 2)
        self.rx(speed, 0x43, [6, 0])
        self.assertIn('speed_set_readback_mismatch', speed.risks)
        speed.outgoing(0x33, [6, 1], 3)
        summary = speed.summary()
        self.assertIn('unfinished_speed_request', summary['gap_risk_counts'])
        self.assertIn('speed_set_without_separate_readback', summary['gap_risk_counts'])
        self.assertFalse(summary['transition_continuity_proven'])

    def test_unmatched_and_overlapping_statuses_never_confirm(self):
        speed, _ = self.make()
        self.rx(speed, 0x43, [6, 1])
        self.assertIsNone(speed.adapter_speed)
        speed.outgoing(0x33, [6], 1)
        speed.outgoing(0x33, [6, 1], 2)
        self.rx(speed, 0x43, [6, 1])
        self.assertIsNone(speed.adapter_speed)
        self.assertIn('overlapping_speed_requests', speed.risks)

    def test_local_network_off_changes_are_not_bus_transitions(self):
        speed, events = self.make()
        self.rx(speed, 0x41, [2, 0])
        for target in (0, 1, 0):
            speed.outgoing(0x33, [6, target], 1)
            self.rx(speed, 0x43, [6, target])
            speed.outgoing(0x33, [6], 2)
            self.rx(speed, 0x43, [6, target])
        self.assertTrue(all(e['scope'] == 'network_off_configuration'
                            for e in events if e['event'] == 'adapter_speed_readback'))
        self.assertEqual(speed.adapter_speed, '1x')
        self.assertNotIn('begin_high_speed_candidate', speed.events)

    def test_a0_permission_then_a1_flags_potential_capture_gap(self):
        speed, events = self.make()
        self.rx(speed, 0x43, [8, 0])
        speed.outgoing(0x33, [6], 1)
        self.rx(speed, 0x43, [6, 0])
        self.rx(speed, 8, [0x6C, 0xFE, 0xF1, 0xA0], 3)
        self.rx(speed, 8, [0x6C, 0xF1, 0x18, 0xE0], 4)
        self.rx(speed, 8, [0x6C, 0xFE, 0xF1, 0xA1], 5)
        begin = next(e for e in events if e['event'] == 'begin_high_speed_candidate')
        self.assertEqual(begin['permission_sources'], [0x18])
        self.assertTrue(begin['permission_context_seen'])
        self.assertEqual(begin['actual_bus_speed'], 'unknown')
        self.assertIn('begin_without_adapter_4x_readback', speed.risks)
        self.assertEqual(speed.adapter_speed, '1x')

    def test_crc_layout_is_required_and_crc_byte_is_not_service(self):
        speed, events = self.make()
        self.rx(speed, 8, [0x6C, 0xFE, 0xF0, 0xA1])
        self.assertEqual(events[-1]['event'], 'ambiguous_vpw_crc_layout')
        self.assertNotIn('begin_high_speed_candidate', speed.events)
        self.rx(speed, 0x43, [8, 1])
        self.rx(speed, 8, [0x6C, 0xFE, 0xF0, 0xA1])  # header + CRC only
        self.assertNotIn('begin_high_speed_candidate', speed.events)
        self.rx(speed, 8, [0x6C, 0xFE, 0xF0, 0xA1, 0x55])
        self.assertEqual(speed.events['begin_high_speed_candidate'], 1)

    def test_unrelated_headers_payloads_and_programming_prompt_are_ignored(self):
        speed, _ = self.make()
        self.rx(speed, 0x43, [8, 0])
        for p in ([0x6C, 0xFE, 0x18, 0xA1], [0x8C, 0xFE, 0xF0, 0xA1],
                  [0x6C, 0xFE, 0xF0, 0x23, 0xA1], [0x6C, 0xFE, 0xF0, 0xA2],
                  [0x6C, 0x10, 0x18, 0xE0]):
            self.rx(speed, 8, p)
        self.assertEqual(speed.events, {})

    def test_refusal_and_orphan_permission_remain_candidates(self):
        speed, events = self.make()
        self.rx(speed, 0x43, [8, 0])
        self.rx(speed, 8, [0x6C, 0xF0, 0x18, 0xE0])
        self.assertFalse(events[-1]['correlated_request'])
        self.rx(speed, 8, [0x6C, 0xFE, 0xF0, 0xA0])
        self.rx(speed, 8, [0x6C, 0xF0, 0x18, 0x7F, 0xA1, 0x22])
        self.assertTrue(events[-1]['correlated_request'])
        self.assertEqual(events[-1]['actual_bus_speed'], 'unknown')

    def test_unknown_status_and_errors_invalidate_confirmation(self):
        speed, _ = self.make()
        speed.outgoing(0x33, [6], 1)
        self.rx(speed, 0x43, [6, 0])
        self.rx(speed, 0x43, [6, 7])
        self.assertIsNone(speed.adapter_speed)
        speed.outgoing(0x33, [6], 2)
        self.rx(speed, 0x7F, [0x33, 6])
        self.assertIn('adapter_error_while_speed_request_pending', speed.risks)

    def test_prepare_context_does_not_leak_between_tools_or_targets(self):
        speed, events = self.make()
        self.rx(speed, 0x43, [8, 0])
        self.rx(speed, 8, [0x6C, 0x10, 0xF0, 0xA0])
        self.rx(speed, 8, [0x6C, 0xF0, 0x10, 0xE0])
        self.rx(speed, 8, [0x6C, 0x18, 0xF1, 0xA1])
        event = next(e for e in events if e['event'] == 'begin_high_speed_candidate')
        self.assertFalse(event['permission_context_seen'])
        self.assertEqual(event['permission_sources'], [])

    def test_begin_after_refusal_is_not_accepted_as_success(self):
        speed, events = self.make()
        self.rx(speed, 0x43, [8, 0])
        self.rx(speed, 8, [0x6C, 0xFE, 0xF0, 0xA0])
        self.rx(speed, 8, [0x6C, 0xF0, 0x18, 0x75, 0xA0])
        self.rx(speed, 8, [0x6C, 0xFE, 0xF0, 0xA1])
        event = next(e for e in events if e['event'] == 'begin_high_speed_candidate')
        self.assertEqual(event['refusal_sources'], [0x18])
        self.assertIn('begin_after_refusal_candidate', speed.risks)
        self.assertEqual(event['actual_bus_speed'], 'unknown')

    def test_terminal_summary_does_not_duplicate_pending_risks(self):
        speed, events = self.make()
        speed.outgoing(0x33, [6, 1], 1)
        first = speed.summary()
        count = len(events)
        self.assertEqual(first, speed.summary())
        self.assertEqual(count, len(events))

    def test_replay_correlates_split_reply_and_preserves_source(self):
        status = c.packet(0x43, [6, 0])
        rows = [{'kind': 'transport', 'api': 'dvi'},
                {'kind': 'adapter_tx', 'raw_hex': c.packet(0x33, [6]).hex()},
                {'kind': 'serial_rx', 'raw_hex': status[:3].hex()},
                {'kind': 'serial_rx', 'raw_hex': (status[3:] + c.packet(0x43, [8, 0]) +
                   network(bytes([0x6C, 0xFE, 0xF1, 0xA1]))).hex()},
                {'kind': 'result', 'success': True}]
        with tempfile.TemporaryDirectory() as root:
            source, output = Path(root) / 'source.jsonl', Path(root) / 'report.jsonl'
            source.write_text(''.join(json.dumps(r) + '\n' for r in rows))
            with patch('sys.argv', ['obdx_capture.py', 'replay', '--input', str(source),
                                   '--output', str(output)]), \
                    patch.object(c, 'WindowsSerial') as serial:
                c.main()
                serial.assert_not_called()
            events = [json.loads(line) for line in output.read_text().splitlines()]
            readback = next(r for r in events if r.get('event') == 'adapter_speed_readback')
            self.assertEqual(readback['source_line'], 4)
            self.assertEqual(readback['request_source_line'], 2)
            summary = next(r for r in events if r['kind'] == 'replay_summary')
            self.assertIn('begin_without_adapter_4x_readback', summary['speed_analysis']['gap_risk_counts'])
            self.assertFalse(summary['speed_analysis']['automatic_speed_tracking'])


if __name__ == '__main__':
    unittest.main()
