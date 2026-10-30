import tempfile
import unittest
import json
from pathlib import Path
from unittest.mock import patch

import obdx_capture as c
import probe_obdx_filter_links as probe
from test_obdx_capture import FakePort


class LinkedPort(FakePort):
    def __init__(self, *, derived_mask=False, mask_sets_from=False):
        super().__init__()
        self.derived_mask = derived_mask
        self.mask_sets_from = mask_sets_from
        self.settings.update({(0x24, 3): b'\x03\x01',
                              (0x33, 0): b'\x00\xf0\x01',
                              (0x33, 1): b'\x01\x10\x00',
                              (0x33, 2): b'\x02\x20\xf0\x01',
                              (0x33, 3): b'\x03\x10\xef\x00',
                              (0x33, 4): b'\x04\x00\xff\x1f\x00',
                              (0x33, 6): b'\x06\x01',
                              (0x33, 7): b'\x07\x01',
                              (0x33, 8): b'\x08\x01'})

    def write(self, wire):
        super().write(wire)
        if wire.startswith(b'AT') or wire.startswith(b'DX'):
            return
        command, payload = wire[0], wire[2:-1]
        if command == 0x33 and payload[0] == 4:
            if len(payload) == 1 and self.derived_mask:
                value = self.settings[0x33, 4][:-1] + self.settings[0x33, 1][-1:]
                self.replies[-1] = c.packet(0x43, value)
            elif len(payload) > 1 and self.mask_sets_from:
                self.settings[0x33, 1] = self.settings[0x33, 1][:-1] + payload[-1:]


class SharedMaskPort(LinkedPort):
    """Observed GT model: exact flags share enable; ON expands shared mask.

    The mask setter updates the three mask bytes but its flag is not used;
    mask GET reports the same shared enable as both exact-filter GETs.
    Range settings remain independent in this bounded model.
    """
    def __init__(self, mask):
        super().__init__()
        self.settings[0x33, 0] = b'\x00\xf0\x01'
        self.settings[0x33, 1] = b'\x01\x10\x01'
        self.settings[0x33, 4] = b'\x04' + mask + b'\x01'

    def write(self, wire):
        command, payload = wire[0], wire[2:-1]
        shared_enable = self.settings[0x33, 1][-1]
        super().write(wire)
        if command == 0x33 and len(payload) > 1:
            if payload[0] in (0, 1):
                shared_enable = payload[-1]
                for sub in (0, 1):
                    self.settings[0x33, sub] = self.settings[0x33, sub][:-1] + bytes([shared_enable])
                mask = bytearray(self.settings[0x33, 4])
                if shared_enable:
                    mask[payload[0] + 2] = 0xff  # TO: middle byte; FROM: final byte.
                mask[-1] = shared_enable
                self.settings[0x33, 4] = bytes(mask)
            elif payload[0] == 4:
                self.settings[0x33, 4] = payload[:-1] + bytes([shared_enable])


class FilterLinksTests(unittest.TestCase):
    def assert_off_only(self, port):
        for wire in port.writes:
            self.assertTrue(c.permitted(wire[0], wire[2:-1]))
            self.assertNotIn(wire[0], (0x10, 0x11, 0x25))
            if wire[0] == 0x31:
                self.assertIn(wire[2:-1], (b'\x01', b'\x02', b'\x02\x00'))

    def test_derived_mask_flag_is_observation_and_all_readbacks_match(self):
        port = LinkedPort(derived_mask=True)
        original = dict(port.settings)
        rows = []
        result = probe.run(port, rows.append, 'dvi')
        self.assertEqual(16, result['observations'])
        self.assertEqual(4, result['readback_mismatches'])
        cases = [r for r in rows if r['kind'] == 'filter_link_observation']
        self.assertEqual(16, len(cases))
        self.assertTrue(all(len(r['all_filter_readbacks']) == 5 for r in cases))
        self.assertEqual(8, sum(r['changed_setting'] == 'mask_filter' for r in cases))
        intermediate = next(r for r in cases if r['case'] == 'to0_from1_to_filter')
        self.assertEqual({'to': 0, 'from': 1}, intermediate['target_exact_flags'])
        self.assertEqual({'to': 0, 'from': 0}, intermediate['observed_exact_flags'])
        self.assertFalse(intermediate['target_exact_flags_reached'])
        # A derived GET cannot reveal the underlying stored mask flag. Compare
        # the complete observable contract, which is what the probe records.
        self.assertEqual(original, port.settings)
        restored = [r for r in rows if r['kind'] == 'filter_snapshot'][-1]
        self.assertEqual('restored_all_readbacks', restored['snapshot'])
        self.assertEqual(9, len(restored['setting_readbacks']))
        self.assert_off_only(port)

    def test_matching_gets_do_not_claim_restoration_of_different_hidden_mask_flag(self):
        port = LinkedPort(derived_mask=True)
        port.settings[0x33, 4] = b'\x04\x00\xff\x1f\x01'
        original_hidden_mask = port.settings[0x33, 4]
        rows = []
        result = probe.run(port, rows.append, 'dvi')
        # Initial GET reports FROM's zero flag, hiding the mask's stored one.
        # Reapplying that GET value changes hidden state, despite equal GETs.
        self.assertNotEqual(original_hidden_mask, port.settings[0x33, 4])
        self.assertEqual(b'\x04\x00\xff\x1f\x00', port.settings[0x33, 4])
        snapshots = [r for r in rows if r['kind'] == 'filter_snapshot']
        self.assertEqual(snapshots[0]['setting_readbacks'], snapshots[-1]['setting_readbacks'])
        receipt = next(r for r in rows if r['kind'] == 'settings_readback_restoration')
        self.assertTrue(receipt['observable_readbacks_match_original'])
        self.assertIsNone(receipt['hidden_setting_state_restored'])
        self.assertTrue(result['observable_readbacks_match_original'])
        self.assertIsNone(result['hidden_setting_state_restored'])
        self.assertFalse(any(r['kind'] == 'settings_restored' for r in rows))
        self.assert_off_only(port)

    def test_shared_mask_source_only_and_enabled_zero_restore_mask_last(self):
        for mask in (bytes.fromhex('0000ff'), bytes.fromhex('000000')):
            with self.subTest(mask=mask.hex()):
                port = SharedMaskPort(mask)
                original = dict(port.settings)
                rows = []
                result = probe.run(port, rows.append, 'dvi')
                snapshots = [r for r in rows if r['kind'] == 'filter_snapshot']
                self.assertEqual(snapshots[0]['setting_readbacks'], snapshots[-1]['setting_readbacks'])
                self.assertEqual(original, port.settings)
                self.assertTrue(result['observable_readbacks_match_original'])
                self.assertIsNone(result['hidden_setting_state_restored'])
                mask_setters = [w for w in port.writes if w[:3] == b'\x33\x05\x04']
                self.assertEqual(9, len(mask_setters))  # eight cases and one restoration
                setting_writes = [w for w in port.writes if w[0] in (0x24, 0x33) and w[1] > 1]
                self.assertEqual(original[0x33, 4], setting_writes[-1][2:-1])
                self.assert_off_only(port)

    def test_incompatible_mask_setter_coupling_fails_without_order_retry(self):
        port = LinkedPort(mask_sets_from=True)
        port.settings[0x33, 4] = b'\x04\x00\xff\x1f\x01'
        rows = []
        with self.assertRaisesRegex(c.ProtocolError, 'restoration coupling unsupported'):
            probe.run(port, rows.append, 'dvi')
        mismatch = next(r for r in rows if r['kind'] == 'restoration_mismatch')
        self.assertIn('from_filter', mismatch['differences'])
        self.assertFalse(mismatch['restoration_supported'])
        self.assertFalse(mismatch['retry_attempted'])
        self.assertEqual(0, port.state)
        self.assertFalse(any(r['kind'] == 'probe_summary' for r in rows))
        writes = [(w[0], w[2:-1]) for w in port.writes if len(w[2:-1]) > 1]
        settings_writes = [w for w in writes if w[0] in (0x24, 0x33)]
        self.assertEqual([b'\x00\xf0\x01', b'\x01\x10\x00', b'\x04\x00\xff\x1f\x01'],
                         [payload for _, payload in settings_writes[-3:]])
        self.assertEqual(25, len(settings_writes))  # sixteen cases, nine restoration writes
        self.assert_off_only(port)

    def test_unknown_identity_stops_without_mutations(self):
        class WrongIdentity(LinkedPort):
            def write(self, wire):
                super().write(wire)
                if wire[:3] == b'\x22\x01\x03':
                    self.replies[-1] = c.packet(0x32, b'\x03Other Adapter')
        port = WrongIdentity()
        with self.assertRaisesRegex(c.ProtocolError, 'identity'):
            probe.run(port, lambda _: None, 'dvi')
        self.assertEqual(1, len(port.writes))

    def test_unknown_snapshot_shape_does_not_start_probe(self):
        class Malformed(LinkedPort):
            def write(self, wire):
                super().write(wire)
                if wire[:3] == b'\x33\x01\x03':
                    self.replies[-1] = c.packet(0x43, b'\x03\x00\x00\x02')
        port = Malformed()
        rows = []
        with self.assertRaisesRegex(c.ProtocolError, 'Unknown setting shape'):
            probe.run(port, rows.append, 'dvi')
        self.assertFalse(any(w[0] == 0x33 and w[1] > 1 for w in port.writes))
        self.assertEqual(0, port.state)
        self.assertTrue(any(r['kind'] == 'unknown_setting_shape' for r in rows))
        self.assert_off_only(port)

    def test_unexpected_network_on_stops_then_disables_and_restores(self):
        class GoesOn(LinkedPort):
            triggered = False
            def write(self, wire):
                super().write(wire)
                if not self.triggered and wire[:3] == b'\x33\x03\x00':
                    self.triggered = True
                    self.state = 1
        port = GoesOn()
        original = dict(port.settings)
        rows = []
        with self.assertRaisesRegex(c.ProtocolError, 'must already be OFF'):
            probe.run(port, rows.append, 'dvi')
        self.assertEqual(original, port.settings)
        self.assertEqual(0, port.state)
        self.assertFalse(any(r['kind'] == 'filter_link_observation' for r in rows))
        self.assert_off_only(port)

    def test_final_snapshot_catches_late_restore_cross_effect(self):
        class LateCrossEffect(LinkedPort):
            from_writes = 0
            def write(self, wire):
                super().write(wire)
                if wire[:3] == b'\x33\x03\x01':
                    self.from_writes += 1
                    if self.from_writes == 5:  # four experiment states, then restoration
                        self.settings[0x33, 2] = b'\x02\x00\xff\x01'
        port = LateCrossEffect()
        rows = []
        with self.assertRaisesRegex(c.ProtocolError, 'Final complete settings readback snapshot'):
            probe.run(port, rows.append, 'dvi')
        mismatch = next(r for r in rows if r['kind'] == 'restoration_mismatch')
        self.assertIn('to_range_filter', mismatch['differences'])
        self.assertEqual(0, port.state)
        self.assertFalse(any(r['kind'] == 'probe_summary' for r in rows))
        self.assert_off_only(port)

    def test_cancellation_restores_state_without_retrying_probe(self):
        class Cancelled(LinkedPort):
            triggered = False
            def write(self, wire):
                if not self.triggered and wire[:3] == b'\x33\x05\x04':
                    self.triggered = True
                    raise KeyboardInterrupt()
                super().write(wire)
        port = Cancelled()
        original = dict(port.settings)
        rows = []
        with self.assertRaises(KeyboardInterrupt):
            probe.run(port, rows.append, 'dvi')
        self.assertEqual(original, port.settings)
        self.assertEqual(0, port.state)
        self.assertEqual(2, sum(r['kind'] == 'filter_link_observation' for r in rows))
        self.assert_off_only(port)

    def test_guard_blocks_listen_before_transport_and_output_is_exclusive(self):
        port = LinkedPort()
        session = probe.OffSession(port, lambda _: None)
        session.dvi = True
        for payload in ([2, 1], [2, 2], [1, 1]):
            with self.assertRaises(PermissionError):
                session.send(0x31, payload)
        self.assertEqual([], port.writes)
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'existing.jsonl'
            output.write_text('preserve', encoding='utf8')
            with patch.object(probe, 'WindowsSerial', side_effect=AssertionError('Serial must not open')):
                with self.assertRaises(FileExistsError):
                    probe.main(['--port', 'COM9', '--api', 'dvi', '--output', str(output)])
            self.assertEqual('preserve', output.read_text(encoding='utf8'))

    def test_failed_off_ack_blocks_restore_and_is_not_success(self):
        class RefusesOff(LinkedPort):
            def write(self, wire):
                super().write(wire)
                if wire[:4] == b'\x31\x02\x02\x00':
                    self.replies[-1] = c.packet(0x41, b'\x02\x01')
        port = RefusesOff()
        rows = []
        with self.assertRaisesRegex(c.ProtocolError, 'Unexpected adapter acknowledgment'):
            probe.run(port, rows.append, 'dvi')
        self.assertEqual(1, sum(w[:4] == b'\x31\x02\x02\x00' for w in port.writes))
        self.assertTrue(any(r['kind'] == 'cleanup' and not r['network_off_acknowledged'] for r in rows))
        self.assertFalse(any(r['kind'] in ('settings_readback_restoration', 'probe_summary') for r in rows))
        self.assert_off_only(port)

    def test_close_failure_is_retained_as_failed_terminal_result(self):
        class CloseFails(LinkedPort):
            def close(self):
                raise OSError('Handle cleanup failed')
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'probe.jsonl'
            with patch.object(probe, 'WindowsSerial', return_value=CloseFails()):
                with self.assertRaisesRegex(OSError, 'Handle cleanup failed'):
                    probe.main(['--port', 'COM9', '--api', 'dvi', '--output', str(output)])
            rows = [json.loads(line) for line in output.read_text(encoding='utf8').splitlines()]
            self.assertEqual({'kind': 'result', 'success': False, 'error': 'Handle cleanup failed',
                              'error_type': 'OSError'}, rows[-1])


if __name__ == '__main__':
    unittest.main()
