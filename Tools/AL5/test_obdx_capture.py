import unittest
from unittest.mock import patch
import tempfile
from pathlib import Path
import json
import contextlib
import io

import obdx_capture as c


def network(payload, large=False, stamp=None):
    body = bytes([9 if large else 8])
    if stamp is not None:
        body += stamp
    body += len(payload).to_bytes(2 if large else 1, 'big') + payload
    return body + bytes([(~sum(body)) & 255])


class FakePort:
    def __init__(self):
        self.writes = []
        self.replies = []
        self.state = 0
        self.reject_listen = False
        self.selected_protocol = b'\x01\x01'
        self.stuck_mask = False
        self.mask_query_flag_stuck_on = False
        self.settings = {(cmd, sub): bytes([sub]) + bytes(size - 1)
                         for cmd, sub, size, _ in c.SETTINGS}

    def write(self, data):
        self.writes.append(data)
        if data == b'AT@1\r':
            self.replies.append(b'AT@1\r\nOBDX Pro GT\r\n>')
            return
        if data == b'DXDP1\r':
            self.replies.append(b'DXDP1\r\nOK\r\n>')
            return
        if sum(data) & 255 != 255:
            raise AssertionError('Outgoing checksum')
        command, p = data[0], data[2:-1]
        if not c.permitted(command, p):
            raise AssertionError('Forbidden adapter operation')
        if command == 0x22:
            values = {0: bytes([2, 0, 0, 0]), 1: bytes([1, 2, 3, 4]),
                      2: b'\x00\x01', 3: b'OBDX Pro GT', 4: bytes(range(12)),
                      5: b'\x02\x00', 6: b'\x01'}
            p += values[p[0]]
        elif command == 0x31 and p[0] == 1:
            if len(p) == 2:
                self.selected_protocol = p
            else:
                p = self.selected_protocol
        elif command == 0x31 and p[0] == 2:
            if len(p) == 2:
                self.state = p[1]
            else:
                p += bytes([self.state])
            if self.reject_listen and p == b'\x02\x02':
                p = b'\x02\x01'
        elif (command, p[0]) in self.settings:
            if len(p) == 1:
                p = self.settings[command, p[0]]
                if self.mask_query_flag_stuck_on and command == 0x33 and p[0] == 4:
                    p = p[:-1] + b'\x01'
            else:
                if not (self.stuck_mask and command == 0x33 and p[0] == 4):
                    self.settings[command, p[0]] = p
        elif len(p) == 1:
            p += b'\x00'
        self.replies.append(c.packet(command + 0x10, p))

    def read(self):
        return self.replies.pop(0) if self.replies else b''


class CoupledFilterPort(FakePort):
    """Model the closed 2026-10-29 OFF-only probe, not physical reception."""
    def write(self, data):
        if data in (b'AT@1\r', b'DXDP1\r'):
            return super().write(data)
        command, p = data[0], data[2:-1]
        previous_mask = self.settings[0x33, 4]
        if command in (0x24, 0x33) and len(p) > 1:
            if self.state != 0:
                raise AssertionError('Setting changed while network not OFF')
        super().write(data)
        if command == 0x33 and len(p) > 1:
            if p[0] in (0, 1):
                mask = bytearray(previous_mask)
                if p[-1]:
                    mask[2 + p[0]] |= 255
                mask[-1] = p[-1]
                self.settings[0x33, 4] = bytes(mask)
                for sub in (0, 1):
                    value = self.settings[0x33, sub]
                    self.settings[0x33, sub] = value[:-1] + p[-1:]
            elif p[0] == 4:
                # MASK's requested flag does not control the observed enable.
                self.settings[0x33, 4] = p[:-1] + previous_mask[-1:]


class ExperimentalFilterTests(unittest.TestCase):
    def session(self, port=None):
        port, events = port or CoupledFilterPort(), []
        session = c.Session(port, events.append)
        session.connect('dvi')
        return session, port, events

    def test_full_profile_verified_before_listen_and_observable_state_restored(self):
        for original_mask in ('0400000000', '040000ff01', '0400000001'):
            with self.subTest(original_mask=original_mask):
                session, port, events = self.session()
                flag = bytes.fromhex(original_mask)[-1:]
                port.settings[0x33, 0] = b'\x00\xF0' + flag
                port.settings[0x33, 1] = b'\x01\x10' + flag
                port.settings[0x33, 4] = bytes.fromhex(original_mask)
                original = dict(port.settings)
                session.capture('4x', 0, all_sources=True)
                self.assertEqual(port.settings, original)
                self.assertEqual(port.state, 0)
                start = next(e for e in events if e['kind'] == 'capture_started')
                self.assertEqual(start['receive_scope'], 'experimental_mask_all')
                self.assertFalse(start['live_receive_verified'])
                self.assertIsNone(start['source_filter'])
                before_listen = port.writes[:port.writes.index(c.packet(0x31, [2, 2]))]
                self.assertEqual(before_listen[-5:],
                                 [c.packet(0x33, [i]) for i in range(5)])
                profile = next(e for e in events if e['kind'] == 'experimental_filter_profile')
                self.assertTrue(profile['readbacks_match'])
                self.assertEqual(profile['observed_readbacks'],
                                 ['000001', '011001', '02000000', '03000000', '0400000001'])
                changes = [w for w in port.writes if w[0] in (0x24, 0x33) and w[1] > 1]
                self.assertEqual(changes[-1], c.packet(0x33, bytes.fromhex(original_mask)))
                expected_final = [c.packet(cmd, [sub]) for cmd, sub, _, _ in c.SETTINGS]
                self.assertEqual(port.writes[-10:-1], expected_final)
                self.assertEqual(port.writes[-1], c.packet(0x31, [2]))
                self.assertEqual(events[-1]['kind'], 'settings_readback_restoration')
                self.assertTrue(events[-1]['observable_readbacks_match_original'])
                self.assertIsNone(events[-1]['hidden_setting_state_restored'])
                states = [w[3] for w in port.writes if w[:3] == b'\x31\x02\x02']
                self.assertEqual(states, [0, 2, 0])
                self.assertTrue(all(c.permitted(w[0], w[2:-1]) for w in port.writes))

    def test_rejected_mask_or_late_cross_filter_change_blocks_listener(self):
        for fault in ('mask', 'to_filter', 'range'):
            with self.subTest(fault=fault):
                session, port, events = self.session()
                original = dict(port.settings)
                write = port.write
                def corrupt(wire):
                    write(wire)
                    if wire == c.packet(0x33, [4, 0, 0, 0, 1]):
                        if fault == 'mask':
                            port.settings[0x33, 4] = b'\x04\x00\x00\xff\x01'
                        elif fault == 'to_filter':
                            port.settings[0x33, 0] = b'\x00\x99\x01'
                        else:
                            port.settings[0x33, 2] = b'\x02\x01\x02\x01'
                port.write = corrupt
                with self.assertRaises(c.ProtocolError):
                    session.capture('4x', 0, all_sources=True)
                self.assertNotIn(c.packet(0x31, [2, 2]), port.writes)
                self.assertEqual(port.settings, original)
                self.assertEqual(port.state, 0)
                self.assertTrue(events[-1]['observable_readbacks_match_original'])

    def test_inconsistent_original_enable_flags_fail_before_setting_mutations(self):
        session, port, events = self.session()
        port.settings[0x33, 4] = b'\x04\x00\x00\x00\x01'
        original = dict(port.settings)
        with self.assertRaisesRegex(c.ProtocolError, 'original filter enable coupling'):
            session.capture('4x', 0, all_sources=True)
        self.assertEqual(port.settings, original)
        self.assertFalse(any(w[0] in (0x24, 0x33) and w[1] > 1 for w in port.writes))
        self.assertNotIn(c.packet(0x31, [2, 2]), port.writes)
        self.assertFalse(events[-1]['attempted'])
        self.assertEqual(port.state, 0)

    def test_independent_filter_firmware_cannot_satisfy_experimental_profile(self):
        session, port, _ = self.session(FakePort())
        with self.assertRaisesRegex(c.ProtocolError, 'full filter profile mismatch'):
            session.capture('4x', 0, all_sources=True)
        self.assertNotIn(c.packet(0x31, [2, 2]), port.writes)
        self.assertEqual(port.state, 0)

    def test_cancellation_after_exact_enable_restores_shared_mask(self):
        session, port, events = self.session()
        original = dict(port.settings)
        write = port.write
        def cancel(wire):
            if wire == c.packet(0x33, [4, 0, 0, 0, 1]):
                raise KeyboardInterrupt()
            write(wire)
        port.write = cancel
        with self.assertRaises(KeyboardInterrupt):
            session.capture('4x', 1, all_sources=True)
        self.assertEqual(port.settings, original)
        self.assertEqual(port.state, 0)
        self.assertTrue(events[-1]['observable_readbacks_match_original'])

    def test_final_snapshot_detects_late_cross_setting_restoration_change(self):
        session, port, events = self.session()
        write = port.write
        def corrupt_restore(wire):
            write(wire)
            if wire == c.packet(0x33, [4, 0, 0, 0, 0]) and c.packet(0x31, [2, 2]) in port.writes:
                port.settings[0x33, 8] = b'\x08\x01'
        port.write = corrupt_restore
        with self.assertRaisesRegex(c.ProtocolError, 'Final experimental setting snapshot'):
            session.capture('4x', 0, all_sources=True)
        self.assertEqual(port.state, 0)
        self.assertFalse(events[-1]['success'])
        self.assertFalse(events[-1]['observable_readbacks_match_original'])

    def test_active_capture_interruption_returns_off_and_restores_settings(self):
        for failure in (KeyboardInterrupt(), c.ProtocolError('capture interrupted')):
            with self.subTest(failure=type(failure).__name__):
                session, port, events = self.session()
                original = dict(port.settings)
                read = port.read
                def interrupt_read():
                    if port.state == 2 and not port.replies:
                        raise failure
                    return read()
                port.read = interrupt_read
                with self.assertRaises(type(failure)):
                    session.capture('4x', 1, all_sources=True)
                self.assertEqual(port.state, 0)
                self.assertEqual(port.settings, original)
                self.assertTrue(events[-1]['observable_readbacks_match_original'])

    def test_api_filter_choices_rejected_before_commands(self):
        session, port, _ = self.session()
        port.writes.clear()
        for operation in (session.capture, session.configure_listener):
            args = ('4x', 0) if operation == session.capture else ('4x',)
            with self.assertRaises(ValueError):
                operation(*args, source_id=0x10, all_sources=True)
        self.assertEqual(port.writes, [])

    def test_cli_filter_choices_rejected_before_output_or_serial(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / 'capture.jsonl'
            args = ['obdx_capture.py', 'capture', '--port', 'COM99', '--speed', '4x',
                    '--source-id', '0x10', '--all-sources', '--output', str(output)]
            with patch('sys.argv', args), patch.object(c, 'WindowsSerial') as serial, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                c.main()
            serial.assert_not_called()
            self.assertFalse(output.exists())


class CaptureTests(unittest.TestCase):
    def test_only_exact_local_commands_reach_transport(self):
        port = FakePort()
        session = c.Session(port, lambda _: None)
        session.dvi = True
        for opcode in range(256):
            if c.permitted(opcode, [1]):
                continue
            with self.assertRaises(PermissionError):
                session.send(opcode, [1])
        self.assertEqual([], port.writes)
        for payload in ([2, 1], [6, 0], [6, 1], [1, 2], [2, 2, 0]):
            with self.assertRaises(PermissionError):
                session.send(0x31, payload)
        for opcode in (0x10, 0x11):
            for service in range(256):
                with self.assertRaises(PermissionError):
                    session.send(opcode, [0x6C, 0x18, 0xF0, service])
        self.assertEqual([], port.writes)

    def test_elm_does_not_accept_vehicle_data_or_reset(self):
        port = FakePort()
        session = c.Session(port, lambda _: None)
        for command in ('01', 'ATZ', 'ATSP2', 'ATMA', 'DXSD6C18F034',
                        'AT@1\r01', 'DXDP0', 'AT@1\n'):
            with self.assertRaises(PermissionError):
                session.elm(command)
        self.assertEqual([], port.writes)

    def test_inspection_disables_previously_enabled_network(self):
        port = FakePort()
        port.state = 1
        events = []
        session = c.Session(port, events.append)
        session.connect('elm')
        result = session.inspect()
        self.assertEqual(result['firmware'], '1.2.3.4')
        self.assertEqual(port.state, 0)
        for wire in port.writes[2:]:
            if wire[1] != 1:
                self.assertEqual(wire, c.packet(0x31, [2, 0]))
            self.assertNotIn(wire[0], (0x10, 0x11, 0x25))
        self.assertEqual(result['network_state_before_inspection_cleanup'], '0201')
        self.assertEqual(result['network_state'], '0200')

    def test_listener_uses_only_listen_and_cleans_up(self):
        for speed in ('1x', '4x'):
            port, events = FakePort(), []
            session = c.Session(port, events.append)
            session.connect('dvi')
            session.capture(speed, 0)
            self.assertEqual(port.state, 0)
            states = [wire[3] for wire in port.writes
                      if wire[:3] == b'\x31\x02\x02']
            self.assertEqual(states, [0, 2, 0])
            self.assertTrue(any(e.get('network_off_acknowledged') for e in events))
            self.assertFalse(session.decoder.timestamps)
            expected = []
            for cmd, sub, size, _ in c.SETTINGS:
                expected.extend([c.packet(cmd, bytes([sub]) + bytes(size - 1)),
                                 c.packet(cmd, [sub])])
            self.assertEqual(port.writes[-len(expected):], expected)

    def test_wrong_listen_ack_fails_and_turns_network_off(self):
        port = FakePort()
        port.reject_listen = True
        session = c.Session(port, lambda _: None)
        session.connect('dvi')
        with self.assertRaises(c.ProtocolError):
            session.capture('1x', 0)
        self.assertEqual(port.state, 0)

    def test_cancellation_turns_network_off(self):
        port, events = FakePort(), []
        session = c.Session(port, events.append)
        session.connect('dvi')
        with patch.object(session, 'configure_listener', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                session.capture('1x', 1)
        self.assertTrue(any(e.get('network_off_acknowledged') for e in events))

    def test_cleanup_failure_is_not_reported_as_success(self):
        session = c.Session(FakePort(), lambda _: None)
        events = []
        session.emit = events.append
        with patch.object(session, 'configure_listener'), \
                patch.object(session, 'request', side_effect=TimeoutError('OFF timeout')):
            with self.assertRaises(TimeoutError):
                session.capture('1x', 0)
        self.assertFalse(events[-1]['network_off_acknowledged'])

    def test_setting_restore_failure_keeps_off_and_reports_failure(self):
        port, events = FakePort(), []
        session = c.Session(port, events.append)
        session.connect('dvi')
        original_write = port.write
        def fail_restore(wire):
            if wire == c.packet(0x24, [3, 0]):
                raise OSError('Restore failed')
            original_write(wire)
        port.write = fail_restore
        with self.assertRaises(OSError):
            session.capture('1x', 0)
        self.assertEqual(port.state, 0)
        self.assertEqual(events[-1]['kind'], 'settings_restored')
        self.assertFalse(events[-1]['success'])

    def test_listener_restores_nondefault_filters_and_crc_policy(self):
        port = FakePort()
        for cmd, sub, size, label in c.SETTINGS:
            if 'filter' in label:
                port.settings[cmd, sub] = bytes([sub]) + bytes([0x18] * (size - 2)) + b'\x01'
        port.settings[0x33, 7] = b'\x07\x00'
        original = dict(port.settings)
        session = c.Session(port, lambda _: None)
        session.connect('dvi')
        session.capture('4x', 0)
        self.assertEqual(port.settings, original)
        self.assertEqual(port.state, 0)

    def test_local_probe_never_enables_network_and_restores_settings(self):
        port = FakePort()
        port.settings[0x24, 3] = b'\x03\x01'
        original = dict(port.settings)
        session = c.Session(port, lambda _: None)
        session.connect('dvi')
        result = session.probe_settings()
        self.assertFalse(result['live_receive_verified'])
        self.assertEqual(result['local_settings_verified'],
                         [label for _, _, _, label in c.SETTINGS])
        self.assertEqual(original, port.settings)
        self.assertFalse(any(wire[:3] == b'\x31\x02\x02' and wire[3] != 0
                             for wire in port.writes))

    def test_echo_only_mask_ack_cannot_enable_listener(self):
        port = FakePort()
        port.stuck_mask = True
        port.settings[0x33, 4] = b'\x04\x00\xff\x00\x01'
        session = c.Session(port, lambda _: None)
        session.connect('dvi')
        with self.assertRaisesRegex(c.ProtocolError, 'readback mismatch'):
            session.capture('1x', 0)
        self.assertEqual(port.state, 0)
        self.assertNotIn(c.packet(0x31, [2, 2]), port.writes)
        self.assertEqual(port.settings[0x33, 4], b'\x04\x00\xff\x00\x01')

    def test_zero_mask_configuration_works_with_stuck_query_flag(self):
        port, events = FakePort(), []
        port.mask_query_flag_stuck_on = True
        port.settings[0x33, 4] = b'\x04\x00\xff\x00\x01'
        original = dict(port.settings)
        session = c.Session(port, events.append)
        session.connect('dvi')
        result = session.probe_mask()
        self.assertEqual([r['readback_matches'] for r in result['cases']], [False, False, True])
        self.assertEqual(original, port.settings)
        self.assertNotIn(c.packet(0x31, [2, 2]), port.writes)
        self.assertEqual(port.state, 0)
        session.capture('1x', 0)
        self.assertIn(c.packet(0x33, [4, 0, 0, 0, 1]), port.writes)
        self.assertEqual(original, port.settings)
        self.assertEqual(port.state, 0)

    def test_mask_probe_restore_failure_stops_remaining_cases(self):
        port, events = FakePort(), []
        port.settings[0x33, 4] = b'\x04\x00\xff\x00\x01'
        session = c.Session(port, events.append)
        session.connect('dvi')
        write = port.write
        def fail_restore(wire):
            if wire == c.packet(0x33, [4, 0, 255, 0, 1]):
                raise OSError('Mask restore failed')
            write(wire)
        port.write = fail_restore
        with self.assertRaises(OSError):
            session.probe_mask()
        self.assertEqual(len([r for r in events if r['kind'] == 'mask_probe_case']), 1)
        self.assertNotIn(c.packet(0x33, [4, 0, 0, 0, 1]), port.writes)
        self.assertEqual(port.state, 0)

    def test_selected_probe_does_not_mutate_other_settings(self):
        port = FakePort()
        session = c.Session(port, lambda _: None)
        session.connect('dvi')
        result = session.probe_settings(['crc_validation'])
        self.assertEqual(result['local_settings_verified'], ['crc_validation'])
        mutations = [w for w in port.writes if w[0] in (0x24, 0x33) and w[1] > 1]
        self.assertEqual(mutations, [c.packet(0x33, [7, 1]), c.packet(0x33, [7, 0])])

    def test_replay_tracks_timestamp_changes_within_one_chunk(self):
        rows = [{'kind': 'transport', 'api': 'dvi'},
                {'kind': 'serial_rx', 'raw_hex': (
                    c.packet(0x34, [3, 1]) + network(b'abc', stamp=bytes(4)) +
                    c.packet(0x34, [3, 0]) + network(b'def')).hex()},
                {'kind': 'network', 'raw_hex': 'invented decoded source row'},
                {'kind': 'result', 'success': False}]
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'capture.jsonl'
            source.write_text(''.join(json.dumps(r) + '\n' for r in rows))
            events = []
            with patch.object(c, 'WindowsSerial') as serial:
                c.replay_jsonl(source, events.append)
                serial.assert_not_called()
            frames = [r for r in events if r['kind'] == 'network']
            self.assertEqual([r['payload_hex'] for r in frames], ['616263', '646566'])
            self.assertEqual(frames[0]['adapter_timestamp_raw_hex'], '00000000')
            self.assertIsNone(frames[1]['adapter_timestamp_raw_hex'])
            self.assertEqual(frames[0]['source_line_end'], 2)
            self.assertTrue(events[-1]['source_reported_failure'])

    def test_replay_audits_forbidden_recorded_commands_without_sending(self):
        rows = [{'kind': 'transport', 'api': 'dvi'},
                {'kind': 'adapter_tx', 'raw_hex': c.packet(0x10, [0x34]).hex()}]
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'capture.jsonl'
            source.write_text(''.join(json.dumps(r) + '\n' for r in rows))
            events = []
            c.replay_jsonl(source, events.append)
            self.assertEqual(events[-1]['outgoing_guard_violations'], 1)

    def test_replay_elm_to_dvi_and_split_frames(self):
        wire = network(b'abc')
        rows = [{'kind': 'transport', 'api': 'elm'},
                {'kind': 'adapter_tx', 'raw_hex': b'DXDP1\r'.hex()},
                {'kind': 'serial_rx', 'raw_hex': b'DXDP1\rOK\r>'.hex()},
                {'kind': 'serial_rx', 'raw_hex': wire[:2].hex()},
                {'kind': 'serial_rx', 'raw_hex': wire[2:].hex()}]
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'capture.jsonl'
            source.write_text(''.join(json.dumps(r) + '\n' for r in rows))
            events = []
            c.replay_jsonl(source, events.append)
            self.assertEqual(events[-1]['network_frames'], 1)
            self.assertEqual(next(r for r in events if r['kind'] == 'network')['source_line_end'], 5)

    def test_replay_keeps_verified_frame_before_later_corruption(self):
        raw = network(b'abc') + b'\x08\x01\x01\x00'
        rows = [{'kind': 'transport', 'api': 'dvi'},
                {'kind': 'serial_rx', 'raw_hex': raw.hex()}]
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / 'capture.jsonl'
            source.write_text(''.join(json.dumps(r) + '\n' for r in rows))
            events = []
            with self.assertRaises(c.ProtocolError):
                c.replay_jsonl(source, events.append)
            self.assertEqual(events[0]['payload_hex'], '616263')

    def test_replay_rejects_missing_api_and_invalid_source_records(self):
        for rows in ([{'kind': 'serial_rx', 'raw_hex': '00'}],
                     [{'kind': 'transport', 'api': 'dvi'}, {'kind': 'result', 'success': 'true'}],
                     [{'kind': 'transport', 'api': 'dvi'}, {'kind': 'transport', 'api': 'dvi'}]):
            with tempfile.TemporaryDirectory() as root:
                source = Path(root) / 'capture.jsonl'
                source.write_text(''.join(json.dumps(r) + '\n' for r in rows))
                with self.assertRaises(c.ProtocolError):
                    c.replay_jsonl(source, lambda _: None)

    def test_corruption_and_truncation_preserve_undecoded_bytes(self):
        raw = bytearray(network(b'\x6c\xf0\x18\x63'))
        raw[-1] ^= 1
        decoder = c.Decoder()
        with self.assertRaises(c.ProtocolError):
            decoder.feed(raw)
        self.assertEqual(decoder.buffer, raw)
        decoder = c.Decoder()
        self.assertEqual([], decoder.feed(network(b'abc')[:-1]))
        with self.assertRaises(c.ProtocolError):
            decoder.finish()

    def test_every_fragment_boundary_and_coalesced_frame(self):
        for timestamped in (False, True):
            stamp = b'\xff\xff\xff\xff' if timestamped else None
            raw = network(b'\x6c\x18\xf1\x34', stamp=stamp)
            raw += network(bytes(range(256)) * 16, large=True, stamp=stamp)
            raw += c.packet(0x7F, [0xFF, 5])
            expected = c.Decoder(timestamped).feed(raw)
            for cut in range(len(raw) + 1):
                decoder = c.Decoder(timestamped)
                self.assertEqual(expected, decoder.feed(raw[:cut]) + decoder.feed(raw[cut:]))
                decoder.finish()
            self.assertEqual(expected[1]['payload_hex'], (bytes(range(256)) * 16).hex())

    def test_uint16_maximum_network_frame_and_raw_timestamp(self):
        decoder = c.Decoder(True)
        payload = b'x' * 65535
        wire = network(payload, large=True, stamp=b'\x04\x03\x02\x01')
        rows = decoder.feed(wire)
        self.assertEqual(rows[0]['adapter_timestamp_raw_hex'], '04030201')
        self.assertEqual(rows[0]['payload_hex'], payload.hex())
        decoder.finish()

    def test_wrong_identity_stops_without_network_commands(self):
        port = FakePort()
        port.write = lambda data: (port.writes.append(data),
                                  port.replies.append(b'OTHER\r\n>'))
        session = c.Session(port, lambda _: None)
        with self.assertRaises(c.ProtocolError):
            session.connect('elm')
        self.assertEqual(port.writes, [b'AT@1\r'])

    def test_no_reply_is_not_retried(self):
        port = FakePort()
        port.write = port.writes.append
        session = c.Session(port, lambda _: None, timeout=0)
        session.dvi = True
        with self.assertRaises(TimeoutError):
            session.request(0x22, [3])
        self.assertEqual(len(port.writes), 1)

    def test_offline_cli_never_opens_serial_and_preserves_output(self):
        with tempfile.TemporaryDirectory() as root:
            source, output = Path(root) / 'rx.bin', Path(root) / 'rx.jsonl'
            source.write_bytes(network(b'\x6c\x18\xf1\x23'))
            args = ['obdx_capture.py', 'decode', '--input', str(source),
                    '--output', str(output)]
            with patch('sys.argv', args), patch.object(c, 'WindowsSerial') as serial:
                c.main()
                serial.assert_not_called()
                original = output.read_bytes()
                rows = [json.loads(line) for line in output.read_text().splitlines()]
                self.assertEqual(rows[-1]['success'], True)
                with self.assertRaises(FileExistsError):
                    c.main()
                self.assertEqual(output.read_bytes(), original)
            with patch('sys.argv', args[:-1] + [str(source)]):
                with self.assertRaises(FileExistsError):
                    c.main()
            self.assertEqual(source.read_bytes(), network(b'\x6c\x18\xf1\x23'))

    def test_offline_cli_corruption_records_failure(self):
        with tempfile.TemporaryDirectory() as root:
            source, output = Path(root) / 'rx.bin', Path(root) / 'rx.jsonl'
            source.write_bytes(b'\x08\x01\x01\x00')
            with patch('sys.argv', ['obdx_capture.py', 'decode', '--input',
                                   str(source), '--output', str(output)]):
                with self.assertRaises(c.ProtocolError):
                    c.main()
            rows = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertFalse(rows[-1]['success'])


if __name__ == '__main__':
    unittest.main()
