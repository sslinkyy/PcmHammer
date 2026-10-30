import unittest
from unittest.mock import Mock, patch
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


class CounterPort(CoupledFilterPort):
    """Documented reply-shape model only, not a model of GT fault meanings."""
    def __init__(self):
        super().__init__()
        self.counters = [100 + i for i in range(14)]
        self.counter_reads = []
        self.listen_seen = False
        self.counter_reply = None

    def write(self, wire):
        command, payload = wire[0], wire[2:-1]
        if command == 0x33 and payload[:1] == b'\x0e':
            if self.state != 0:
                raise AssertionError('Counter query with network enabled')
            if not c.permitted(command, payload):
                raise AssertionError('Counter query outside allowlist')
            self.writes.append(wire)
            index = payload[1]
            self.counter_reads.append((index, self.state, self.listen_seen))
            reply = self.counter_reply(index, self.listen_seen) if self.counter_reply else None
            self.replies.append(reply if reply is not None else
                                c.packet(0x43, payload + bytes([self.counters[index]])))
            self.counters[index] = 0
            return
        super().write(wire)
        if command == 0x31 and payload == b'\x02\x02':
            self.listen_seen = True
            self.counters = [i for i in range(14)]


class VpwErrorCounterTests(unittest.TestCase):
    def session(self):
        port, rows = CounterPort(), []
        session = c.Session(port, rows.append)
        session.connect('dvi')
        return session, port, rows

    def test_counter_guard_accepts_only_documented_query_shape(self):
        for index in range(14):
            self.assertTrue(c.permitted(0x33, [0x0E, index]))
        for payload in ([0x0E], [0x0E, 14], [0x0E, 255], [0x0E, 0, 1], [0x0D, 0]):
            self.assertFalse(c.permitted(0x33, payload))

    def test_opt_in_records_two_off_only_read_clear_snapshots_and_restores(self):
        session, port, rows = self.session()
        original = dict(port.settings)
        session.capture('4x', 0, all_sources=True, vpw_error_counters=True)
        self.assertEqual([(i, 0, False) for i in range(13)] +
                         [(i, 0, True) for i in range(13)], port.counter_reads)
        snapshots = [r for r in rows if r['kind'] == 'vpw_error_counter_snapshot']
        self.assertEqual(['before_listener_configuration', 'after_network_off'],
                         [r['phase'] for r in snapshots])
        self.assertEqual([list(range(13)), list(range(13))],
                         [r['requested_indices'] for r in snapshots])
        self.assertEqual([list(range(100, 113)), list(range(13))],
                         [r['counts_raw'] for r in snapshots])
        self.assertTrue(all(r['success'] and r['read_clears_counter']
                            and not r['counter_semantics_verified'] for r in snapshots))
        self.assertEqual(26, len([r for r in rows if r['kind'] == 'vpw_error_counter']))
        self.assertEqual([0] * 13 + [13], port.counters)
        self.assertNotIn(c.packet(0x33, [0x0E, 13]), port.writes)
        self.assertEqual(original, port.settings)
        self.assertEqual(0, port.state)
        first = rows.index(snapshots[0])
        started = next(i for i, r in enumerate(rows) if r['kind'] == 'capture_started')
        cleanup = next(i for i, r in enumerate(rows) if r['kind'] == 'cleanup')
        last = rows.index(snapshots[1])
        self.assertLess(first, started)
        self.assertLess(cleanup, last)

    def test_default_makes_no_counter_queries_and_nonboolean_optin_fails_before_io(self):
        session, port, _ = self.session()
        session.capture('4x', 0, all_sources=True)
        self.assertEqual([], port.counter_reads)
        port.writes.clear()
        with self.assertRaises(ValueError):
            session.capture('4x', 0, vpw_error_counters=1)
        self.assertEqual([], port.writes)

    def test_counter_query_refuses_active_network(self):
        session, port, rows = self.session()
        port.state = 2
        with self.assertRaisesRegex(c.ProtocolError, 'verified network OFF'):
            session.read_vpw_error_counters('before_listener_configuration')
        self.assertEqual([], port.counter_reads)
        self.assertFalse(rows[-1]['success'])
        self.assertEqual(list(range(13)), rows[-1]['requested_indices'])

    def test_unsupported_or_malformed_before_snapshot_never_enables_listener(self):
        bad = [c.packet(0x7F, b'\x33'), c.packet(0x43, b'\x0e\x02'),
               c.packet(0x43, b'\x0e\x03\x05'), c.packet(0x43, b'\x0e\x02\x05\x00')]
        for reply in bad:
            with self.subTest(reply=reply.hex()):
                session, port, rows = self.session()
                port.counter_reply = lambda index, _: reply if index == 2 else None
                with self.assertRaises(c.ProtocolError):
                    session.capture('4x', 0, all_sources=True, vpw_error_counters=True)
                self.assertFalse(port.listen_seen)
                self.assertEqual(0, port.state)
                snapshots = [r for r in rows if r['kind'] == 'vpw_error_counter_snapshot']
                self.assertEqual(1, len(snapshots))
                self.assertFalse(snapshots[0]['success'])
                self.assertEqual([100, 101], snapshots[0]['counts_raw'])
                self.assertEqual(list(range(13)), snapshots[0]['requested_indices'])

    def test_after_counter_failure_still_restores_observable_settings(self):
        session, port, rows = self.session()
        original = dict(port.settings)
        port.counter_reply = lambda index, listened: c.packet(0x7F, b'\x33') if listened and index == 1 else None
        with self.assertRaises(c.ProtocolError):
            session.capture('4x', 0, all_sources=True, vpw_error_counters=True)
        self.assertEqual(0, port.state)
        self.assertEqual(original, port.settings)
        self.assertTrue(rows[-1]['observable_readbacks_match_original'])
        snapshots = [r for r in rows if r['kind'] == 'vpw_error_counter_snapshot']
        self.assertFalse(snapshots[-1]['success'])
        self.assertEqual([0], snapshots[-1]['counts_raw'])
        self.assertEqual(list(range(13)), snapshots[-1]['requested_indices'])


class FakeWin32Api:
    """Exercise the ctypes transport boundary without opening a native handle."""
    def __init__(self, reads=(), statuses=()):
        self.reads, self.statuses = list(reads), list(statuses)
        self.last_error = 0
        self.calls = []
        for name in ('CreateFileW', 'CloseHandle', 'GetCommState', 'SetCommState',
                     'SetCommTimeouts', 'ReadFile', 'WriteFile', 'ClearCommError'):
            setattr(self, name, Mock(side_effect=lambda *args, name=name: self.call(name, args)))

    def call(self, name, args):
        self.calls.append(name)
        if name == 'CreateFileW':
            return 123
        if name == 'SetCommState':
            dcb = args[1]._obj
            self.dcb_values = (dcb.baud, dcb.bytesize, dcb.parity, dcb.stopbits, dcb.flags)
        elif name == 'SetCommTimeouts':
            self.timeouts = tuple(args[1])
        elif name == 'ReadFile':
            item = self.reads.pop(0) if self.reads else b''
            if isinstance(item, dict):
                self.last_error = item['failure']
                args[3]._obj.value = item['reported_count']
                return 0
            if isinstance(item, int):
                self.last_error = item
                return 0
            c.ctypes.memmove(args[1], item, len(item))
            args[3]._obj.value = len(item)
        elif name == 'ClearCommError':
            item = self.statuses.pop(0) if self.statuses else {}
            if 'failure' in item:
                self.last_error = item['failure']
                return 0
            args[1]._obj.value = item.get('errors', 0)
            status = args[2]._obj
            status.flags = item.get('flags', 0)
            status.in_queue = item.get('in', 0)
            status.out_queue = item.get('out', 0)
        return 1


class WindowsSerialDiagnosticsTests(unittest.TestCase):
    def native_port(self, api, enabled=True):
        def win_error(code):
            error = OSError(code, 'fake Win32 failure')
            error.winerror = code
            return error
        self.enterContext(patch.object(c.os, 'name', 'nt'))
        self.enterContext(patch.object(c.ctypes, 'WinDLL', return_value=api, create=True))
        self.enterContext(patch.object(c.ctypes, 'get_last_error',
                                      side_effect=lambda: api.last_error, create=True))
        self.enterContext(patch.object(c.ctypes, 'WinError', side_effect=win_error, create=True))
        port = c.WindowsSerial('COM999', serial_diagnostics=enabled)
        self.addCleanup(port.close)
        return port

    def test_default_transport_does_not_poll_or_change_timeouts(self):
        api = FakeWin32Api([b'\x00\x11\x13\xff'])
        rows = []
        port = self.native_port(api, enabled=False)
        self.assertEqual(b'\x00\x11\x13\xff', c.Session(port, rows.append).read())
        self.assertNotIn('ClearCommError', api.calls)
        self.assertEqual((115200, 8, 0, 0, 1), api.dcb_values)
        self.assertEqual((0xFFFFFFFF, 0, 100, 0, 1000), api.timeouts)
        self.assertEqual(['serial_rx'], [r['kind'] for r in rows])
        self.assertNotIn('read_sequence', rows[0])

    def test_raw_bytes_precede_diagnostics_and_decoding_with_exact_raw_status(self):
        wire = network(bytes.fromhex('6df010750154'))
        api = FakeWin32Api([wire], [{'errors': 0x80000003, 'flags': 0x1234, 'in': 4211, 'out': 17},
                                   {'errors': 8, 'flags': 0x40, 'in': 29, 'out': 0}])
        rows = []
        port = self.native_port(api)
        session = c.Session(port, rows.append)
        for row in session.decoder.iter_feed(session.read()):
            session.emit(row)
        self.assertEqual(['serial_rx', 'serial_read_diagnostics', 'network'], [r['kind'] for r in rows])
        self.assertEqual(wire.hex(), rows[0]['raw_hex'])
        self.assertEqual(1, rows[0]['read_sequence'])
        d = rows[1]
        self.assertEqual(1, d['read_sequence'])
        self.assertTrue(d['read_succeeded'])
        self.assertEqual(len(wire), d['bytes_returned'])
        self.assertIsNone(d['read_error'])
        self.assertTrue(d['polling_clears_error_flags'])
        self.assertEqual(0x80000003, d['before']['error_mask_raw'])
        self.assertEqual((0x1234, 4211, 17), tuple(d['before'][k] for k in ('comstat_flags_raw', 'cb_in_que', 'cb_out_que')))
        self.assertEqual(8, d['after']['error_mask_raw'])
        self.assertEqual(29, d['after']['cb_in_que'])
        self.assertLessEqual(d['before']['host_monotonic_ns'], d['read_start_monotonic_ns'])
        self.assertLessEqual(d['read_start_monotonic_ns'], d['read_end_monotonic_ns'])
        self.assertLessEqual(d['read_end_monotonic_ns'], d['after']['host_monotonic_ns'])
        self.assertEqual(['ClearCommError', 'ReadFile', 'ClearCommError'], api.calls[-3:])

    def test_status_query_failure_is_explicit_and_does_not_discard_bytes(self):
        api = FakeWin32Api([b'abc'], [{'failure': 5}, {'errors': 0}])
        rows = []
        self.assertEqual(b'abc', c.Session(self.native_port(api), rows.append).read())
        self.assertEqual('616263', rows[0]['raw_hex'])
        before = rows[1]['before']
        self.assertFalse(before['success'])
        self.assertEqual(5, before['win32_error'])
        for key in ('error_mask_raw', 'comstat_flags_raw', 'cb_in_que', 'cb_out_que'):
            self.assertIsNone(before[key])
        self.assertTrue(rows[1]['after']['success'])

    def test_read_failure_retains_diagnostics_and_original_win32_error(self):
        api = FakeWin32Api([{'failure': 123, 'reported_count': 7}], [{'errors': 2}, {'failure': 6}])
        rows = []
        with self.assertRaises(OSError) as raised:
            c.Session(self.native_port(api), rows.append).read()
        self.assertEqual(123, raised.exception.winerror)
        self.assertEqual(['serial_read_diagnostics'], [r['kind'] for r in rows])
        d = rows[0]
        self.assertFalse(d['read_succeeded'])
        self.assertEqual(123, d['read_error']['win32_error'])
        self.assertEqual(6, d['after']['win32_error'])
        self.assertEqual(0, d['bytes_returned'])
        self.assertEqual(7, d['bytes_reported_by_readfile'])

    def test_empty_reads_have_unique_diagnostics_without_inventing_serial_bytes(self):
        api = FakeWin32Api([b'', b'z'])
        rows = []
        session = c.Session(self.native_port(api), rows.append)
        self.assertEqual(b'', session.read())
        self.assertEqual(b'z', session.read())
        self.assertEqual(['serial_read_diagnostics', 'serial_rx', 'serial_read_diagnostics'],
                         [r['kind'] for r in rows])
        self.assertEqual([1, 2, 2], [r['read_sequence'] for r in rows])
        self.assertEqual(0, rows[0]['bytes_returned'])

    def test_unavailable_diagnostics_api_closes_handle_and_fails_explicitly(self):
        api = FakeWin32Api()
        del api.ClearCommError
        with self.assertRaises(AttributeError):
            self.native_port(api)
        self.assertEqual(['CreateFileW', 'CloseHandle'], api.calls)


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

    def test_persistent_journal_failure_cannot_block_off_cleanup(self):
        for fail_at in ('capture_started', 'serial_rx', 'network', 'cleanup_off_tx'):
            with self.subTest(fail_at=fail_at):
                port, events = CoupledFilterPort(), []
                state = {'started': False, 'failed': False, 'traffic': False}
                def emit(row):
                    if row['kind'] == 'capture_started':
                        state['started'] = True
                    trigger = (row['kind'] == fail_at or
                               (fail_at == 'cleanup_off_tx' and row['kind'] == 'adapter_tx'
                                and row['raw_hex'] == c.packet(0x31, [2, 0]).hex()))
                    if state['started'] and trigger:
                        state['failed'] = True
                    if state['failed']:
                        raise OSError('persistent journal failure')
                    events.append(row)
                read = port.read
                def receive():
                    if state['started'] and port.state == 2 and not port.replies and not state['traffic']:
                        state['traffic'] = True
                        return network(b'ack', stamp=b'\x00' * 4)
                    return read()
                port.read = receive
                session = c.Session(port, emit)
                session.connect('dvi')
                with self.assertRaisesRegex(OSError, 'persistent journal failure'):
                    session.capture('4x', 1 if fail_at in ('serial_rx', 'network') else 0, all_sources=True)
                self.assertEqual(0, port.state)
                self.assertEqual([c.packet(0x31, [2, 0]), c.packet(0x31, [2])], port.writes[-2:])
                self.assertFalse(session._cleanup_logging)
                self.assertTrue(all(c.permitted(wire[0], wire[2:-1]) for wire in port.writes))

    def test_cleanup_transport_failure_is_not_swallowed_when_journal_is_broken(self):
        port = CoupledFilterPort()
        failed = False
        def emit(row):
            nonlocal failed
            if row['kind'] == 'capture_started':
                failed = True
            if failed:
                raise OSError('journal failure')
        write = port.write
        def broken_off(wire):
            if failed and wire == c.packet(0x31, [2, 0]):
                raise OSError('OFF transport failure')
            write(wire)
        port.write = broken_off
        session = c.Session(port, emit)
        session.connect('dvi')
        with self.assertRaisesRegex(OSError, 'OFF transport failure'):
            session.capture('4x', 0, all_sources=True)
        self.assertEqual(2, port.state)
        self.assertFalse(session._cleanup_logging)

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


class CrcRetentionTests(unittest.TestCase):
    def session(self):
        port, events = CoupledFilterPort(), []
        port.settings[0x33, 7] = b'\x07\x01'
        session = c.Session(port, events.append)
        session.connect('dvi')
        return session, port, events

    def test_default_and_optin_check_requested_crc_policy_before_listen_and_restore(self):
        for retain in (False, True):
            for scope in ({}, {'source_id': 0x10}, {'all_sources': True}):
                with self.subTest(retain=retain, scope=scope):
                    session, port, events = self.session()
                    original = dict(port.settings)
                    session.capture('4x', 0, retain_invalid_crc=retain, **scope)
                    before = port.writes[:port.writes.index(c.packet(0x31, [2, 2]))]
                    wanted = c.packet(0x33, [7, int(not retain)])
                    at = before.index(wanted)
                    self.assertEqual(c.packet(0x33, [7]), before[at + 1])
                    self.assertIn(c.packet(0x33, [8, 1]), before)
                    self.assertNotIn(c.packet(0x33, [7, int(retain)]), before)
                    start = next(r for r in events if r['kind'] == 'capture_started')
                    self.assertEqual(retain, start['retain_invalid_crc_requested'])
                    self.assertEqual(not retain, start['adapter_crc_validation_requested'])
                    self.assertEqual(not retain, start['adapter_crc_validation_enabled'])
                    self.assertEqual('0700' if retain else '0701', start['adapter_crc_validation_readback_hex'])
                    self.assertTrue(start['crc_in_payload'])
                    self.assertEqual(original, port.settings)
                    self.assertEqual(0, port.state)
                    self.assertTrue(all(c.permitted(w[0], w[2:-1]) for w in port.writes))

    def test_nonboolean_retention_rejected_before_io(self):
        session, port, _ = self.session()
        port.writes.clear()
        for value in (None, 0, 1, 'false', []):
            for operation in (session.capture, session.configure_listener):
                args = ('4x', 0) if operation == session.capture else ('4x',)
                with self.subTest(value=value, operation=operation.__name__), self.assertRaises(ValueError):
                    operation(*args, retain_invalid_crc=value)
        self.assertEqual([], port.writes)

    def test_crc_set_or_readback_failure_prevents_listen_and_restores(self):
        for failure in ('set_rejected', 'readback_mismatch'):
            with self.subTest(failure=failure):
                session, port, events = self.session()
                original = dict(port.settings)
                write = port.write
                def corrupt(wire):
                    write(wire)
                    if wire == c.packet(0x33, [7, 0]):
                        if failure == 'set_rejected':
                            port.replies[-1] = c.packet(0x7F, b'\x33\x07')
                        else:
                            port.settings[0x33, 7] = b'\x07\x01'
                port.write = corrupt
                with self.assertRaises(c.ProtocolError):
                    session.capture('4x', 0, all_sources=True, retain_invalid_crc=True)
                self.assertNotIn(c.packet(0x31, [2, 2]), port.writes)
                self.assertFalse(any(r['kind'] == 'capture_started' for r in events))
                self.assertEqual(original, port.settings)
                self.assertEqual(0, port.state)
                self.assertTrue(events[-1]['observable_readbacks_match_original'])

    def test_invalid_vpw_crc_bytes_preserved_without_claiming_validity(self):
        from compare_vpw_read_capture import capture_context, crc8_j1850
        session, port, events = self.session()
        original = dict(port.settings)
        message = bytes.fromhex('6df010750154')
        invalid = message + bytes([crc8_j1850(message) ^ 1])
        wire = network(invalid, stamp=b'\x12\x34\x56\x78')
        now = 0
        def emit(row):
            nonlocal now
            events.append(row)
            if row['kind'] == 'capture_started':
                self.assertEqual(b'\x07\x00', port.settings[0x33, 7])
                self.assertEqual(b'\x08\x01', port.settings[0x33, 8])
                port.replies.append(wire)
                with self.assertRaises(PermissionError):
                    session.send(0x10, [0x6C, 0x18, 0xF0, 0x34])
            if row['kind'] == 'network':
                now = 2
        session.emit = emit
        with patch.object(c.time, 'monotonic', side_effect=lambda: now):
            session.capture('4x', 1, all_sources=True, retain_invalid_crc=True)
        captured = [r for r in events if r['kind'] == 'network']
        self.assertEqual([invalid.hex()], [r['payload_hex'] for r in captured])
        self.assertNotEqual(crc8_j1850(invalid[:-1]), invalid[-1])
        self.assertNotIn('crc_valid', captured[0])
        self.assertNotIn('vpw_crc_valid', captured[0])
        self.assertIn(wire.hex(), [r['raw_hex'] for r in events if r['kind'] == 'serial_rx'])
        self.assertEqual(original, port.settings)
        self.assertEqual(0, port.state)
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'invalid_crc.jsonl'
            rows = [{'kind': 'transport', 'api': 'dvi'}, *events,
                    {'kind': 'result', 'success': True}]
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf8')
            replayed = []
            with patch.object(c, 'WindowsSerial', side_effect=AssertionError('No hardware')):
                c.replay_jsonl(path, replayed.append)
        context = capture_context(replayed, None, all_sources=True)
        self.assertFalse(context['verified'])
        self.assertEqual(['crc_validation_on'],
                         context['frame_context_failures'][0]['missing_or_contradictory_settings'])

    def test_active_capture_cancellation_or_error_restores_original_crc_policy(self):
        for scope in ({'source_id': 0x10}, {'all_sources': True}):
            for failure in (KeyboardInterrupt(), c.ProtocolError('read interrupted')):
                with self.subTest(scope=scope, failure=type(failure).__name__):
                    session, port, events = self.session()
                    original = dict(port.settings)
                    read = port.read
                    def interrupt():
                        if port.state == 2 and not port.replies:
                            self.assertEqual(b'\x07\x00', port.settings[0x33, 7])
                            raise failure
                        return read()
                    port.read = interrupt
                    with self.assertRaises(type(failure)):
                        session.capture('4x', 1, retain_invalid_crc=True, **scope)
                    self.assertEqual(original, port.settings)
                    self.assertEqual(0, port.state)
                    self.assertTrue(events[-1]['success'])


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
