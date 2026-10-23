"""One PID-support query on an isolated bench; selectable GT or SX listener.

No loader, security access, speed negotiation, reset, erase or write services.
GT listener mode leaves SX's volatile transmit header at the OBD-II header.
SX listener mode leaves headers enabled and J1850 in-frame responses disabled.
This proves neither electrical silence nor capture during programming.
"""
import argparse
import json
from pathlib import Path
import threading
import time

from inspect_obdlink import LocalQueries
from obdx_capture import Session, WindowsSerial, packet


def exchange(port, command, rows, timeout=3):
    if command not in ('ATSH686AF1', '0100', 'ATH1', 'ATIFR0'):
        raise PermissionError('Only fixed bench diagnostic and monitor settings allowed')
    row = {'command': command, 'tx_hex': (command + '\r').encode().hex(),
           'rx_hex': '', 'host_monotonic_ns': time.monotonic_ns()}
    rows.append(row)
    port.write((command + '\r').encode('ascii'))
    deadline = time.monotonic() + timeout
    data = bytearray()
    while time.monotonic() < deadline:
        data.extend(port.read())
        row['rx_hex'] = data.hex()
        if len(data) > 65536:
            raise ValueError('Response limit exceeded; no retry')
        if b'>' in data:
            before, after = bytes(data).split(b'>', 1)
            if after.strip():
                raise ValueError('Trailing bytes after prompt')
            row['text'] = before.decode('ascii', errors='strict')
            return row['text'].replace(command, '').strip()
    raise TimeoutError('No SX prompt; no interrupt, reset or retry sent')


def gt_fixed(session, command, payload):
    """Separate bench-only authority; the capture client's guard stays unchanged."""
    expected = {(0x31, b'\x02\x01'): (0x41, '0201'),
                (0x10, bytes.fromhex('686af10100')): (0x20, '00')}
    key = (command, bytes(payload))
    if key not in expected:
        raise PermissionError('Only bench network ON and one fixed PID query allowed')
    reply_command, reply_payload = expected[key]
    wire = packet(command, payload)
    session.emit({'kind': 'bench_fixed_tx', 'raw_hex': wire.hex(),
                  'host_monotonic_ns': time.monotonic_ns()})
    session.port.write(wire)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        for row in session.decoder.iter_feed(session.read()):
            session.emit(row)
            if row['command'] == 0x7f:
                raise ValueError('GT adapter error; no retry')
            if row['command'] == reply_command:
                if row['payload_hex'] != reply_payload:
                    raise ValueError('Unexpected GT reply; no retry')
                return
    raise TimeoutError('GT acknowledgment missing; no retry')


def run_sx_monitor(gt, sx, emit):
    rows = []
    if sx.read():
        raise ValueError('SX pending input')
    local = LocalQueries(sx, rows)
    if local.query('STI').replace('STI', '').strip() != 'STN1130 v4.0.1':
        raise ValueError('Unexpected SX firmware')
    if 'OBDLink SX r4.2' not in local.query('STDI'):
        raise ValueError('Unexpected SX hardware')
    if local.query('ATDPN').replace('ATDPN', '').strip() != '2':
        raise ValueError('SX protocol must already be VPW')
    for command in ('ATH1', 'ATIFR0'):
        if exchange(sx, command, rows) != 'OK':
            raise ValueError('SX monitor setup rejected')
    session = Session(gt, emit)
    session.connect('dvi')
    # Fixed VPW 1x listener setup first; preserve/restore all its settings.
    saved = []
    monitoring = False
    try:
        from obdx_capture import SETTINGS
        session.set_checked(0x31, [2, 0])
        for command, sub, size, label in SETTINGS:
            value = bytes.fromhex(session.request(command, [sub])['payload_hex'])
            if len(value) != size or value[-1] not in (0, 1):
                raise ValueError('Unknown GT setting shape')
            saved.append((command, value))
        session.configure_listener('1x')
        sx.write(b'STMA\r')
        monitoring = True
        data = bytearray()
        deadline = time.monotonic() + 0.3
        while time.monotonic() < deadline:
            data.extend(sx.read())
            if b'>' in data or len(data) > 65536:
                raise ValueError('SX did not remain in monitor mode')
        gt_fixed(session, 0x31, b'\x02\x01')
        if session.request(0x31, [2])['payload_hex'] != '0201':
            raise ValueError('GT ON readback failed; no query sent')
        gt_fixed(session, 0x10, bytes.fromhex('686af10100'))
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            data.extend(sx.read())
            if len(data) > 65536 or b'>' in data:
                raise ValueError('SX monitoring stopped or overflowed')
    finally:
        if monitoring:
            emit({'kind': 'sx_monitor', 'tx_hex': b'STMA\r'.hex(),
                  'rx_hex': data.hex(), 'text': data.decode('ascii', errors='replace')})
        # Disable the requester before stopping the monitor, even on errors.
        try:
            session.set_checked(0x31, [2, 0])
            emit({'kind': 'cleanup', 'network_off_acknowledged': True})
        finally:
            if monitoring:
                sx.write(b'x')
                stopped = bytearray()
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline and b'>' not in stopped:
                    stopped.extend(sx.read())
                emit({'kind': 'sx_monitor_stop', 'tx_hex': '78', 'rx_hex': stopped.hex(),
                      'prompt_observed': stopped.rstrip().endswith(b'>')})
                if not stopped.rstrip().endswith(b'>'):
                    raise ValueError('SX stop prompt missing; no follow-up commands')
            for command, value in saved:
                session.set_checked(command, value)
                if command == 0x24:
                    session.decoder.timestamps = bool(value[1])
            emit({'kind': 'settings_restored', 'success': True})
            emit({'kind': 'sx_setup', 'queries': rows,
                  'sx_volatile_settings_left': ['ATH1', 'ATIFR0']})


def run(gt, sx, emit):
    rows = []
    if sx.read():
        raise ValueError('SX pending input; no commands sent')
    local = LocalQueries(sx, rows)
    if local.query('STI').replace('STI', '').strip() != 'STN1130 v4.0.1':
        raise ValueError('Unexpected SX firmware')
    if 'OBDLink SX r4.2' not in local.query('STDI'):
        raise ValueError('Unexpected SX hardware')
    if local.query('ATDPN').replace('ATDPN', '').strip() != '2':
        raise ValueError('SX must already have explicit VPW protocol 2 selected')
    if exchange(sx, 'ATSH686AF1', rows) != 'OK':
        raise ValueError('SX did not acknowledge fixed OBD-II header')
    ready = threading.Event()
    errors = []
    def gt_emit(row):
        emit(row)
        if row.get('kind') == 'capture_started':
            ready.set()
    def listen():
        try:
            session = Session(gt, gt_emit)
            session.connect('dvi')
            session.capture('1x', 6)
        except BaseException as error:
            errors.append(str(error))
    thread = threading.Thread(target=listen)
    thread.start()
    query_error = None
    try:
        if not ready.wait(12):
            raise TimeoutError('GT listener not ready; no diagnostic request sent')
        if errors or not thread.is_alive():
            raise RuntimeError('GT listener stopped; no diagnostic request sent')
        exchange(sx, '0100', rows)
    except BaseException as error:
        query_error = str(error)
    finally:
        # All serial operations have bounded timeouts. Keep ownership until exit.
        thread.join()
        emit({'kind': 'sx_exchange', 'queries': rows,
              'sx_header_left_at': '686AF1', 'error': query_error})
    if errors or query_error:
        raise RuntimeError('; '.join(errors + ([query_error] if query_error else [])))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gt-port', required=True)
    parser.add_argument('--sx-port', required=True)
    parser.add_argument('--bench-ecm-confirmed', action='store_true', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--listener', choices=('gt', 'sx'), default='gt')
    args = parser.parse_args()
    if args.gt_port == args.sx_port:
        parser.error('Adapters require distinct ports')
    with args.output.open('x', encoding='utf8') as output:
        lock = threading.Lock()
        def emit(row):
            with lock:
                output.write(json.dumps(row, sort_keys=True) + '\n')
                output.flush()
        emit({'kind': 'bench_test', 'schema': 'dual-adapter-pid-v1',
              'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'gt_port': args.gt_port, 'sx_port': args.sx_port, 'listener': args.listener,
              'gt_api': 'dvi', 'isolated_bench_user_confirmed': True,
              'programming_enabled': False, 'electrical_silence_proven': False,
              'programming_capture_proven': False})
        gt = sx = None
        try:
            gt = WindowsSerial(args.gt_port)
            sx = WindowsSerial(args.sx_port)
            (run if args.listener == 'gt' else run_sx_monitor)(gt, sx, emit)
            emit({'kind': 'result', 'completed': True,
                  'capture_completeness': 'not established'})
        except Exception as error:
            emit({'kind': 'result', 'completed': False, 'error': str(error)})
            return 1
        finally:
            for port in (sx, gt):
                if port is not None:
                    port.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
