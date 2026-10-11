"""OBDX capture-only DVI client. No vehicle-send operation is implemented.

Uses only Python's standard library, including Win32 serial APIs on Windows.
Offline decoding never opens a port. Inspection disables any previously enabled
network; it never enables one.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import time


class ProtocolError(ValueError):
    pass


# One owner for settings shape, inspection and capture restoration.
SETTINGS = ((0x24, 3, 2, 'timestamps'),
            (0x33, 0, 3, 'to_filter'), (0x33, 1, 3, 'from_filter'),
            (0x33, 2, 4, 'to_range_filter'), (0x33, 3, 4, 'from_range_filter'),
            (0x33, 4, 5, 'mask_filter'), (0x33, 6, 2, 'speed'),
            (0x33, 7, 2, 'crc_validation'), (0x33, 8, 2, 'crc_display'))


def packet(command, payload):
    payload = bytes(payload)
    if len(payload) > 255:
        raise ProtocolError('Adapter commands must use short framing')
    body = bytes([command, len(payload)]) + payload
    return body + bytes([(~sum(body)) & 255])


def permitted(command, payload):
    """Exact adapter-local allowlist; unknown operations fail closed."""
    p = bytes(payload)
    if command == 0x22:
        return len(p) == 1 and p[0] <= 6
    if command == 0x24:
        return p in (b'\x03', b'\x03\x00', b'\x03\x01')
    if command == 0x31:
        return p in (b'\x01', b'\x02', b'\x01\x01',
                     b'\x02\x00', b'\x02\x02')  # VPW; OFF/LISTEN ONLY
    if command == 0x33:
        if len(p) == 1 and p[0] in (0, 1, 2, 3, 4, 6, 7, 8, 13):
            return True
        return any(cmd == command and len(p) == size and p[0] == sub
                   and p[-1] in (0, 1) for cmd, sub, size, _ in SETTINGS)
    return False


class Decoder:
    """Incremental, strict DVI framing. Preserve uncertain bytes; never resync."""
    def __init__(self, timestamps=False, track_timestamp_status=False):
        self.timestamps = timestamps
        self.track_timestamp_status = track_timestamp_status
        self.buffer = bytearray()

    def feed(self, chunk):
        return list(self.iter_feed(chunk))

    def iter_feed(self, chunk):
        """Yield verified frames before a later corrupt frame fails the stream."""
        self.buffer.extend(chunk)
        while self.buffer:
            command = self.buffer[0]
            network = command in (8, 9)
            offset = 5 if network and self.timestamps else 1
            width = 2 if command == 9 else 1
            header = offset + width
            if len(self.buffer) < header:
                break
            length = int.from_bytes(self.buffer[offset:header], 'big')
            total = header + length + 1  # uint16 network length bounds allocation
            if len(self.buffer) < total:
                break
            raw = bytes(self.buffer[:total])
            if sum(raw) & 255 != 255:
                raise ProtocolError('DVI checksum mismatch; stream not resynchronized')
            del self.buffer[:total]
            row = {'kind': 'network' if network else 'adapter',
                         'command': command, 'raw_hex': raw.hex(),
                         'payload_hex': raw[header:-1].hex(),
                         'adapter_timestamp_raw_hex': raw[1:5].hex()
                         if network and self.timestamps else None}
            if self.track_timestamp_status and command == 0x34:
                status = raw[header:-1]
                if status in (b'\x03\x00', b'\x03\x01'):
                    # Status applies to following bytes, even in the same chunk.
                    self.timestamps = bool(status[1])
            yield row

    def finish(self):
        if self.buffer:
            raise ProtocolError('Truncated DVI frame: ' + self.buffer.hex())


class WindowsSerial:
    """115200 8N1; no reset, purge, DTR/RTS assertion or third-party dependency."""
    def __init__(self, port):
        if os.name != 'nt' or not re.fullmatch(r'COM[1-9][0-9]*', port):
            raise ValueError('An explicit Windows COM port is required')
        from ctypes import wintypes as w
        self.w = w
        self.api = ctypes.WinDLL('kernel32', use_last_error=True)
        self.api.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD,
                                        w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
        self.api.CreateFileW.restype = w.HANDLE
        self.api.CloseHandle.argtypes = [w.HANDLE]
        for name in ('GetCommState', 'SetCommState', 'SetCommTimeouts'):
            getattr(self.api, name).argtypes = [w.HANDLE, w.LPVOID]
        for name in ('ReadFile', 'WriteFile'):
            getattr(self.api, name).argtypes = [w.HANDLE, w.LPVOID, w.DWORD,
                                               ctypes.POINTER(w.DWORD), w.LPVOID]
        self.handle = self.api.CreateFileW('\\\\.\\' + port, 0xC0000000, 0,
                                          None, 3, 0, None)
        if self.handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        class DCB(ctypes.Structure):
            _fields_ = [('length', w.DWORD), ('baud', w.DWORD), ('flags', w.DWORD),
                        ('reserved', w.WORD), ('xonlimit', w.WORD),
                        ('xofflimit', w.WORD), ('bytesize', w.BYTE),
                        ('parity', w.BYTE), ('stopbits', w.BYTE),
                        ('xon', ctypes.c_char), ('xoff', ctypes.c_char),
                        ('error', ctypes.c_char), ('eof', ctypes.c_char),
                        ('event', ctypes.c_char), ('reserved1', w.WORD)]
        try:
            dcb = DCB()
            dcb.length = ctypes.sizeof(dcb)
            self.check(self.api.GetCommState(self.handle, ctypes.byref(dcb)))
            dcb.baud, dcb.bytesize, dcb.parity, dcb.stopbits = 115200, 8, 0, 0
            dcb.flags = 1  # fBinary, no hardware/software flow control or DTR/RTS
            self.check(self.api.SetCommState(self.handle, ctypes.byref(dcb)))
            # Read returns within 100 ms; writes are bounded by 1000 ms.
            timeouts = (w.DWORD * 5)(0xFFFFFFFF, 0, 100, 0, 1000)
            self.check(self.api.SetCommTimeouts(self.handle, timeouts))
        except BaseException:
            self.close()
            raise

    @staticmethod
    def check(ok):
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    def read(self):
        buf = ctypes.create_string_buffer(4096)
        count = self.w.DWORD()
        self.check(self.api.ReadFile(self.handle, buf, 4096, ctypes.byref(count), None))
        return buf.raw[:count.value]

    def write(self, data):
        count = self.w.DWORD()
        buf = ctypes.create_string_buffer(data)
        self.check(self.api.WriteFile(self.handle, buf, len(data), ctypes.byref(count), None))
        if count.value != len(data):
            raise OSError('Partial serial write; no retry')

    def close(self):
        if self.handle is not None:
            handle, self.handle = self.handle, None
            self.check(self.api.CloseHandle(handle))


class Session:
    def __init__(self, port, emit, timeout=2.0):
        self.port, self.emit, self.timeout = port, emit, timeout
        self.decoder = Decoder()
        self.dvi = False

    def read(self):
        raw = self.port.read()
        if raw:
            self.emit({'kind': 'serial_rx', 'host_monotonic_ns': time.monotonic_ns(),
                       'raw_hex': raw.hex()})
        return raw

    def send(self, command, payload):
        if not self.dvi or not permitted(command, payload):
            raise PermissionError('Vehicle transmissions and unknown commands are disabled')
        wire = packet(command, payload)
        self.emit({'kind': 'adapter_tx', 'raw_hex': wire.hex()})
        self.port.write(wire)

    def elm(self, command):
        if self.dvi or command not in ('AT@1', 'DXDP1'):
            raise PermissionError('ELM command blocked')
        self.emit({'kind': 'adapter_tx', 'raw_hex': (command + '\r').encode().hex()})
        self.port.write((command + '\r').encode())
        received = bytearray()
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            received.extend(self.read())
            if len(received) > 65536:
                raise ProtocolError('ELM response exceeds bounded identification buffer')
            if b'>' in received:
                text = bytes(received).decode('ascii', errors='strict')
                return [s.strip() for s in text.replace('>', '').splitlines()
                        if s.strip() and s.strip() != command]
        raise TimeoutError('No ELM prompt; stopped without reset or protocol guessing')

    def connect(self, api):
        if api == 'elm':
            name = self.elm('AT@1')
            if name != ['OBDX Pro GT']:
                raise ProtocolError('Expected OBDX Pro GT identification, got ' + repr(name))
            if self.elm('DXDP1') != ['OK']:
                raise ProtocolError('Adapter did not acknowledge DVI switch')
        self.dvi = True
        name = bytes.fromhex(self.request(0x22, [3])['payload_hex'])[1:]
        if name != b'OBDX Pro GT':
            raise ProtocolError('DVI identity is not OBDX Pro GT: ' + repr(name))

    def request(self, command, payload, echo=False):
        self.send(command, payload)
        deadline = time.monotonic() + self.timeout
        match = None
        while time.monotonic() < deadline:
            for row in self.decoder.iter_feed(self.read()):
                self.emit(row)
                p = bytes.fromhex(row['payload_hex'])
                if row['command'] == 0x7F:
                    raise ProtocolError('Adapter error: ' + row['raw_hex'])
                if row['command'] == command + 0x10:
                    if not p or p[0] != payload[0] or (echo and p != bytes(payload)):
                        raise ProtocolError('Unexpected adapter acknowledgment')
                    if match is not None:
                        raise ProtocolError('Duplicate adapter acknowledgment')
                    match = row
            if match is not None:
                if self.decoder.buffer:
                    # A partial trailing frame must stay buffered for the next read.
                    self.emit({'kind': 'pending_partial_frame',
                               'bytes': len(self.decoder.buffer)})
                return match
        raise TimeoutError('Adapter response timed out; no automatic retry')

    def inspect(self):
        identity = {}
        identity['network_state_before_inspection_cleanup'] = self.request(0x31, [2])['payload_hex']
        self.request(0x31, [2, 0], echo=True)
        identity['network_state'] = self.request(0x31, [2])['payload_hex']
        if identity['network_state'] != '0200':
            raise ProtocolError('Inspection could not verify network OFF')
        for sub, label in ((0, 'hardware'), (1, 'firmware'), (2, 'model'),
                           (3, 'name'), (4, 'serial'), (5, 'obd_protocols'),
                           (6, 'pc_protocols')):
            p = bytes.fromhex(self.request(0x22, [sub])['payload_hex'])[1:]
            identity[label + '_raw_hex'] = p.hex()
            if label in ('hardware', 'firmware') and len(p) == 4:
                identity[label] = '.'.join(str(v) for v in p)
            if label == 'name':
                identity[label] = p.decode('ascii', errors='strict')
        identity['selected_protocol'] = self.request(0x31, [1])['payload_hex']
        for cmd, sub, _, label in SETTINGS:
            identity[label] = self.request(cmd, [sub])['payload_hex']
        self.emit({'kind': 'identity', **identity,
                   'vehicle_transmit_commands_enabled': False})
        return identity

    def configure_listener(self, speed):
        # capture() has verified OFF before saving the original settings.
        self.request(0x31, [1, 1], echo=True)
        for p in ([0, 0, 0], [1, 0, 0], [2, 0, 0, 0],
                  [3, 0, 0, 0], [4, 0, 0, 0, 0]):
            self.request(0x33, p, echo=True)
        self.request(0x33, [6, 0 if speed == '1x' else 1], echo=True)
        self.request(0x33, [7, 1], echo=True)
        self.request(0x33, [8, 1], echo=True)
        if self.decoder.buffer:
            raise ProtocolError('Pending bytes before timestamp layout change')
        self.request(0x24, [3, 1], echo=True)
        self.decoder.timestamps = True
        self.request(0x31, [2, 2], echo=True)
        if self.request(0x31, [2])['payload_hex'] != '0202':
            raise ProtocolError('LISTEN ONLY readback failed')

    def probe_settings(self):
        """Check adapter-local setters with network OFF; restore exact values."""
        identity = self.inspect()
        for command, sub, size, label in SETTINGS:
            if label not in ('timestamps', 'speed', 'crc_display'):
                continue
            original = bytes.fromhex(identity[label])
            if len(original) != size or original[1] not in (0, 1):
                raise ProtocolError('Unknown setting shape; local probe blocked')
            alternate = bytes([sub, 1 - original[1]])
            if self.request(0x31, [2])['payload_hex'] != '0200':
                raise ProtocolError('Network is not OFF; local probe blocked')
            try:
                self.request(command, alternate, echo=True)
                observed = self.request(command, [sub])['payload_hex']
                if observed != alternate.hex():
                    raise ProtocolError('Adapter setting readback mismatch')
                self.emit({'kind': 'local_setting_probe', 'label': label,
                           'original_hex': original.hex(), 'observed_hex': observed,
                           'vehicle_network_enabled': False})
            finally:
                self.request(command, original, echo=True)
                if self.request(command, [sub])['payload_hex'] != original.hex():
                    raise ProtocolError('Local probe setting restoration failed')
                if self.request(0x31, [2])['payload_hex'] != '0200':
                    self.request(0x31, [2, 0], echo=True)
                    raise ProtocolError('Unexpected network state during local probe')
        return {'firmware': identity.get('firmware'), 'network_state': '0200',
                'local_settings_verified': ['timestamps', 'speed', 'crc_display'],
                'live_receive_verified': False}

    def capture(self, speed, seconds):
        saved = []
        try:
            self.request(0x31, [2, 0], echo=True)
            # Preserve each exact filter and CRC policy, not inferred defaults.
            for command, sub, size, label in SETTINGS:
                p = bytes.fromhex(self.request(command, [sub])['payload_hex'])
                if len(p) != size or p[-1] not in (0, 1):
                    raise ProtocolError('Unknown adapter setting; no listener setup')
                saved.append((command, p))
                self.emit({'kind': 'saved_setting', 'label': label, 'command': command,
                           'payload_hex': p.hex()})
            self.configure_listener(speed)
            self.emit({'kind': 'capture_started', 'fixed_speed': speed,
                       'automatic_speed_tracking': False,
                       'complete_programming_capture_proven': False,
                       'crc_in_payload': True})
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                for row in self.decoder.iter_feed(self.read()):
                    self.emit(row)
                    if row['command'] == 0x7F:
                        raise ProtocolError('Adapter reported capture error')
        finally:
            # Required even if listener setup failed or Ctrl+C cancelled capture.
            try:
                self.request(0x31, [2, 0], echo=True)
                self.emit({'kind': 'cleanup', 'network_off_acknowledged': True})
            except BaseException as error:
                self.emit({'kind': 'cleanup', 'network_off_acknowledged': False,
                           'error': str(error)})
                raise
            self.decoder.finish()
            try:
                for command, p in saved:
                    self.request(command, p, echo=True)
                    if command == 0x24:
                        self.decoder.timestamps = bool(p[1])
                self.emit({'kind': 'settings_restored', 'success': True})
            except BaseException as error:
                self.emit({'kind': 'settings_restored', 'success': False,
                           'error': str(error)})
                raise
        self.decoder.finish()


def replay_jsonl(path, emit, timestamps=False):
    """Reconstruct recorded RX only. This function has no transport authority."""
    decoder = Decoder(timestamps, track_timestamp_status=True)
    digest = hashlib.sha256()
    counts = {'network_frames': 0, 'adapter_frames': 0, 'adapter_errors': 0,
              'outgoing_guard_violations': 0, 'serial_chunks': 0,
              'source_reported_failure': False, 'source_result_seen': False}
    api = None
    switching = False
    elm = bytearray()
    with path.open('rb') as stream:
        for line_number, line in enumerate(stream, 1):
            digest.update(line)
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ProtocolError('JSONL record must be an object')
            kind = row.get('kind')
            if kind == 'transport':
                if api is not None or row.get('api') not in ('elm', 'dvi'):
                    raise ProtocolError('Expected exactly one known transport API')
                api = row['api']
            elif kind == 'adapter_tx':
                wire = bytes.fromhex(row['raw_hex'])
                if api == 'elm':
                    allowed = wire in (b'AT@1\r', b'DXDP1\r')
                    switching = wire == b'DXDP1\r'
                    elm.clear()
                elif api == 'dvi':
                    allowed = (len(wire) >= 3 and len(wire) == wire[1] + 3
                               and sum(wire) & 255 == 255
                               and permitted(wire[0], wire[2:-1]))
                else:
                    raise ProtocolError('Outgoing bytes precede known API')
                counts['outgoing_guard_violations'] += not allowed
                emit({'kind': 'recorded_tx_audit', 'source_line': line_number,
                      'raw_hex': wire.hex(), 'allowed_by_capture_guard': allowed})
            elif kind == 'serial_rx':
                if api is None:
                    raise ProtocolError('Receive bytes precede known API')
                raw = bytes.fromhex(row['raw_hex'])
                counts['serial_chunks'] += 1
                if api == 'elm':
                    elm.extend(raw)
                    if len(elm) > 65536:
                        raise ProtocolError('ELM replay response exceeds identification bound')
                    emit({'kind': 'recorded_elm_rx', 'source_line': line_number,
                          'raw_hex': raw.hex()})
                    if b'>' in elm and switching:
                        prompt = elm.index(b'>')
                        text = bytes(elm[:prompt]).decode('ascii', errors='strict')
                        lines = [s.strip() for s in text.splitlines()
                                 if s.strip() and s.strip() != 'DXDP1']
                        if lines != ['OK']:
                            raise ProtocolError('Recorded DVI switch was not acknowledged')
                        api, switching = 'dvi', False
                        raw = bytes(elm[prompt + 1:])
                    else:
                        continue
                for decoded in decoder.iter_feed(raw):
                    decoded['source_line_end'] = line_number
                    decoded['host_monotonic_ns_at_chunk_end'] = row.get('host_monotonic_ns')
                    emit(decoded)
                    counts['network_frames' if decoded['kind'] == 'network'
                           else 'adapter_frames'] += 1
                    counts['adapter_errors'] += decoded['command'] == 0x7F
            elif kind == 'result':
                if not isinstance(row.get('success'), bool):
                    raise ProtocolError('Source result has no boolean success')
                counts['source_reported_failure'] |= not row['success']
                counts['source_result_seen'] = True
                emit({'kind': 'source_result', 'source_line': line_number,
                      'record': row})
            # Decoded source rows are intentionally not replay inputs.
    if api is None:
        raise ProtocolError('No transport declaration in source JSONL')
    decoder.finish()
    emit({'kind': 'replay_summary', 'input_path': str(path.resolve()),
          'input_sha256': digest.hexdigest(), **counts,
          'capture_completeness': 'not established',
          'timestamp_byte_order': 'unknown'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    for mode in ('inspect', 'probe', 'capture'):
        p = sub.add_parser(mode)
        p.add_argument('--port', required=True)
        p.add_argument('--api', choices=('elm', 'dvi'), default='elm',
                       help='Known current adapter API; no automatic reset/fallback')
        p.add_argument('--output', type=Path, required=True)
        if mode == 'capture':
            p.add_argument('--speed', choices=('1x', '4x'), required=True)
            p.add_argument('--seconds', type=float, default=60)
    p = sub.add_parser('decode')
    p.add_argument('--input', type=Path, required=True,
                   help='Raw binary DVI receive stream, not EFX/HTX')
    p.add_argument('--timestamps', action='store_true')
    p.add_argument('--output', type=Path, required=True)
    p = sub.add_parser('replay', help='Offline replay of the tool\'s JSONL logs')
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--timestamps', action='store_true',
                   help='Initial layout only; subsequent recorded status changes are followed')
    p.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.mode == 'capture' and not 0 < args.seconds <= 43200:
        parser.error('--seconds must be between 0 and 43200')
    # Exclusive creation preserves all previous output and supplied input.
    with args.output.open('x', encoding='utf-8') as output:
        def emit(row):
            output.write(json.dumps(row, sort_keys=True) + '\n')
            output.flush()
        emit({'kind': 'session', 'mode': args.mode,
              'utc_started': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'vehicle_transmit_commands_enabled': False,
              'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
        if args.mode in ('decode', 'replay'):
            emit({'kind': 'input_configuration', 'path': str(args.input.resolve()),
                  'timestamps': args.timestamps, 'timestamp_byte_order': 'unknown'})
        try:
            if args.mode == 'replay':
                replay_jsonl(args.input, emit, args.timestamps)
            elif args.mode == 'decode':
                decoder = Decoder(args.timestamps)
                digest = hashlib.sha256()
                with args.input.open('rb') as stream:
                    while chunk := stream.read(4096):
                        digest.update(chunk)
                        for row in decoder.iter_feed(chunk):
                            emit(row)
                decoder.finish()
                emit({'kind': 'input', 'path': str(args.input.resolve()),
                      'sha256': digest.hexdigest()})
            else:
                emit({'kind': 'transport', 'port': args.port, 'api': args.api,
                      'baud': 115200})
                port = WindowsSerial(args.port)
                try:
                    session = Session(port, emit)
                    session.connect(args.api)
                    if args.mode == 'inspect':
                        print(json.dumps(session.inspect(), indent=2))
                    elif args.mode == 'probe':
                        print(json.dumps(session.probe_settings(), indent=2))
                    else:
                        session.capture(args.speed, args.seconds)
                finally:
                    port.close()
            emit({'kind': 'result', 'success': True,
                  'capture_completeness': 'not established'})
        except BaseException as error:
            emit({'kind': 'result', 'success': False, 'error': str(error),
                  'capture_completeness': 'not established'})
            raise


if __name__ == '__main__':
    main()
