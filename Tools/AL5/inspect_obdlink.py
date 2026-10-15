"""Bounded OBDLink adapter-local queries only; never opens a vehicle protocol.

No resets, bare CR (repeat-last-command), monitor, protocol setters, firmware
updates or OBD requests. UART is fixed at 115200; there is no baud probing.
"""
import argparse
import json
from pathlib import Path
import re
import time

from obdx_capture import WindowsSerial


QUERIES = ('ATI', 'STI', 'STDI', 'STSN', 'STIX', 'STMFR',
           'STDIX', 'ATRV', 'ATDP', 'ATDPN', 'STPBRR')


class LocalQueries:
    def __init__(self, port, rows, timeout=2.0):
        self.port, self.rows, self.timeout = port, rows, timeout

    def query(self, command):
        if command not in QUERIES:
            raise PermissionError('Only exact adapter-local queries are allowed')
        row = {'command': command, 'tx_hex': (command + '\r').encode().hex(),
               'rx_hex': '', 'complete': False}
        self.rows.append(row)
        self.port.write((command + '\r').encode('ascii'))
        deadline = time.monotonic() + self.timeout
        data = bytearray()
        while time.monotonic() < deadline:
            chunk = self.port.read()
            data.extend(chunk)
            row['rx_hex'] = data.hex()
            if len(data) > 65536:
                raise ValueError('Response exceeds inspection limit')
            if b'>' in data:
                before, after = bytes(data).split(b'>', 1)
                if after.strip():
                    raise ValueError('Unexpected bytes after adapter prompt')
                row['text'] = before.decode('ascii', errors='replace')
                row['complete'] = True
                return row['text']
        raise TimeoutError('No prompt; stopped without reset or retry')


def inspect(port, report):
    # Existing unsolicited traffic means this is not an idle local session.
    pending = port.read()
    report['initial_rx_hex'] = pending.hex()
    if pending:
        raise ValueError('Adapter not idle; stopped before sending queries')
    session = LocalQueries(port, report['queries'])
    session.query('ATI')
    firmware = session.query('STI')
    if not re.search(r'\bSTN1130\s+v\d', firmware):
        raise ValueError('Expected OBDLink SX STN1130 identity not confirmed')
    for command in QUERIES[2:]:
        session.query(command)
    report['inspection_complete'] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    # Refuse overwrite and reserve output before opening any device.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as output:
        report = {'schema': 'obdlink-local-inspection-v1', 'port': args.port,
                  'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                  'uart_baud': 115200, 'queries': [],
                  'vehicle_commands_sent': False, 'vehicle_bus_state': 'unobserved',
                  'passive_capture_proven': False, 'vpw_4x_proven': False,
                  'inspection_complete': False}
        port = None
        try:
            port = WindowsSerial(args.port)
            inspect(port, report)
        except Exception as error:
            report['error'] = str(error)
        finally:
            if port is not None:
                try:
                    port.close()
                except Exception as error:
                    report['close_error'] = str(error)
            json.dump(report, output, indent=2)
            output.write('\n')
        print(json.dumps(report, indent=2))
        return 0 if report['inspection_complete'] and 'close_error' not in report else 1


if __name__ == '__main__':
    raise SystemExit(main())
