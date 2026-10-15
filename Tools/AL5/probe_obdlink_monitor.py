"""USB-only SX monitor entry/exit probe; OBD plug MUST be physically unplugged.

This is not a vehicle capture tool or electrical silence qualification. No
settings are changed and no protocol-open or vehicle-request command is used.
"""
import argparse
import json
from pathlib import Path
import time

from inspect_obdlink import LocalQueries
from obdx_capture import WindowsSerial


def receive(port, row, seconds):
    deadline = time.monotonic() + seconds
    data = bytearray()
    while time.monotonic() < deadline:
        data.extend(port.read())
        row['rx_hex'] = data.hex()
        if len(data) > 65536:
            raise ValueError('Unexpected response volume; no retry')
        if b'>' in data:
            return bytes(data)
    return bytes(data)


def probe(port, report, *, usb_only_confirmed=False, duration=1.0):
    if not usb_only_confirmed:
        raise PermissionError('Requires physical OBD disconnection confirmation')
    pending = port.read()
    report['initial_rx_hex'] = pending.hex()
    if pending:
        raise ValueError('Pending adapter input; stopped before sending')
    local = LocalQueries(port, report['queries'])
    if local.query('STI').replace('STI', '').strip() != 'STN1130 v4.0.1':
        raise ValueError('Probe is restricted to observed SX firmware 4.0.1')
    hardware = local.query('STDI')
    if 'OBDLink SX r4.2' not in hardware:
        raise ValueError('Expected SX hardware identity not confirmed')
    if local.query('ATDPN').replace('ATDPN', '').strip() != '2':
        raise ValueError('Selected protocol must already be VPW; no setter used')
    if local.query('ATRV').replace('ATRV', '').strip() != '0.0V':
        raise ValueError('Unexpected voltage; stopped before monitoring')
    monitor = {'command': 'STMA', 'tx_hex': b'STMA\r'.hex(), 'rx_hex': ''}
    report['queries'].append(monitor)
    port.write(b'STMA\r')
    entered = receive(port, monitor, duration)
    if b'>' in entered:
        report['monitor_ended_before_stop'] = True
        report['monitor_entry_exit_confirmed'] = False
        return
    if entered.replace(b'STMA\r', b'').strip():
        raise ValueError('Unexpected monitor output on disconnected adapter')
    # One non-hex, non-CR interrupt byte. Never retry or send an empty command.
    stop = {'command': 'interrupt-x', 'tx_hex': b'x'.hex(), 'rx_hex': ''}
    report['queries'].append(stop)
    port.write(b'x')
    stopped = receive(port, stop, 2.0)
    if not stopped.rstrip().endswith(b'>'):
        raise ValueError('Monitor stop not confirmed; no follow-up command sent')
    if stopped.split(b'>', 1)[1].strip():
        raise ValueError('Unexpected data after stop prompt')
    # Observed 4.0.1 behavior on an empty bus: CR + prompt, no STOPPED text.
    before = stopped.split(b'>', 1)[0].strip()
    if before not in (b'', b'STOPPED'):
        raise ValueError('Unexpected stop response; no follow-up command sent')
    report['stop_message_present'] = before == b'STOPPED'
    report['stop_prompt_observed'] = True
    report['monitor_entry_exit_confirmed'] = True
    report['post_stop_identity'] = local.query('STI')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--obd-plug-unplugged', action='store_true', required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf8') as output:
        report = {'schema': 'obdlink-usb-only-monitor-probe-v1', 'queries': [],
                  'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                  'port': args.port, 'obd_disconnected_user_confirmed': True,
                  'vehicle_request_commands_sent': False,
                  'vehicle_bus_state': 'physically disconnected per user',
                  'electrical_silence_proven': False,
                  'passive_reception_proven': False, 'vpw_4x_proven': False,
                  'monitor_entry_exit_confirmed': False}
        port = None
        try:
            port = WindowsSerial(args.port)
            probe(port, report, usb_only_confirmed=True)
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
        return 0 if report['monitor_entry_exit_confirmed'] and 'error' not in report and 'close_error' not in report else 1


if __name__ == '__main__':
    raise SystemExit(main())
