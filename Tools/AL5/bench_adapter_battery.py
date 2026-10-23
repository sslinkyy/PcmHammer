"""Bounded GT receive matrix on the user-confirmed isolated bench ECM.

SX sends only 0100; no loader, reset, security, speed negotiation or flash.
GT ON cases are explicitly not claimed to be passive. No arbitrary payloads.
"""
import argparse
import hashlib
import json
from pathlib import Path
import time

from bench_dual_adapter_probe import exchange, gt_fixed
from inspect_obdlink import LocalQueries
from obdx_capture import Session, SETTINGS, WindowsSerial, ProtocolError


CASES = (
    ('listen_no_timestamps', 2, 0, 1, None),
    ('listen_timestamps', 2, 1, 1, None),
    ('listen_crc_validation_off', 2, 0, 0, None),
    ('listen_to_f1', 2, 0, 1, [0, 0xf1, 1]),
    ('listen_from_10', 2, 0, 1, [1, 0x10, 1]),
    ('listen_to_range_all', 2, 0, 1, [2, 0, 0xff, 1]),
    ('listen_from_range_all', 2, 0, 1, [3, 0, 0xff, 1]),
    ('on_receive_no_gt_requests', 1, 0, 1, None),
    ('on_to_f1_no_gt_requests', 1, 0, 1, [0, 0xf1, 1]),
    ('listen_from_10_flag_off', 2, 0, 1, [1, 0x10, 0]),
    ('listen_from_f1', 2, 0, 1, [1, 0xf1, 1]),
    ('listen_from_f1_flag_off', 2, 0, 1, [1, 0xf1, 0]),
    ('listen_from_unrelated_55', 2, 0, 1, [1, 0x55, 1]),
    ('listen_from_10_timestamps', 2, 1, 1, [1, 0x10, 1]),
    ('listen_from_10_crc_off', 2, 0, 0, [1, 0x10, 1]),
)

ROUTING_CASES = (
    ('listen_to_6a', 2, 0, 1, [0, 0x6a, 1]),
    ('listen_to_6b', 2, 0, 1, [0, 0x6b, 1]),
    ('listen_to_range_60_70', 2, 0, 1, [2, 0x60, 0x70, 1]),
    ('listen_from_range_10_11', 2, 0, 1, [3, 0x10, 0x11, 1]),
    ('listen_from_range_00_7f', 2, 0, 1, [3, 0, 0x7f, 1]),
    ('listen_from_range_80_ff', 2, 0, 1, [3, 0x80, 0xff, 1]),
)

COMBINED_CASES = (
    ('listen_from_10_or_to_6a', 2, 0, 1, ([1, 0x10, 1], [0, 0x6a, 1])),
    ('listen_from_10_or_to_6a_timestamps', 2, 1, 1, ([1, 0x10, 1], [0, 0x6a, 1])),
    ('listen_mask_priority_08', 2, 0, 1, [4, 8, 0, 0, 1]),
    ('listen_mask_priority_40', 2, 0, 1, [4, 0x40, 0, 0, 1]),
)

REPEAT_CASES = (
    ('listen_from_10_repeat', 2, 0, 1, [1, 0x10, 1]),
    ('listen_from_f1_repeat', 2, 0, 1, [1, 0xf1, 1]),
    ('listen_from_10_and_to_6b_repeat', 2, 1, 1, ([1, 0x10, 1], [0, 0x6b, 1])),
)


def drain(session, seconds, emit):
    deadline = time.monotonic() + seconds
    count = 0
    while time.monotonic() < deadline:
        for row in session.decoder.iter_feed(session.read()):
            emit(row)
            count += row['kind'] == 'network'
            if row['command'] == 0x7f:
                raise ProtocolError('GT error during receive matrix; stopped')
    return count


def save(session):
    session.set_checked(0x31, [2, 0])
    values = []
    for command, sub, size, label in SETTINGS:
        value = bytes.fromhex(session.request(command, [sub])['payload_hex'])
        if len(value) != size or value[-1] not in (0, 1):
            raise ProtocolError('Unknown saved setting shape')
        values.append((command, value))
    return values


def restore(session, saved):
    session.set_checked(0x31, [2, 0])
    for command, value in saved:
        session.set_checked(command, value)
        if command == 0x24:
            session.decoder.timestamps = bool(value[1])


def configure(session, case):
    name, state, timestamp, crc, enabled_filter = case
    session.configure_listener('1x')
    session.set_checked(0x31, [2, 0])
    session.set_checked(0x24, [3, timestamp])
    session.decoder.timestamps = bool(timestamp)
    session.set_checked(0x33, [7, crc])
    if enabled_filter is not None:
        for value in (enabled_filter if isinstance(enabled_filter, tuple) else (enabled_filter,)):
            session.set_checked(0x33, value)
    if state == 1:
        gt_fixed(session, 0x31, b'\x02\x01')
        if session.request(0x31, [2])['payload_hex'] != '0201':
            raise ProtocolError('GT ON readback mismatch')
    else:
        session.set_checked(0x31, [2, 2])


def run(gt, sx, emit, cases=None, repetitions=3):
    if type(repetitions) is not int or not 1 <= repetitions <= 100:
        raise ValueError('Repetition count outside bench bound; no commands sent')
    rows = []
    if sx.read():
        raise ValueError('SX pending input; stopped')
    local = LocalQueries(sx, rows)
    if local.query('STI').replace('STI', '').strip() != 'STN1130 v4.0.1':
        raise ValueError('Unexpected SX firmware')
    if 'OBDLink SX r4.2' not in local.query('STDI'):
        raise ValueError('Unexpected SX hardware')
    if local.query('ATDPN').replace('ATDPN', '').strip() != '2':
        raise ValueError('SX must already have explicit VPW selected')
    for command in ('ATSH686AF1', 'ATH1', 'ATIFR0'):
        if exchange(sx, command, rows) != 'OK':
            raise ValueError('SX fixed setup rejected')
    emit({'kind': 'sx_setup', 'queries': rows})
    session = Session(gt, emit)
    session.connect('dvi')
    session.inspect()
    saved = save(session)
    results = []
    try:
        # GT OFF control confirms the ECM/SX exchange before listening tests.
        for case in (('off_control', 0, 0, 1, None),) + (CASES if cases is None else cases):
            name, state, timestamp, crc, selected = case
            result = {'case': name, 'state': state, 'timestamps': timestamp,
                      'crc_validation': crc, 'selected_filter': selected,
                      'requests': [], 'network_frames': 0,
                      'gt_passive_mode_requested': state == 2}
            def record(row):
                emit(dict(row, case=name))
                if row.get('kind') == 'network':
                    result['network_frames'] += 1
            session.emit = record
            try:
                if state:
                    configure(session, case)
                for ordinal in range(3 if state == 0 else repetitions):
                    request = []
                    start = time.monotonic_ns()
                    observation = {'ordinal': ordinal + 1, 'exchange': request,
                                   'positive_response': False}
                    result['requests'].append(observation)
                    try:
                        response = exchange(sx, '0100', request)
                        observation['positive_response'] = '41 00 98 3B 00 15' in response
                    finally:
                        observation['elapsed_ns'] = time.monotonic_ns() - start
                    drain(session, .15, record)
                drain(session, .3, record)
                result['completed'] = True
            except ProtocolError as error:
                result.update(completed=False, error=str(error))
                # Setting mismatches block that case. Never transmit blindly.
            finally:
                restore(session, saved)
                result['gt_network_off_confirmed'] = True
                result['settings_restored'] = True
                emit({'kind': 'case_result', **result})
            results.append(result)
        return results
    finally:
        restore(session, saved)
        emit({'kind': 'cleanup', 'network_off_acknowledged': True,
              'settings_restored': True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gt-port', required=True)
    parser.add_argument('--sx-port', required=True)
    parser.add_argument('--bench-ecm-confirmed', action='store_true', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--extended-only', action='store_true',
                        help='Run six follow-up source-filter cases plus OFF control')
    parser.add_argument('--routing-only', action='store_true',
                        help='Run six destination/range-filter cases plus OFF control')
    parser.add_argument('--combined-only', action='store_true',
                        help='Run combined exact-filter and priority-mask cases plus OFF control')
    parser.add_argument('--repeat-only', action='store_true',
                        help='Run three verified-filter repetition cases plus OFF control')
    parser.add_argument('--repetitions', type=int, default=3)
    args = parser.parse_args()
    if args.gt_port == args.sx_port:
        parser.error('Distinct adapter ports required')
    if sum((args.extended_only, args.routing_only, args.combined_only, args.repeat_only)) > 1:
        parser.error('Select one matrix subset')
    if not 1 <= args.repetitions <= 100:
        parser.error('Repetitions must be 1..100')
    with args.output.open('x', encoding='utf8') as stream:
        def emit(row):
            stream.write(json.dumps(row, sort_keys=True) + '\n')
            stream.flush()
        emit({'kind': 'battery', 'schema': 'bench-gt-receive-matrix-v1',
              'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'source_files': {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                               for name in ('obdx_capture.py', 'bench_dual_adapter_probe.py', 'inspect_obdlink.py')},
              'programming_enabled': False, 'electrical_silence_proven': False,
              'gt_port': args.gt_port, 'sx_port': args.sx_port})
        gt = sx = None
        try:
            gt = WindowsSerial(args.gt_port)
            sx = WindowsSerial(args.sx_port)
            cases = next((values for selected, values in (
                (args.repeat_only, REPEAT_CASES), (args.combined_only, COMBINED_CASES),
                (args.routing_only, ROUTING_CASES), (args.extended_only, CASES[-6:])) if selected), None)
            results = run(gt, sx, emit, cases, args.repetitions)
            emit({'kind': 'result', 'completed': True,
                  'cases_completed': sum(r['completed'] for r in results),
                  'cases_blocked': sum(not r['completed'] for r in results)})
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
