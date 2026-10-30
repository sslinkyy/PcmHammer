"""Bounded adapter-local GT filter-link probe; the vehicle network stays OFF.

Readback disagreements are observations, not successful setting checks. This
does not qualify filtering, reception, electrical silence, or programming.
Restoration compares observable GET payloads only. If GET aliases a different
flag, the original hidden stored flag is unknown and may change despite an
identical final readback. This probe cannot prove hidden-state restoration.
"""
import argparse
import hashlib
import json
from pathlib import Path
import time

from obdx_capture import ProtocolError, Session, SETTINGS, WindowsSerial


FILTERS = tuple(setting for setting in SETTINGS if setting[0] == 0x33 and setting[1] <= 4)
EXACT_STATES = ((0, 0), (1, 0), (0, 1), (1, 1))
# Observed GT exact-filter enable writes OR FF into the shared mask lane.
# Restore exact/range settings before the mask so source-only and enabled-zero
# masks survive. Other incompatible coupling fails the final comparison;
# restoration never retries alternate orders or infers hidden stored state.
RESTORE_LABELS = ('timestamps', 'speed', 'crc_validation', 'crc_display',
                  'to_range_filter', 'from_range_filter',
                  'to_filter', 'from_filter', 'mask_filter')


class OffSession(Session):
    """Narrow the existing DVI guard: this probe cannot enable any network."""
    def send(self, command, payload):
        if command == 0x31 and bytes(payload) not in (b'\x01', b'\x02', b'\x02\x00'):
            raise PermissionError('Filter-link probe permits network OFF and queries only')
        super().send(command, payload)


def require_off(session):
    observed = session.request(0x31, [2])['payload_hex']
    if observed != '0200':
        session.emit({'kind': 'unexpected_network_state', 'payload_hex': observed})
        raise ProtocolError('Network must already be OFF; filter-link probe stopped')


def snapshot(session, label, settings=SETTINGS):
    require_off(session)
    values = {}
    for command, sub, size, name in settings:
        raw = session.request(command, [sub])['payload_hex']
        payload = bytes.fromhex(raw)
        if len(payload) != size or payload[0] != sub or payload[-1] not in (0, 1):
            session.emit({'kind': 'unknown_setting_shape', 'snapshot': label,
                          'setting': name, 'payload_hex': raw, 'partial_readbacks': values})
            raise ProtocolError('Unknown setting shape for ' + name)
        values[name] = raw
    require_off(session)
    session.emit({'kind': 'filter_snapshot', 'snapshot': label,
                  'setting_readbacks': values, 'network_state': '0200'})
    return values


def change_and_observe(session, payload, label, setting, requested_state):
    require_off(session)
    # An echo is checked separately from the full cross-filter GET snapshot.
    # A mismatched GET remains data; it never authorizes a receive operation.
    session.request(0x33, payload, echo=True)
    values = snapshot(session, label, FILTERS)
    requested = bytes(payload).hex()
    target_flags = {'to': requested_state[0], 'from': requested_state[1]}
    observed_flags = {'to': bytes.fromhex(values['to_filter'])[-1],
                      'from': bytes.fromhex(values['from_filter'])[-1]}
    row = {'kind': 'filter_link_observation', 'case': label,
           'target_exact_flags': target_flags, 'observed_exact_flags': observed_flags,
           'target_exact_flags_reached': observed_flags == target_flags,
           'changed_setting': setting, 'requested_payload_hex': requested,
           'echo_matches': True, 'readback_payload_hex': values[setting],
           'readback_matches': values[setting] == requested,
           'all_filter_readbacks': values, 'network_state': '0200',
           'receive_behavior_verified': False}
    session.emit(row)
    return row


def restore(session, saved):
    try:
        session.set_checked(0x31, [2, 0])
        session.emit({'kind': 'cleanup', 'network_off_acknowledged': True})
    except BaseException as error:
        session.emit({'kind': 'cleanup', 'network_off_acknowledged': False, 'error': str(error)})
        raise
    if saved is None:
        session.emit({'kind': 'settings_readback_restoration', 'success': True,
                      'restoration_required': False, 'observable_readbacks_match_original': None,
                      'hidden_setting_state_restored': None,
                      'reason': 'No complete snapshot; no probe setting writes issued'})
        return
    try:
        by_name = {name: command for command, _, _, name in SETTINGS}
        for name in RESTORE_LABELS:
            require_off(session)
            payload = bytes.fromhex(saved[name])
            session.request(by_name[name], payload, echo=True)
            if name == 'timestamps':
                session.decoder.timestamps = bool(payload[-1])
        actual = snapshot(session, 'restored_all_readbacks')
        differences = {name: {'expected': saved[name], 'observed': actual[name]}
                       for name in saved if actual[name] != saved[name]}
        if differences:
            session.emit({'kind': 'restoration_mismatch', 'differences': differences,
                          'restoration_supported': False, 'retry_attempted': False})
            raise ProtocolError('Final complete settings readback snapshot does not match original; '
                                'restoration coupling unsupported')
        session.decoder.finish()
    except BaseException as error:
        session.emit({'kind': 'settings_readback_restoration', 'success': False,
                      'hidden_setting_state_restored': None, 'error': str(error)})
        raise
    finally:
        # A failed or surprising restoration must also finish with OFF checked.
        try:
            session.set_checked(0x31, [2, 0])
            session.emit({'kind': 'final_network_state', 'network_off_acknowledged': True})
        except BaseException as error:
            session.emit({'kind': 'final_network_state', 'network_off_acknowledged': False,
                          'error': str(error)})
            raise
    session.emit({'kind': 'settings_readback_restoration', 'success': True,
                  'restoration_required': True, 'observable_readbacks_match_original': True,
                  'restoration_write_order': list(RESTORE_LABELS),
                  'hidden_setting_state_restored': None,
                  'scope': 'All nine GET payloads match; hidden stored state is unknown'})


def run(port, emit, api):
    if api not in ('dvi', 'elm'):
        raise ValueError('An explicit known API is required')
    session = OffSession(port, emit)
    # Do not mutate settings or request OFF from a device of unknown identity.
    session.connect(api)
    saved = None
    observations = []
    try:
        require_off(session)
        saved = snapshot(session, 'original_all_readbacks')
        for to_flag, from_flag in EXACT_STATES:
            flags = (to_flag, from_flag)
            state_name = 'to%d_from%d' % flags
            for name, flag in (('to_filter', to_flag), ('from_filter', from_flag)):
                payload = bytes.fromhex(saved[name])[:-1] + bytes([flag])
                observations.append(change_and_observe(session, payload, state_name + '_' + name,
                                                       name, flags))
            for mask_flag in (0, 1):
                payload = bytes.fromhex(saved['mask_filter'])[:-1] + bytes([mask_flag])
                observations.append(change_and_observe(session, payload, state_name + '_mask%d' % mask_flag,
                                                       'mask_filter', flags))
    finally:
        restore(session, saved)
    result = {'kind': 'probe_summary', 'completed': True,
              'requested_exact_states': len(EXACT_STATES), 'mask_cases': 8,
              'observations': len(observations),
              'readback_mismatches': sum(not row['readback_matches'] for row in observations),
              'observable_readbacks_match_original': True,
              'hidden_setting_state_restored': None,
              'network_state': '0200', 'receive_behavior_verified': False,
              'electrical_silence_proven': False, 'vehicle_transmit_commands_enabled': False}
    emit(result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', required=True)
    parser.add_argument('--api', required=True, choices=('elm', 'dvi'),
                        help='Known current API; no reset, guessing, or fallback')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    with args.output.open('x', encoding='utf8') as output:
        def emit(row):
            output.write(json.dumps(row, sort_keys=True) + '\n')
            output.flush()
        emit({'kind': 'session', 'mode': 'filter-links',
              'schema': 'obdx-filter-links-v1',
              'utc_started': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'source_files': {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                               for name in ('obdx_capture.py', 'obdx_speed.py')},
              'restoration_scope': 'Observable GET payloads only; hidden stored state is unknown',
              'restoration_write_order': list(RESTORE_LABELS),
              'vehicle_transmit_commands_enabled': False, 'receive_enable_permitted': False})
        emit({'kind': 'transport', 'port': args.port, 'api': args.api, 'baud': 115200})
        try:
            port = WindowsSerial(args.port)
            try:
                run(port, emit, args.api)
            finally:
                port.close()
        except BaseException as error:
            emit({'kind': 'result', 'success': False, 'error': str(error),
                  'error_type': type(error).__name__})
            raise
        emit({'kind': 'result', 'success': True, 'receive_behavior_verified': False,
              'observable_readbacks_match_original': True, 'hidden_setting_state_restored': None})
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
