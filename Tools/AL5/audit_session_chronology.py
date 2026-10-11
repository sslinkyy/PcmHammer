"""Saved AL5 session candidate chronology; no execution, transport or packet output."""
import argparse
from collections import Counter
import json
from pathlib import Path

from al5_segment import sha256
from audit_trace_wrappers import recognized_header, framed_message
from decode_trace_containers import decode, records, NAME, MAX_INPUT


def summarize_records(parsed):
    """Record order is observed; candidate links do not assign session state."""
    if not parsed:
        raise ValueError('empty trace records')
    events = []
    # Fixed route identities keep all candidates once. Event references select
    # the prefix present at that record, never later events or a time window.
    indices = {f'{kind}:{tester}': {'kind': kind, 'tester': tester, 'ordinals': []}
               for kind in ('mode34', 'mode74_44') for tester in ('0xf0', '0xf1')}
    orphan_responses = {'0xf0': 0, '0xf1': 0}
    uploads = 0
    first_date = parsed[0]['date']
    for ordinal, record in enumerate(parsed):
        observed = framed_message(record)
        if observed is None:
            continue
        direction, message = observed
        if not recognized_header(message):
            continue
        request_route = message[1] in (0x18, 0xFE) and message[2] in (0xF0, 0xF1)
        response_route = message[1] in (0xF0, 0xF1) and message[2] == 0x18
        kind = None
        if direction == 'host_tx_candidate' and request_route and message[3] == 0x34:
            kind = 'mode34_request_candidate'
        elif direction == 'device_rx_candidate' and response_route and message[3:] == b'\x74\x44':
            kind = 'mode74_44_response_candidate'
        elif direction == 'host_tx_candidate' and request_route and message[3:5] == b'\x36\x80':
            kind = 'subtype80_upload_candidate'
        if kind is None:
            continue
        event = {'kind': kind, 'record_ordinal': ordinal, 'record_offset': hex(record['offset']),
                 'elapsed_ms': round((record['date'] - first_date) * 86400000, 3),
                 'direction_inference': direction, 'priority': hex(message[0]),
                 'destination': hex(message[1]), 'source': hex(message[2]),
                 'message_bytes': len(message), 'message_sha256': sha256(message)}
        if kind == 'mode34_request_candidate':
            indices[f"mode34:{event['source']}"]['ordinals'].append(ordinal)
        elif kind == 'mode74_44_response_candidate':
            request_key = f"mode34:{event['destination']}"
            count = len(indices[request_key]['ordinals'])
            event['preceding_route_compatible_requests'] = {'index': request_key, 'end_exclusive': count}
            event['preceding_route_compatible_request_count'] = count
            event['request_pairing_verified'] = False
            event['pairing_ambiguities'] = ['application_startup_and_boot_dispatcher_share_response']
            if not count:
                event['pairing_ambiguities'].append('no_preceding_route_compatible_request')
                orphan_responses[event['destination']] += 1
            elif count > 1:
                event['pairing_ambiguities'].append('multiple_preceding_requests_or_retries')
            indices[f"mode74_44:{event['destination']}"]['ordinals'].append(ordinal)
        else:
            response_key = f"mode74_44:{event['source']}"
            request_key = f"mode34:{event['source']}"
            response_count = len(indices[response_key]['ordinals'])
            request_count = len(indices[request_key]['ordinals'])
            event['preceding_route_compatible_responses'] = {'index': response_key, 'end_exclusive': response_count}
            event['preceding_route_compatible_requests'] = {'index': request_key, 'end_exclusive': request_count}
            event['preceding_route_compatible_response_count'] = response_count
            event['preceding_route_compatible_request_count'] = request_count
            event['preceding_orphan_response_count'] = orphan_responses[event['source']]
            event['pairing_ambiguities'] = ['response_does_not_prove_upload_arming',
                                          'prior_response_may_be_stale_or_unrelated']
            if not response_count:
                event['pairing_ambiguities'].append('no_preceding_route_compatible_response')
            elif response_count > 1:
                event['pairing_ambiguities'].append('multiple_preceding_responses')
            if orphan_responses[event['source']]:
                event['pairing_ambiguities'].append('response_without_preceding_request')
            event['upload_arming_verified'] = False
            uploads += 1
        events.append(event)
    counts = Counter(e['message_sha256'] for e in events)
    for event in events:
        event['identical_message_candidate_count'] = counts[event['message_sha256']]
    return {'record_count': len(parsed), 'ordinal_origin': 'zero_based_all_decoded_records',
            'timestamp_origin': 'first_decoded_record',
            'timestamps_monotonic': all(a['date'] <= b['date'] for a, b in zip(parsed, parsed[1:])),
            'candidate_ordinal_indices': indices,
            'candidate_reference_semantics': 'Each reference selects ordinals[0:end_exclusive] from its named shared index; later candidates are excluded. Indices combine module/global requests per tester because recognized AL5 responses originate from module 0x18.',
            'events': events,
            'mode34_request_count': sum(len(v['ordinals']) for v in indices.values() if v['kind'] == 'mode34'),
            'mode74_44_response_count': sum(len(v['ordinals']) for v in indices.values() if v['kind'] == 'mode74_44'),
            'subtype80_upload_count': uploads,
            'application_entry_verified': False, 'upload_arming_verified': False,
            'request_response_pairing_verified': False, 'physical_timing_verified': False,
            'operation_outcome': None}


def analyze(path):
    path = Path(path)
    if not NAME.fullmatch(path.name):
        raise ValueError('explicit saved AL5 trace required')
    if not 0 < path.stat().st_size <= MAX_INPUT:
        raise ValueError('encoded input exceeds policy')
    source = path.read_bytes()
    decoded = decode(source)
    return {'source_name': path.name, 'source_sha256': sha256(source),
            'decoded_sha256': sha256(decoded), **summarize_records(list(records(decoded)))}


def report(paths):
    traces = [analyze(path) for path in paths]
    if not traces:
        raise ValueError('no saved AL5 traces')
    return {'schema_version': 2, 'scope': 'Saved framed Mode34, Mode74/44 and subtype80 chronology only.',
            'limits': 'Links enumerate all preceding address-compatible candidates without a time cutoff or unique pairing claim. Global requests can have module responses. Repeated or stale responses cannot prove arming; startup and boot dispatcher share 7444 bytes. Container order/timestamps do not establish physical bus order/timing or complete capture. Private payloads, keys and executable bytes are not exported.',
            'generator_sha256': sha256(Path(__file__).read_bytes()),
            'trace_count': len(traces), 'traces': traces,
            'physical_transport_verified': False, 'complete_programming_exchange_verified': False,
            'physical_recovery_verified': False, 'ready_to_flash': False,
            'live_write_enabled': False, 'erase_scope': None,
            'would_send': [], 'erase_packets': [], 'program_packets': []}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if any(args.output.resolve() == path.resolve() for path in args.trace):
        parser.error('output must not overwrite an input trace')
    result = report(args.trace)
    with args.output.open('x', encoding='utf8') as output:
        output.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'trace_count': result['trace_count'], 'ready_to_flash': False}))
