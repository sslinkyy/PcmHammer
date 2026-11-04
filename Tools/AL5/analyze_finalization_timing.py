"""Saved EFILive AL5 tail timing only; no transport, clock calibration or send plan."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from decode_trace_containers import decode, records
from inspect_autocal_read_gap import frame


def digest(data):
    return hashlib.sha256(data).hexdigest()


FINALIZE = bytes.fromhex('6c18f036ff')
FINAL_REPLY = bytes.fromhex('6cf018760086')
QUERY = bytes.fromhex('6c18f03c55')
IDENTITY = bytes.fromhex('6cf0187c550a0012')


def analyze(source):
    rows = list(records(decode(source)))
    events = []
    previous = None
    for ordinal, row in enumerate(rows):
        if row['kind'] != 0x42:
            continue
        item = frame(row['payload'], row['channel'])
        if not (item['command'] == 0x8a00 if item['direction'] == 1
                else item['raw'][2:6] == bytes.fromhex('18000000')):
            continue
        message = item['payload']
        if len(message) < 4 or message[1:3] not in (b'\x18\xf0', b'\xf0\x18', b'\xfe\xf0'):
            continue
        if previous is not None and row['date'] < previous:
            raise ValueError('Relevant trace timestamps moved backwards; no elapsed-time inference')
        previous = row['date']
        events.append(dict(ordinal=ordinal, offset=row['offset'], date=row['date'],
                           direction=item['direction'], message=message))
    requests = [e for e in events if e['direction'] == 1 and e['message'] == FINALIZE]
    if len(requests) != 1:
        raise ValueError('Exactly one observed finalization request required; split sessions explicitly')
    request = requests[0]
    replies = [e for e in events if e['direction'] == 2 and e['message'] == FINAL_REPLY]
    if len(replies) > 1 or (replies and replies[0]['ordinal'] < request['ordinal']):
        raise ValueError('Ambiguous or unowned final success reply')
    reply = replies[0] if replies else None
    tail = [e for e in events if reply is not None and e['ordinal'] > reply['ordinal']]
    identities = [e for e in tail if e['direction'] == 2 and e['message'] == IDENTITY]
    first_identity = identities[0] if identities else None
    queries = [e for e in tail if e['direction'] == 1 and e['message'] == QUERY
               and (first_identity is None or e['ordinal'] < first_identity['ordinal'])]
    if first_identity is not None and not queries:
        raise ValueError('Post-finalization identity reply has no preceding captured query')

    def delta(first, last):
        return round((last['date'] - first['date']) * 86400000, 3)

    def observation(event):
        if event is None:
            return None
        return dict(record_ordinal=event['ordinal'], decoded_offset=event['offset'],
                    saved_date_f64_le_hex=struct.pack('<d', event['date']).hex(),
                    message_sha256=digest(event['message']), message_bytes=len(event['message']),
                    direction='host_to_device' if event['direction'] == 1 else 'device_to_host',
                    ms_after_final_request=delta(request, event),
                    ms_after_final_reply=delta(reply, event) if reply is not None else None)

    # Query repeats have no transaction ID. Ordered observations do not prove
    # which query caused the response, or whether an uncaptured reply existed.
    return dict(schema='al5-saved-finalization-timing-v1', source_sha256=digest(source),
                records_examined=len(rows), relevant_vehicle_records=len(events),
                final_request=observation(request), final_reply=observation(reply),
                queries_before_first_identity=[observation(e) for e in queries],
                first_identity_reply=observation(first_identity),
                observed_query_count_before_identity=len(queries),
                final_reply_to_first_query_ms=delta(reply, queries[0]) if queries else None,
                query_spacing_ms=[delta(a, b) for a, b in zip(queries, queries[1:])],
                final_reply_to_identity_ms=delta(reply, first_identity) if first_identity else None,
                last_query_to_identity_ms=delta(queries[-1], first_identity) if first_identity else None,
                mode23_requests_after_final_reply=sum(e['direction'] == 1 and e['message'][3] == 0x23 for e in tail),
                mode63_replies_after_final_reply=sum(e['direction'] == 2 and e['message'][3] == 0x63 for e in tail),
                identity_query_response_pairing_proven=False, physical_reset_verified=False,
                flash_readback_verified=False, post_finalization_readback_window_verified=False,
                physical_deadlines_qualified=False, hardware_access=False,
                live_upload_enabled=False, live_execution_enabled=False, live_write_enabled=False,
                automatic_retry_enabled=False, ready_to_flash=False,
                limitations=[
                    'Saved wrapper timestamps are host/device observations, not wire or reset timestamps.',
                    'Repeated identity queries carry no transaction ID; reply causation is unresolved.',
                    'Identity response is not a flash read, coherent snapshot, or preservation comparison.',
                    'No observed delay is promoted to a watchdog deadline, polling policy or sleep duration.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', type=Path, required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.trace.read_bytes()
    if digest(source) != args.expected_sha256.lower():
        parser.error('Saved trace hash mismatch')
    result = analyze(source)
    result['source_selected_path'] = str(args.trace)
    result['source_resolved_path'] = str(args.trace.resolve())
    result['producers'] = {str(p): digest(p.read_bytes()) for p in
                           (Path(__file__), Path(__file__).with_name('decode_trace_containers.py'),
                            Path(__file__).with_name('inspect_autocal_read_gap.py'),
                            Path(__file__).with_name('audit_trace_wrappers.py'),
                            Path(__file__).with_name('checksum.py'))}
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print('Saved tail analyzed; no physical reset/readback window qualified.')


if __name__ == '__main__':
    main()
