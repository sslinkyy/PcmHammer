"""File-only AL5 write evidence. Never imports a transport or emits a send plan."""
import argparse
from collections import Counter
import json
from pathlib import Path

from al5_segment import sha256
from analyze_trace_transfers import transfer_contract
from decode_trace_containers import decode, records
from inspect_autocal_read_gap import frame


def analyze(source, calibration):
    if len(calibration) != 57304:
        raise ValueError('Expected a 57,304-byte independent calibration reference')
    events, transfers, blocks, wrappers = [], [], {}, []
    reply_statuses = Counter()
    conflicts = []
    rows = list(records(decode(source)))
    for ordinal, row in enumerate(rows):
        if row['kind'] != 0x42:
            continue
        item = frame(row['payload'], row['channel'])  # validates extent and outer CRC
        msg = item['payload']
        if not (item['command'] == 0x8a00 if item['direction'] == 1
                else item['raw'][2:6] == bytes.fromhex('18000000')):
            continue
        if len(msg) < 4 or msg[1:3] not in (bytes.fromhex('18f0'), bytes.fromhex('f018')):
            continue
        event = dict(record_ordinal=ordinal, decoded_offset=row['offset'],
                     elapsed_ms=round((row['date']-rows[0]['date'])*86400000, 3),
                     direction=item['direction'], prefix=msg[:5].hex(), bytes=len(msg),
                     sha256=sha256(msg))
        if item['direction'] == 2 and len(msg) == 6 and msg[3:5] == bytes.fromhex('7600'):
            event['loader_status'] = msg[3:].hex()
            reply_statuses[msg[3:].hex()] += 1
        if item['direction'] == 1 and msg.startswith(bytes.fromhex('6d18f036')):
            contract = transfer_contract(msg)
            if not contract['length_matches'] or not contract['byte_sum_matches']:
                raise ValueError('Invalid captured transfer length or byte sum')
            event['transfer'] = contract
            transfers.append(event)
            if msg[4] == 0:
                address = int.from_bytes(msg[7:10], 'big')
                data = msg[10:-2]
                if not data or len(data) > 512 or len(data) % 2 or address % 2 or not 0x8000 <= address < address+len(data) <= 0x1fffe:
                    raise ValueError('Program block outside observed bounded profile')
                wrappers.append(msg.hex())
                for offset, value in enumerate(data):
                    absolute = address + offset
                    if absolute in blocks and blocks[absolute] != value:
                        conflicts.append(absolute)
                    blocks[absolute] = value
        events.append(event)
    coverage = len(blocks)
    dense = coverage == 0x1fffe-0x8000
    image = bytes(blocks[a] for a in range(0x8000, 0x1fffe)) if dense and not conflicts else None
    programming = [e for e in transfers if e['transfer']['subtype'] == '0x0']
    counts = Counter((e['transfer']['address'], e['transfer']['payload_sha256']) for e in programming)
    result = dict(schema='al5-captured-write-evidence-v1', source_sha256=sha256(source),
                  reference_sha256=sha256(calibration), events=events,
                  program_requests=len(programming), unique_address_payload_pairs=len(counts),
                  repeated_identical_requests=sum(n-1 for n in counts.values()),
                  conflicting_byte_addresses=sorted(set(conflicts)), covered_bytes=coverage,
                  dense_observed_range=dense, range_start=0x8000, range_end_exclusive=0x1fffe,
                  captured_image_sha256=sha256(image) if image is not None else None,
                  calibration_matches_reference=image[:57304] == calibration if image is not None else None,
                  collateral_sha256=sha256(image[57304:]) if image is not None else None,
                  loader_reply_status_counts=dict(reply_statuses),
                  positive_program_reply_count=reply_statuses['760073'],
                  checksum_error_reply_count=reply_statuses['760077'],
                  automatic_retry_enabled=False, recovery_verified=False, live_write_enabled=False,
                  ready_to_flash=False, would_send=[],
                  limitations=['Host requests are not proof of physical programming or erase geometry.',
                              'Repeated requests are not automatically classified as bus retries.',
                              'ACKs have no block address; count equality does not establish pairing.',
                              'Reference equality compares transmitted bytes, not post-write readback.'])
    return result, wrappers


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', type=Path, required=True)
    parser.add_argument('--calibration', type=Path, required=True)
    parser.add_argument('--expected-calibration-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--private-program-corpus', type=Path)
    args = parser.parse_args()
    calibration = args.calibration.read_bytes()
    if sha256(calibration) != args.expected_calibration_sha256.lower():
        parser.error('Reference hash mismatch')
    result, corpus = analyze(args.trace.read_bytes(), calibration)
    result.update(source_name=args.trace.name)
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf8')
    if args.private_program_corpus:
        args.private_program_corpus.write_text('\n'.join(corpus)+'\n', encoding='ascii')
    print(json.dumps({k:v for k,v in result.items() if k != 'events'}))
