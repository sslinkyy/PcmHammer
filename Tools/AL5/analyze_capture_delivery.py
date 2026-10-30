"""Offline byte accounting and host-delivery evidence for a saved DVI capture.

Reuses strict replay; never opens a serial port. Host arrival gaps and frame
assembly spans describe logging/delivery, not VPW pulse timing or a loss site.
"""
import argparse
from bisect import bisect_right
from collections import Counter
import hashlib
import json
from pathlib import Path
import statistics

from compare_vpw_read_capture import DATA_HEADER, crc8_j1850
from obdx_capture import replay_jsonl


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def distribution(values):
    return {'count': len(values), 'minimum': min(values) if values else None,
            'maximum': max(values) if values else None,
            'median': statistics.median(values) if values else None,
            'total': sum(values)}


def elapsed(first, last):
    return last - first if type(first) is int and type(last) is int and last >= first else None


def e54_address(payload, crc_present):
    """Candidate address in the already-supported E54 read envelope only."""
    if not crc_present or not payload or crc8_j1850(payload[:-1]) != payload[-1]:
        return None
    message = payload[:-1]
    if len(message) < 10:
        return None
    size, address = int.from_bytes(message[5:7], 'big'), int.from_bytes(message[7:10], 'big')
    shape = ((message[:4] == DATA_HEADER and message[4] == 0 and len(message) == size + 12)
             or (message[:4] == bytes.fromhex('6d10f035') and message[4] == 1 and len(message) == 10))
    if shape and 0 < size <= 4096 and address + size <= 0x80000:
        return address
    return None


def physical_crc(payload, crc_present):
    """Check logged bytes only when the capture declares a trailing VPW CRC."""
    checked = crc_present and len(payload) >= 2
    expected = crc8_j1850(payload[:-1]) if checked else None
    observed = payload[-1] if checked else None
    return {'checked': checked, 'matches': observed == expected if checked else None,
            'observed_crc_hex': f'{observed:02x}' if checked else None,
            'calculated_crc_hex': f'{expected:02x}' if checked else None}


def serial_diagnostics(rows):
    """Summarize optional host observations, never infer absent error telemetry."""
    transports = [r for _, r in rows if r.get('kind') == 'transport']
    requested = transports[0].get('serial_diagnostics_enabled') if len(transports) == 1 else None
    observations = [(line, r) for line, r in rows if r.get('kind') == 'serial_read_diagnostics']
    rx_rows = [(line, r) for line, r in rows if r.get('kind') == 'serial_rx']
    issues, samples, durations, gaps, sequences = [], [], [], [], []
    by_sequence = {}
    previous_end = None
    for line, row in observations:
        sequence = row.get('read_sequence')
        if type(sequence) is not int or sequence != len(sequences) + 1:
            issues.append(f'Non-contiguous diagnostic read sequence at line {line}')
        sequences.append(sequence)
        if type(sequence) is int:
            by_sequence[sequence] = (line, row)
        start, end = row.get('read_start_monotonic_ns'), row.get('read_end_monotonic_ns')
        duration = elapsed(start, end)
        if duration is None or start < 0:
            issues.append(f'Missing or regressed read timing at line {line}')
        else:
            durations.append(duration)
        if previous_end is not None:
            gap = elapsed(previous_end, start)
            if gap is None:
                issues.append(f'Read observations overlap or regress at line {line}')
            else:
                gaps.append(gap)
        previous_end = end
        count = row.get('bytes_returned')
        if type(count) is not int or count < 0 or type(row.get('read_succeeded')) is not bool:
            issues.append(f'Invalid read result at line {line}')
        error = row.get('read_error')
        if row.get('read_succeeded') is True:
            if error is not None:
                issues.append(f'Successful read reports an error at line {line}')
        elif row.get('read_succeeded') is False:
            if count != 0 or not isinstance(error, dict) or not isinstance(error.get('message'), str):
                issues.append(f'Failed read reports bytes or lacks error evidence at line {line}')
        if row.get('polling_clears_error_flags') is not True:
            issues.append(f'Unspecified error-flag polling semantics at line {line}')
        for phase in ('before', 'after'):
            sample = row.get(phase)
            if not isinstance(sample, dict) or sample.get('success') is not True:
                issues.append(f'Unavailable {phase} driver status at line {line}')
                continue
            fields = ('error_mask_raw', 'comstat_flags_raw', 'cb_in_que', 'cb_out_que')
            if any(type(sample.get(k)) is not int or not 0 <= sample[k] <= 0xffffffff for k in fields):
                issues.append(f'Invalid {phase} driver status at line {line}')
                continue
            timestamp = sample.get('host_monotonic_ns')
            if (type(timestamp) is not int or timestamp < 0 or duration is None
                    or (phase == 'before' and timestamp > start)
                    or (phase == 'after' and timestamp < end)):
                issues.append(f'Invalid {phase} snapshot chronology at line {line}')
            samples.append(sample)
    seen_rx = Counter()
    for line, row in rx_rows:
        sequence = row.get('read_sequence')
        if not observations and requested is not True:
            continue  # Legacy logs have no diagnostic coverage, not zero errors.
        if type(sequence) is not int or sequence not in by_sequence:
            issues.append(f'Receive bytes lack a diagnostic read at line {line}')
            continue
        seen_rx[sequence] += 1
        observed_line, observed = by_sequence[sequence]
        try:
            count = len(bytes.fromhex(row['raw_hex']))
        except (KeyError, TypeError, ValueError):
            count = None
        if count != observed.get('bytes_returned') or line >= observed_line:
            issues.append(f'Receive bytes do not correlate with diagnostic read at line {line}')
        timestamp = row.get('host_monotonic_ns')
        after = observed.get('after')
        after_time = after.get('host_monotonic_ns') if isinstance(after, dict) else None
        if (type(timestamp) is not int or type(after_time) is not int or timestamp < after_time):
            issues.append(f'Invalid receive/driver snapshot chronology at line {line}')
        prior = by_sequence.get(sequence - 1)
        if prior is not None and line <= prior[0]:
            issues.append(f'Receive bytes precede the prior diagnostic read at line {line}')
    for sequence, (line, row) in by_sequence.items():
        wanted = 1 if type(row.get('bytes_returned')) is int and row['bytes_returned'] > 0 else 0
        if seen_rx[sequence] != wanted:
            issues.append(f'Diagnostic read byte coverage mismatch at line {line}')
    if requested is True and not observations:
        issues.append('Requested serial diagnostics are missing')
    mask = None
    if samples:
        mask = 0
        for sample in samples:
            mask |= sample['error_mask_raw']
    return {
        'requested': requested, 'available': bool(observations),
        'read_observation_count': len(observations), 'status_snapshot_count': len(samples),
        'coverage_complete_for_logged_reads': bool(observations) and requested is True and not issues,
        'issues': issues, 'observed_error_mask_or': mask,
        'snapshots_reporting_errors': sum(s['error_mask_raw'] != 0 for s in samples) if samples else None,
        'snapshots_reporting_rx_overflow_or_overrun': sum(bool(s['error_mask_raw'] & 3) for s in samples) if samples else None,
        'max_observed_input_queue_bytes': max((s['cb_in_que'] for s in samples), default=None),
        'max_observed_output_queue_bytes': max((s['cb_out_que'] for s in samples), default=None),
        'failed_read_count': sum(r.get('read_succeeded') is False for _, r in observations) if observations else None,
        'read_durations_ns': distribution(durations), 'between_read_calls_ns': distribution(gaps),
        'limits': ['Snapshots are sampled Windows driver state, not a true queue high-water mark or adapter FIFO measurement.',
                   'Polling clears driver error flags; error-bearing snapshots are not counts of lost bytes or frames.',
                   'Zero sampled errors do not prove USB, driver, adapter or bus losslessness.',
                   'Read timings cover the host session, including configuration and cleanup, not physical bus timing.'],
    }


def analyze(path, *, ordinals=(), addresses=(), radius=2):
    if type(radius) is not int or radius < 0:
        raise ValueError('Neighbor radius must be a nonnegative integer')
    if any(type(n) is not int or n < 0 for n in (*ordinals, *addresses)):
        raise ValueError('Ordinals and addresses must be nonnegative integers')
    path = Path(path)
    source = path.read_bytes()
    rows, issues = [], []
    for line, raw in enumerate(source.splitlines(), 1):
        try:
            row = json.loads(raw)
            if not isinstance(row, dict):
                raise ValueError('JSONL record must be an object')
            rows.append((line, row))
        except (ValueError, TypeError) as error:
            issues.append(f'Source JSONL invalid at line {line}: {error}')
            break
    replayed = []
    try:
        replay_jsonl(path, replayed.append)
    except (ValueError, KeyError, TypeError, OSError) as error:
        issues.append('Strict replay failed: ' + str(error))
    summaries = [r for r in replayed if r['kind'] == 'replay_summary']
    summary = summaries[0] if len(summaries) == 1 else None
    if (summary is None or not summary['replay_complete'] or not summary['source_fully_read']
            or not summary['source_result_seen'] or summary['source_reported_failure']
            or summary['adapter_errors'] or summary['outgoing_guard_violations']
            or summary['undecoded_dvi_hex'] or summary['input_sha256'] != sha256(source)):
        issues.append('Source does not have a complete successful guarded replay')
    transports = [r.get('api') for _, r in rows if r.get('kind') == 'transport']
    supported = transports == ['dvi']
    if not supported:
        issues.append('Byte accounting supports explicit DVI logs only; ELM prefixes are not inferred')
    starts = [r for _, r in rows if r.get('kind') == 'capture_started']
    crc_present = len(starts) == 1 and starts[0].get('crc_in_payload') is True
    chunks, parts, offset = [], [], 0
    previous_time = None
    for line, row in rows:
        if row.get('kind') != 'serial_rx':
            continue
        try:
            raw = bytes.fromhex(row['raw_hex'])
        except (ValueError, KeyError, TypeError) as error:
            issues.append(f'Invalid serial bytes at line {line}: {error}')
            break
        timestamp = row.get('host_monotonic_ns')
        gap = elapsed(previous_time, timestamp)
        chunks.append({'serial_chunk_ordinal_zero_based': len(chunks), 'source_line': line,
                       'bytes': len(raw), 'sha256': sha256(raw),
                       'raw_stream_start': offset, 'raw_stream_end_exclusive': offset + len(raw),
                       'host_monotonic_ns': timestamp, 'host_arrival_gap_ns': gap,
                       'host_clock_regressed': (type(previous_time) is int and type(timestamp) is int
                                                and timestamp < previous_time)})
        previous_time = timestamp
        offset += len(raw)
        parts.append(raw)
    stream = b''.join(parts)
    ends = [c['raw_stream_end_exclusive'] for c in chunks]
    cursor, mapped_frames, network = 0, 0, []
    if supported:
        for row in replayed:
            if row['kind'] not in ('adapter', 'network'):
                continue
            raw = bytes.fromhex(row['raw_hex'])
            end = cursor + len(raw)
            if stream[cursor:end] != raw:
                issues.append(f'Replayed DVI frame {mapped_frames} does not match the next logged bytes')
                break
            index, spans = bisect_right(ends, cursor), []
            while index < len(chunks) and chunks[index]['raw_stream_start'] < end:
                chunk = chunks[index]
                start = max(cursor, chunk['raw_stream_start'])
                stop = min(end, chunk['raw_stream_end_exclusive'])
                if stop > start:
                    spans.append({'serial_chunk_ordinal_zero_based': index,
                                  'source_line': chunk['source_line'],
                                  'chunk_offset_start': start - chunk['raw_stream_start'],
                                  'chunk_offset_end_exclusive': stop - chunk['raw_stream_start']})
                index += 1
            if not spans or spans[-1]['source_line'] != row['source_line_end']:
                issues.append(f'Replayed DVI frame {mapped_frames} has inconsistent source-line provenance')
                break
            if row['kind'] == 'network':
                first = chunks[spans[0]['serial_chunk_ordinal_zero_based']]
                last = chunks[spans[-1]['serial_chunk_ordinal_zero_based']]
                payload = bytes.fromhex(row['payload_hex'])
                network.append({
                    'network_ordinal_zero_based': len(network),
                    'dvi_frame_ordinal_zero_based': mapped_frames,
                    'dvi_command': row['command'], 'dvi_frame_bytes': len(raw),
                    'dvi_frame_sha256': sha256(raw),
                    'payload_bytes': len(payload), 'payload_sha256': sha256(payload),
                    'raw_vpw_prefix_hex': payload[:4].hex(),
                    'physical_crc': physical_crc(payload, crc_present),
                    'e54_block_address_candidate': e54_address(payload, crc_present),
                    'raw_stream_start': cursor, 'raw_stream_end_exclusive': end,
                    'serial_chunk_spans': spans,
                    'adapter_timestamp_raw_hex': row['adapter_timestamp_raw_hex'],
                    'first_host_monotonic_ns': first['host_monotonic_ns'],
                    'last_host_monotonic_ns': last['host_monotonic_ns'],
                    'assembly_host_span_ns': elapsed(first['host_monotonic_ns'], last['host_monotonic_ns']),
                })
            cursor, mapped_frames = end, mapped_frames + 1
    byte_accounting = supported and cursor == len(stream) and summary is not None
    if not byte_accounting:
        issues.append('Not every logged receive byte is accounted for by replayed DVI frames')
    if sha256(path.read_bytes()) != sha256(source):
        issues.append('Input changed during analysis')
    selected, selections = set(), []
    for kind, requests in (('network_ordinal', ordinals), ('e54_block_address', addresses)):
        for requested in requests:
            centers = ([requested] if requested < len(network) else []) if kind == 'network_ordinal' else [
                frame['network_ordinal_zero_based'] for frame in network
                if frame['e54_block_address_candidate'] == requested]
            neighbors = sorted({n for center in centers for n in
                                range(max(0, center - radius), min(len(network), center + radius + 1))})
            selected.update(neighbors)
            selections.append({'kind': kind, 'requested': requested, 'matched_ordinals': centers,
                               'neighbor_ordinals': neighbors})
    extended = [frame for frame in network if frame['dvi_command'] == 9]
    gaps = [c['host_arrival_gap_ns'] for c in chunks if c['host_arrival_gap_ns'] is not None]
    return {
        'schema_version': 1, 'scope': 'Offline saved-DVI byte accounting and host delivery only',
        'input': {'path': str(path.resolve()), 'bytes': len(source), 'sha256': sha256(source)},
        'analysis_complete': not issues, 'issues': issues, 'strict_replay': summary,
        'byte_accounting': {'all_logged_rx_bytes_accounted_for': byte_accounting and not issues,
                            'logged_rx_bytes': len(stream), 'mapped_dvi_bytes': cursor,
                            'unaccounted_bytes': len(stream) - cursor,
                            'mapped_dvi_frames': mapped_frames,
                            'mapped_network_frames': len(network), 'logged_rx_sha256': sha256(stream)},
        'serial_diagnostics': serial_diagnostics(rows),
        'physical_crc': {
            'layout_basis': 'Single capture_started.crc_in_payload declaration; not independent bus evidence',
            'trailing_crc_declared': crc_present,
            'checked_frames': sum(f['physical_crc']['checked'] for f in network),
            'matching_frames': sum(f['physical_crc']['matches'] is True for f in network),
            'mismatching_frames': sum(f['physical_crc']['matches'] is False for f in network),
            'unchecked_frames': sum(not f['physical_crc']['checked'] for f in network),
            'mismatching_network_ordinals': [f['network_ordinal_zero_based'] for f in network
                                            if f['physical_crc']['matches'] is False],
            'interpretation': 'CRC mismatch is preserved as received; it does not locate corruption or repair bytes. Complete byte accounting can include CRC-invalid network frames.'},
        'serial_delivery': {'chunk_count': len(chunks),
                            'chunk_bytes': distribution([c['bytes'] for c in chunks]),
                            'chunk_size_histogram': dict(Counter(c['bytes'] for c in chunks)),
                            'host_arrival_gaps_ns': distribution(gaps),
                            'host_clock_regressions': sum(c['host_clock_regressed'] for c in chunks),
                            'missing_or_noninteger_host_timestamps': sum(type(c['host_monotonic_ns']) is not int for c in chunks)},
        'extended_length_frames': {'count': len(extended),
                                  'fragmented_across_chunks': sum(len(f['serial_chunk_spans']) > 1 for f in extended),
                                  'assembly_host_spans_ns': distribution([f['assembly_host_span_ns'] for f in extended
                                                                        if f['assembly_host_span_ns'] is not None])},
        'serial_chunks': chunks, 'network_frame_mappings': network,
        'selection_radius': radius, 'selections': selections,
        'requested_selection_complete': all(s['matched_ordinals'] for s in selections),
        'selected_frame_evidence': [network[n] for n in sorted(selected)],
        'interpretation': 'Complete accounting means strict replay discarded no complete DVI frame after the recorded serial_rx boundary. It cannot establish what arrived at USB, the adapter, or the physical bus before logging.',
        'limits': ['Host chunk timestamps are logging/delivery observations, not bus-frame timestamps.',
                   'Adapter timestamp bytes are preserved without assuming byte order or clock units.',
                   'Assembly span is host arrival time from first to last contributing chunk, not VPW duration.',
                   'Missing physical traffic and its loss location cannot be inferred from this saved stream.',
                   'E54 address selection requires the known envelope and a matching physical CRC; it is a candidate label only.'],
        'live_write_enabled': False, 'complete_bus_capture_proven': False,
        'implementation_sha256': {name: sha256(Path(__file__).with_name(name).read_bytes()) for name in
                                  (Path(__file__).name, 'obdx_capture.py', 'obdx_speed.py', 'compare_vpw_read_capture.py')},
    }


def number(value):
    try:
        result = int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError('Expected a decimal or 0x-prefixed integer') from error
    if result < 0:
        raise argparse.ArgumentTypeError('Value must be nonnegative')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--ordinal', type=number, action='append', default=[], help='Zero-based network ordinal')
    parser.add_argument('--address', type=number, action='append', default=[], help='E54 read-block address candidate')
    parser.add_argument('--radius', type=number, default=2, help='Neighbor frames on each side, clipped to the recorded stream')
    parser.add_argument('--output', type=Path, required=True, help='New JSON receipt, never overwritten')
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error('Output already exists; choose a new receipt path')
    try:
        result = analyze(args.capture, ordinals=args.ordinal, addresses=args.address, radius=args.radius)
        with args.output.open('x', encoding='utf8', newline='\n') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps({'receipt': str(args.output.resolve()), 'analysis_complete': result['analysis_complete'],
                      'byte_accounting': result['byte_accounting'], 'issues': result['issues']}))
    return 0 if result['analysis_complete'] and result['requested_selection_complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
