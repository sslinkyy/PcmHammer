"""Offline PcmHammer debug RX versus selected GT USB bulk-IN comparison.

Caller supplies explicit DVI byte windows after inspecting the ELM/bootstrap
boundaries. Skipped bytes remain evidence, not an inferred DVI stream. This tool
does not open an adapter. TX classifications are log observations, not USB OUT
verification. Even exact RX agreement does not establish lossless VPW reception.
"""
import argparse
from bisect import bisect_right
from collections import Counter
import hashlib
import io
import json
from pathlib import Path
import re

import compare_usb_serial_capture as usb
from obdx_capture import Decoder, ProtocolError


MAX_FRAMES = 100000  # Bound Python frame/list expansion independently of input bytes.
EXAMPLES = 1000
ROW = re.compile(r'^(?:\[[^\]\r\n]+\]\s*)?(TX|Received):\s*(.*)$')
HEX = re.compile(r'(?:[0-9a-fA-F]{2})(?:\s+[0-9a-fA-F]{2})*')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def describe(data):
    return {'bytes': len(data), 'sha256': digest(data),
            'prefix_hex': data[:32].hex(),
            'literal_hex_if_short': data.hex() if len(data) <= 32 else None}


def classify(data, direction):
    """Project protocol fields without inferring successful flash or transmitter."""
    result = {'kind': 'other'}
    if len(data) < 4:
        return {'kind': 'shorter_than_three_byte_header_and_mode'}
    result.update(header_hex=data[:3].hex(), mode_hex=f'{data[3]:02x}')
    if direction == 'tx' and data[3] == 0x36:
        if len(data) < 12:
            return {**result, 'kind': 'truncated_block_request'}
        size = int.from_bytes(data[5:7], 'big')
        kind = {0: 'copy_ram_or_flash_request', 0x44: 'test_write_request',
                0x80: 'copy_and_execute_request'}.get(data[4], 'unknown_block_submode')
        result.update(kind=kind, submode_hex=f'{data[4]:02x}',
                      address_hex=f'{int.from_bytes(data[7:10], "big"):06x}',
                      declared_data_bytes=size, block_length_matches=len(data) == size + 12)
    elif direction == 'tx' and data[3:5] == b'\x3d\x05':
        result.update(kind='erase_request' if len(data) == 8 else 'malformed_erase_request',
                      address_hex=data[5:8].hex() if len(data) >= 8 else None)
    elif direction == 'rx' and data[3] == 0x76:
        result['kind'] = 'upload_ack_shaped'
    elif direction == 'rx' and data[3:5] == b'\x7d\x05':
        result['kind'] = 'erase_reply_shaped'
    elif direction == 'rx' and data[3] == 0x7f:
        result['kind'] = 'negative_response_shaped'
    return result


def parse_log(raw, encoding='utf-8-sig'):
    rows, tx, rx, issues, retry_lines = [], [], [], [], []
    issue_counts = Counter()
    retry_count = 0
    def issue(reason, **evidence):
        issue_counts[reason] += 1
        if len(issues) < EXAMPLES:
            issues.append({'reason': reason, **evidence})
    text = raw.decode(encoding, errors='strict')
    for line_number, line in enumerate(io.StringIO(text, newline=None), 1):
        line = line.rstrip('\r\n')
        if line_number > MAX_FRAMES:
            issue('log_line_resource_limit', line=line_number, limit=MAX_FRAMES)
            break
        match = ROW.fullmatch(line.strip())
        if match:
            if not HEX.fullmatch(match[2]):
                issue('malformed_hex_message', line=line_number,
                      text_prefix=line[:256], text_characters=len(line))
                continue
            data = bytes.fromhex(match[2])
            direction = 'tx' if match[1] == 'TX' else 'rx'
            if len(rows) == MAX_FRAMES:
                issue('message_resource_limit', line=line_number, limit=MAX_FRAMES)
                break
            (tx if direction == 'tx' else rx).append(data)
            rows.append({'line': line_number, 'direction': direction,
                         'message': describe(data), 'protocol': classify(data, direction)})
        elif re.search(r'\bretr(?:y|ies|ied)\b', line, flags=re.I):
            retry_count += 1
            if len(retry_lines) < EXAMPLES:
                retry_lines.append({'line': line_number, 'text_prefix': line[:256], 'text_characters': len(line)})
    return {'tx_count': len(tx), 'rx_count': len(rx), 'issues': issues,
            'issue_counts': dict(issue_counts),
            'omitted_issue_examples': sum(issue_counts.values()) - len(issues),
            'protocol_counts': dict(Counter(r['direction'] + ':' + r['protocol']['kind'] for r in rows)),
            'message_examples': rows[:EXAMPLES], 'omitted_message_examples': max(0, len(rows) - EXAMPLES),
            'retry_text_observations': retry_lines,
            'omitted_retry_text_observations': retry_count - len(retry_lines),
            'retry_limit': 'Text observations are not an independently reconstructed retry count'}, tx, rx


def spans(start, end, segments, segment_ends):
    found = []
    index = bisect_right(segment_ends, start)
    while index < len(segments) and segments[index]['stream_start'] < end:
        seg = segments[index]
        left, right = max(start, seg['stream_start']), min(end, seg['stream_end_exclusive'])
        if left < right:
            found.append({'record': seg['record'], 'stream_start': left,
                          'stream_end_exclusive': right,
                          'pcap_file_offset': seg['pcap_payload_file_offset'] + left - seg['stream_start']})
        index += 1
    return found


def parse_windows(stream, windows, segments, timestamps):
    segment_ends = [segment['stream_end_exclusive'] for segment in segments]
    previous = 0
    normalized = []
    for start, end in windows:
        end = len(stream) if end is None else end
        if type(start) is not int or type(end) is not int or not previous <= start < end <= len(stream):
            raise ValueError('DVI windows must be nonempty, ordered, nonoverlapping and inside the selected stream')
        normalized.append((start, end))
        previous = end
    if not normalized:
        raise ValueError('At least one explicit DVI stream window is required')
    frames, network, skipped, issues = [], [], [], []
    previous = 0
    for window_index, (start, end) in enumerate(normalized):
        if start > previous:
            skipped.append({'start': previous, 'end_exclusive': start, 'data': describe(stream[previous:start])})
        decoder = Decoder(timestamps=timestamps, track_timestamp_status=True)
        offset = start
        try:
            for row in decoder.iter_feed(stream[start:end]):
                if len(frames) == MAX_FRAMES:
                    raise ProtocolError(f'DVI frame resource limit {MAX_FRAMES} reached')
                raw = bytes.fromhex(row['raw_hex'])
                data = bytes.fromhex(row['payload_hex'])
                record = {'window': window_index, 'stream_start': offset,
                          'stream_end_exclusive': offset + len(raw), 'command_hex': f'{row["command"]:02x}',
                          'frame': describe(raw), 'payload': describe(data),
                          'pcap_spans': spans(offset, offset + len(raw), segments, segment_ends),
                          'adapter_timestamp_raw_hex': row['adapter_timestamp_raw_hex']}
                if row['kind'] == 'network':
                    network.append(data)
                    record.update(network_ordinal=len(network) - 1, protocol=classify(data, 'rx'))
                frames.append(record)
                offset += len(raw)
            decoder.finish()
        except ProtocolError as error:
            issues.append({'window': window_index, 'error': str(error),
                           'unparsed_start': offset, 'unparsed_end_exclusive': end,
                           'unparsed': describe(stream[offset:end])})
        previous = end
    if previous < len(stream):
        skipped.append({'start': previous, 'end_exclusive': len(stream), 'data': describe(stream[previous:])})
    short_network = [r for r in frames if 'network_ordinal' in r and r['payload']['bytes'] <= 12]
    adapter_errors = [r for r in frames if r['command_hex'] == '7f']
    return {'windows': [{'start': a, 'end_exclusive': b} for a, b in normalized],
            'initial_timestamps_per_window': timestamps, 'skipped_stream_spans': skipped,
            'issues': issues, 'decoded_frame_count': len(frames), 'network_count': len(network),
            'command_counts': dict(Counter(r['command_hex'] for r in frames)),
            'adapter_error_examples': adapter_errors[:EXAMPLES],
            'omitted_adapter_error_examples': max(0, len(adapter_errors) - EXAMPLES),
            'frame_examples': frames[:EXAMPLES], 'omitted_frame_examples': max(0, len(frames) - EXAMPLES),
            'short_network_examples': short_network[:EXAMPLES],
            'short_network_count': len(short_network),
            'omitted_short_network_examples': max(0, len(short_network) - EXAMPLES)}, network


def compare_messages(log_rx, usb_rx):
    log_counts, usb_counts = Counter(log_rx), Counter(usb_rx)
    missing, extra = log_counts - usb_counts, usb_counts - log_counts
    def examples(counter):
        return [{'message': describe(k), 'count': v} for k, v in list(counter.items())[:EXAMPLES]]
    mismatch = next((i for i, pair in enumerate(zip(log_rx, usb_rx)) if pair[0] != pair[1]), None)
    if mismatch is None and len(log_rx) != len(usb_rx):
        mismatch = min(len(log_rx), len(usb_rx))
    return {'literal_ordered_rx_agreement': log_rx == usb_rx, 'first_mismatch_ordinal': mismatch,
            'log_rx_count': len(log_rx), 'usb_network_count': len(usb_rx),
            'missing_usb_occurrences': sum(missing.values()), 'extra_usb_occurrences': sum(extra.values()),
            'missing_usb_examples': examples(missing), 'extra_usb_examples': examples(extra),
            'omitted_missing_examples': max(0, len(missing) - EXAMPLES),
            'omitted_extra_examples': max(0, len(extra) - EXAMPLES),
            'comparison_rule': 'Exact bytes and order; counts additionally retain duplicate occurrences; no repair or alignment'}


def analyze(pcap_path, log_path, *, bus, device, endpoint, windows, timestamps=False,
            log_encoding='utf-8-sig', max_input_bytes=usb.DEFAULT_MAX_INPUT_BYTES):
    selection = usb.validate_selection(bus, device, endpoint)
    pcap_raw, pcap_source = usb.read_input(pcap_path, max_input_bytes)
    log_raw, log_source = usb.read_input(log_path, max_input_bytes)
    pcap_report, stream, segments = usb.parse_pcap(pcap_raw, selection)
    dvi_report, network = parse_windows(stream, windows, segments, timestamps)
    log_report, tx, rx = parse_log(log_raw, log_encoding)
    comparison = compare_messages(rx, network)
    complete = (pcap_report['source_fully_read'] and not pcap_report['issues']['count']
                and not pcap_report['urb_pairing']['count'] and not dvi_report['issues']
                and not log_report['issues'])
    repo = Path(__file__).resolve().parents[2]
    protocol_sources = [repo / relative for relative in (
        'Apps/PcmLibrary/Messages/Protocol.ReadWrite.cs',
        'Apps/PcmLibrary/Messages/Protocol.Kernel.cs',
        'Apps/PcmLibrary/Devices/Device.cs', 'Apps/PcmLibrary/Devices/OBDXProDevice.cs')]
    return {'schema': 'pcmhammer-usb-rx-comparison-v1', 'hardware_access_performed': False,
            'inputs': {'pcap': pcap_source, 'debug_log': log_source},
            'parameters': {'log_encoding': log_encoding, 'max_input_bytes': max_input_bytes,
                           'frame_and_log_line_resource_limit': MAX_FRAMES},
            'selection': {'bus': bus, 'device': device, 'endpoint': endpoint},
            'source_provenance': {str(Path(f).resolve()): digest(Path(f).read_bytes())
                                  for f in (__file__, usb.__file__, __import__('obdx_capture').__file__)},
            'protocol_source_provenance': [{'path': str(path), 'exists': path.is_file(),
                'sha256': digest(path.read_bytes()) if path.is_file() else None} for path in protocol_sources],
            'pcap': pcap_report, 'dvi': dvi_report, 'log': log_report, 'comparison': comparison,
            'selected_window_analysis_complete': complete,
            'selected_window_rx_agreement_qualified': bool(complete and rx and comparison['literal_ordered_rx_agreement']),
            'usb_tx_verified': False, 'vpw_losslessness_proven': False, 'physical_flash_success_proven': False,
            'limits': ['USB IN records bytes forwarded by GT, not an independent VPW wire capture.',
                       'Caller-selected DVI windows exclude explicitly reported bootstrap or other spans.',
                       'TX classifications describe debug log contents; USB OUT is not examined.',
                       'Copy submode 00 can target RAM or flash; it alone does not prove flash programming.',
                       'No erased-memory, readback, electrical interference or recovery qualification follows.']}


def window_arg(value):
    try:
        start, end = value.split(':', 1)
        return int(start, 0), int(end, 0) if end else None
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError('Use START:END byte offsets, or START: for stream end')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap', type=Path, required=True)
    parser.add_argument('--log', type=Path, required=True)
    parser.add_argument('--bus', type=lambda x: int(x, 0), required=True)
    parser.add_argument('--device', type=lambda x: int(x, 0), required=True)
    parser.add_argument('--endpoint', type=lambda x: int(x, 0), required=True)
    parser.add_argument('--window', action='append', type=window_arg, required=True)
    parser.add_argument('--timestamps', choices=['on', 'off'], required=True)
    parser.add_argument('--log-encoding', choices=['utf-8-sig', 'utf-16'], default='utf-8-sig')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    result = analyze(args.pcap, args.log, bus=args.bus, device=args.device, endpoint=args.endpoint,
                     windows=args.window, timestamps=args.timestamps == 'on', log_encoding=args.log_encoding)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({key: result[key] for key in ('selected_window_analysis_complete',
                      'selected_window_rx_agreement_qualified', 'comparison')}, indent=2))
    return 0 if result['selected_window_rx_agreement_qualified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
