"""Offline, literal USBPcap bulk-IN versus serial_rx byte comparison.

Reads classic PCAP (LINKTYPE_USBPCAP 249), never opens a device. Inventory mode
requires only --pcap; comparison also requires --serial, --bus, --device and an
explicit IN --endpoint. No stream alignment, trimming, repair or deduplication
is performed. A receipt is created exclusively, never overwritten.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct


USB_HEADER = struct.Struct('<HQIHBHHBBI')
PCAP_MAGICS = {b'\xd4\xc3\xb2\xa1': ('<', 1000000),
               b'\xa1\xb2\xc3\xd4': ('>', 1000000),
               b'\x4d\x3c\xb2\xa1': ('<', 1000000000),
               b'\xa1\xb2\x3c\x4d': ('>', 1000000000)}
DEFAULT_MAX_INPUT_BYTES = 128 * 1024 * 1024
EXAMPLE_LIMIT = 100
CONTEXT_BYTES = 16
FORMAT_SOURCES = [
    'https://desowin.org/usbpcap/captureformat.html',
    'https://github.com/desowin/usbpcap/blob/1.5.4.0/USBPcapDriver/USBPcapURB.c',
    'https://github.com/the-tcpdump-group/libpcap/blob/master/pcap-savefile.manfile.in',
    'https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-usb.c',
    'https://desowin.org/usbpcap/capture_limitations.html',
]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class Findings:
    """Bound examples without concealing the number or kinds of findings."""
    def __init__(self):
        self.counts = Counter()
        self.examples = []

    def add(self, code, **evidence):
        self.counts[code] += 1
        if len(self.examples) < EXAMPLE_LIMIT:
            self.examples.append({'code': code, **evidence})

    def report(self):
        count = sum(self.counts.values())
        return {'count': count, 'counts_by_code': dict(self.counts),
                'examples': self.examples, 'omitted_example_count': count - len(self.examples)}


def read_input(path, max_input_bytes):
    """Cap allocation before reading; hashes describe exactly the analyzed snapshot."""
    if type(max_input_bytes) is not int or max_input_bytes <= 0:
        raise ValueError('max_input_bytes must be a positive integer')
    path = Path(path)
    with path.open('rb') as stream:
        if stream.seek(0, 2) > max_input_bytes:
            raise ValueError(f'{path}: input exceeds the {max_input_bytes}-byte analysis memory limit')
        stream.seek(0)
        raw = stream.read(max_input_bytes + 1)
    if len(raw) > max_input_bytes:
        raise ValueError(f'{path}: input grew beyond the analysis memory limit')
    return raw, {'path': str(path.resolve()), 'bytes': len(raw), 'sha256': sha256(raw)}


def validate_selection(bus, device, endpoint):
    if any(type(n) is not int for n in (bus, device, endpoint)):
        raise ValueError('Comparison requires explicit integer bus, device and IN endpoint')
    if not 0 <= bus <= 0xffff or not 0 <= device <= 0xffff:
        raise ValueError('USBPcap bus and device values must fit their 16-bit fields')
    if not 0x81 <= endpoint <= 0x8f:
        raise ValueError('Select a non-control IN endpoint address from 0x81 through 0x8f')
    return (bus, device, endpoint)


def parse_pcap(raw, selection=None):
    """Parse recorded lengths first; successful selected completion bytes stay literal."""
    issues, pairing, timing = Findings(), Findings(), Findings()
    inventory, counts = {}, Counter()
    pending, completed = {}, set()
    payload = bytearray()
    segments, examples = [], []
    offset, record_number, prior_time = 0, 0, None
    header = None
    fully_read = False
    if raw[:4] == b'\x0a\x0d\x0d\x0a':
        issues.add('unsupported_pcapng', explanation='Use the original classic PCAP produced by USBPcapCMD; PCAPNG is not parsed')
    elif len(raw) < 24:
        issues.add('truncated_pcap_global_header', available_bytes=len(raw))
    elif raw[:4] not in PCAP_MAGICS:
        issues.add('unsupported_pcap_magic', magic_hex=raw[:4].hex())
    else:
        endian, units = PCAP_MAGICS[raw[:4]]
        major, minor, reserved1, reserved2, snaplen, linktype = struct.unpack_from(endian + 'HHIIII', raw, 4)
        header = {'version': [major, minor], 'byte_order': 'little' if endian == '<' else 'big',
                  'timestamp_fraction_units_per_second': units, 'snaplen': snaplen,
                  'linktype_and_information_raw': linktype, 'reserved1_raw': reserved1,
                  'reserved2_raw': reserved2, 'usbpcap_header_byte_order': 'little'}
        if (major, minor) != (2, 4):
            issues.add('unsupported_pcap_version', version=[major, minor])
        if linktype != 249:
            issues.add('unsupported_linktype_or_additional_flags', raw=linktype, required=249)
        if snaplen < USB_HEADER.size:
            issues.add('snaplen_cannot_hold_usbpcap_header', snaplen=snaplen)
        if not issues.counts:
            offset = 24
            while offset < len(raw):
                record_number += 1
                record_offset = offset
                if len(raw) - offset < 16:
                    issues.add('truncated_pcap_record_header', record=record_number, file_offset=offset)
                    break
                seconds, fraction, captured, original = struct.unpack_from(endian + 'IIII', raw, offset)
                offset += 16
                if captured > len(raw) - offset:
                    issues.add('truncated_pcap_record_data', record=record_number, file_offset=offset,
                               declared_captured_bytes=captured, available_bytes=len(raw) - offset)
                    break
                data_offset = offset
                offset += captured
                counts['records'] += 1
                record_bad = False
                if fraction >= units:
                    issues.add('invalid_timestamp_fraction', record=record_number, fraction=fraction)
                timestamp = seconds * units + fraction
                if prior_time is not None and timestamp < prior_time:
                    # USBPcap samples wall time before acquiring its buffer lock.
                    # Preserve record order; clock ordering is not file integrity.
                    timing.add('pcap_timestamp_regressed', record=record_number,
                               previous_timestamp_units=prior_time, timestamp_units=timestamp)
                prior_time = timestamp
                if captured > snaplen or captured > original:
                    record_bad = True
                    issues.add('invalid_pcap_lengths', record=record_number, captured=captured,
                               original=original, snaplen=snaplen)
                if captured < original:
                    record_bad = True
                    issues.add('pcap_snaplen_truncation', record=record_number, captured=captured, original=original)
                if captured < USB_HEADER.size:
                    issues.add('truncated_usbpcap_header', record=record_number, captured=captured)
                    continue
                (header_len, irp, status, function, info, bus, device, endpoint,
                 transfer, declared) = USB_HEADER.unpack_from(raw, data_offset)
                key = (bus, device, endpoint)
                item = inventory.setdefault(key, {'bus': bus, 'device': device, 'endpoint': endpoint,
                    'endpoint_hex': f'0x{endpoint:02x}', 'records': 0, 'submission_records': 0,
                    'completion_records': 0, 'declared_completion_data_bytes': 0,
                    'transfer_types_raw': Counter(), 'functions_raw': Counter()})
                item['records'] += 1
                item['transfer_types_raw'][transfer] += 1
                item['functions_raw'][function] += 1
                is_completion = bool(info & 1)
                item['completion_records' if is_completion else 'submission_records'] += 1
                if is_completion:
                    item['declared_completion_data_bytes'] += declared
                if header_len < USB_HEADER.size or header_len > captured or header_len + declared != captured:
                    record_bad = True
                    issues.add('usbpcap_header_or_data_length_mismatch', record=record_number,
                               header_length=header_len, declared_data_length=declared, captured=captured)
                if selection != key:
                    counts['unselected_records'] += 1
                    continue
                counts['selected_records'] += 1
                evidence = {'record': record_number, 'pcap_record_file_offset': record_offset,
                            'irp_id_hex': f'0x{irp:016x}', 'status_hex': f'0x{status:08x}',
                            'function_raw': function, 'info_raw': info, 'transfer_raw': transfer,
                            'header_length': header_len, 'captured_record_bytes': captured,
                            'declared_data_bytes': declared, 'completion': is_completion,
                            'pcap_timestamp_seconds': seconds, 'pcap_timestamp_fraction': fraction}
                if header_len <= captured and header_len >= USB_HEADER.size:
                    evidence['captured_data_file_offset'] = data_offset + header_len
                    evidence['captured_data_sha256'] = sha256(raw[data_offset + header_len:offset])
                if len(examples) < EXAMPLE_LIMIT:
                    examples.append(evidence)
                if info not in (0, 1) or transfer != 3 or function != 9 or header_len != USB_HEADER.size:
                    record_bad = True
                    issues.add('unsupported_selected_transfer', **evidence)
                if not is_completion:
                    counts['selected_submissions'] += 1
                    if declared:
                        record_bad = True
                        issues.add('unexpected_payload_on_in_submission', **evidence)
                    if irp in pending:
                        pairing.add('duplicate_or_reused_pending_submission', record=record_number,
                                    previous_record=pending[irp], irp_id_hex=evidence['irp_id_hex'])
                    elif irp in completed:
                        counts['selected_irp_reuses_after_completion'] += 1
                    pending[irp] = record_number
                    completed.discard(irp)
                    continue
                counts['selected_completions'] += 1
                submission = pending.pop(irp, None)
                if submission is None:
                    pairing.add('duplicate_completion_without_submission' if irp in completed
                                else 'completion_without_recorded_submission', **evidence)
                else:
                    counts['selected_paired_completions'] += 1
                completed.add(irp)
                if status != 0:
                    counts['selected_failed_completions'] += 1
                    issues.add('selected_non_success_status', **evidence)
                    continue
                if record_bad:
                    counts['selected_invalid_completions'] += 1
                    continue
                counts['selected_successful_completion_records'] += 1
                start = len(payload)
                payload.extend(raw[data_offset + header_len:offset])
                segments.append({'record': record_number, 'pcap_payload_file_offset': data_offset + header_len,
                                 'stream_start': start, 'stream_end_exclusive': len(payload),
                                 'irp_id_hex': evidence['irp_id_hex']})
            else:
                fully_read = True
    for irp, record in pending.items():
        pairing.add('submission_pending_at_capture_end', record=record, irp_id_hex=f'0x{irp:016x}')
    if selection is not None and not counts['selected_successful_completion_records']:
        issues.add('no_selected_successful_completion_records')
    return {'header': header, 'source_fully_read': fully_read, 'parsed_file_bytes': offset,
            'counts': dict(counts), 'issues': issues.report(), 'urb_pairing': pairing.report(),
            'timing_warnings': timing.report(),
            'endpoint_inventory': [inventory[key] for key in sorted(inventory)],
            'selected_record_examples': examples,
            'omitted_selected_record_examples': max(0, counts['selected_records'] - len(examples)),
            'selected_stream_bytes': len(payload), 'selected_stream_sha256': sha256(payload)}, bytes(payload), segments


def parse_serial(raw):
    issues, counts = Findings(), Counter()
    payload, segments, transports, results = bytearray(), [], [], []
    fully_read, last_line = True, None
    for line, raw_line in enumerate(raw.splitlines(), 1):
        if not raw_line.strip():
            continue
        last_line = line
        try:
            row = json.loads(raw_line)
            if not isinstance(row, dict):
                raise ValueError('JSONL record is not an object')
        except (ValueError, UnicodeError, RecursionError) as error:
            issues.add('invalid_jsonl', line=line, reason=str(error))
            fully_read = False
            break
        counts['records'] += 1
        if row.get('kind') == 'transport':
            transports.append(row.get('api'))
        if row.get('kind') == 'result':
            results.append((line, row.get('success')))
        if row.get('kind') != 'serial_rx':
            continue
        counts['serial_rx_rows'] += 1
        try:
            if not isinstance(row.get('raw_hex'), str):
                raise ValueError('raw_hex must be a string')
            data = bytes.fromhex(row['raw_hex'])
        except ValueError as error:
            issues.add('invalid_serial_rx_bytes', line=line, reason=str(error))
            fully_read = False
            break
        start = len(payload)
        payload.extend(data)
        segments.append({'line': line, 'stream_start': start, 'stream_end_exclusive': len(payload),
                         'host_monotonic_ns': row.get('host_monotonic_ns'), 'read_sequence': row.get('read_sequence')})
    if transports != ['dvi']:
        issues.add('serial_transport_not_one_explicit_dvi_session', transports=transports)
    if len(results) != 1 or results[0][0] != last_line or results[0][1] is not True:
        issues.add('serial_result_not_one_final_success', result_records=results, final_line=last_line)
    if not counts['serial_rx_rows']:
        issues.add('no_serial_rx_rows')
    return {'source_fully_read': fully_read, 'counts': dict(counts), 'issues': issues.report(),
            'serial_rx_bytes': len(payload), 'serial_rx_sha256': sha256(payload)}, bytes(payload), segments


def location(segments, offset):
    return next(({**part, 'offset_within_payload': offset - part['stream_start']}
                 for part in segments if part['stream_start'] <= offset < part['stream_end_exclusive']), None)


def compare_bytes(usb, serial, usb_segments=(), serial_segments=()):
    limit = min(len(usb), len(serial))
    first = next((n for n in range(limit) if usb[n] != serial[n]), limit if len(usb) != len(serial) else None)
    context = None
    if first is not None:
        start = max(0, first - CONTEXT_BYTES)
        end = first + CONTEXT_BYTES + 1
        context = {'stream_offset_start': start, 'usb_hex': usb[start:end].hex(),
                   'serial_hex': serial[start:end].hex(), 'radius_bytes': CONTEXT_BYTES,
                   'usb_location': location(usb_segments, first),
                   'serial_location': location(serial_segments, first),
                   'usb_eof_at_difference': first >= len(usb),
                   'serial_eof_at_difference': first >= len(serial)}
    return {'literal_byte_agreement': first is None, 'usb_bytes': len(usb), 'serial_bytes': len(serial),
            'first_differing_stream_offset': first, 'difference_context': context,
            'alignment_or_trimming_performed': False, 'duplicate_completions_removed': False}


def analyze(pcap_path, serial_path=None, *, bus=None, device=None, endpoint=None,
            max_input_bytes=DEFAULT_MAX_INPUT_BYTES):
    comparison_mode = serial_path is not None
    if comparison_mode:
        selection = validate_selection(bus, device, endpoint)
    else:
        if any(n is not None for n in (bus, device, endpoint)):
            raise ValueError('Inventory mode uses no selection; provide --serial to compare')
        selection = None
    pcap_raw, pcap_input = read_input(pcap_path, max_input_bytes)
    pcap, usb, usb_segments = parse_pcap(pcap_raw, selection)
    serial, comparison, serial_input = None, None, None
    if comparison_mode:
        serial_raw, serial_input = read_input(serial_path, max_input_bytes)
        serial, serial_bytes, serial_segments = parse_serial(serial_raw)
        comparison = compare_bytes(usb, serial_bytes, usb_segments, serial_segments)
    complete = pcap['source_fully_read'] and pcap['issues']['count'] == 0
    if serial is not None:
        complete = complete and serial['source_fully_read'] and serial['issues']['count'] == 0
    qualified = (comparison_mode and complete and pcap['urb_pairing']['count'] == 0
                 and comparison['literal_byte_agreement'] and bool(usb))
    return {'schema_version': 1, 'mode': 'compare' if comparison_mode else 'inventory',
            'inputs': {'pcap': pcap_input, 'serial': serial_input},
            'selection': {'bus': bus, 'device': device, 'endpoint': endpoint,
                          'endpoint_hex': f'0x{endpoint:02x}', 'transfer': 'bulk',
                          'direction': 'IN', 'completion_status_required': 0} if comparison_mode else None,
            'resource_limits': {'max_bytes_per_input': max_input_bytes, 'finding_example_limit': EXAMPLE_LIMIT},
            'pcap': pcap, 'serial': serial, 'comparison': comparison,
            'analysis_complete': complete, 'selected_stream_agreement_qualified': qualified,
            'capture_integrity': {'recorded_structure_complete': complete,
                'selected_urb_pairing_complete': pcap['urb_pairing']['count'] == 0 if comparison_mode else None,
                'capture_drop_count': None, 'usb_capture_losslessness_proven': False,
                'physical_vpw_capture_completeness_proven': False},
            'limits': [
                'Equality covers literal recorded selected successful IN completions and every logged serial_rx byte, including setup and cleanup.',
                'Failed, malformed and unsupported selected transfers prevent qualification; their recorded bytes are not silently accepted as successful data.',
                'Submissions contribute no IN data. Duplicate successful completions remain in the stream and create pairing uncertainty. IRP reuse after completion is allowed.',
                'Unmatched URBs can reflect capture boundaries, omissions or duplicates; their cause is unknown.',
                'Classic PCAP has no capture-drop statistics. Complete file structure and URB pairing do not establish lossless capture.',
                'USBPcap observes Windows URBs, not USB wire transactions or the VPW waveform. Results cannot locate an upstream corruption source or prove noninterference.',
                'Selection is caller supplied and does not itself establish USB device identity. Device-address reuse and matching capture windows require independent evidence.',
                'Receipt examples are bounded; counts include all parsed observations. Source hashes preserve the complete inputs.',
            ], 'format_sources': FORMAT_SOURCES,
            'implementation_sha256': sha256(Path(__file__).read_bytes()),
            'hardware_access_performed': False, 'live_write_enabled': False}


def number(value):
    try:
        return int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError('Expected a decimal or 0x-prefixed integer') from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap', type=Path, required=True)
    parser.add_argument('--serial', type=Path, help='Existing DVI JSONL capture; omit for endpoint inventory')
    parser.add_argument('--bus', type=number)
    parser.add_argument('--device', type=number)
    parser.add_argument('--endpoint', type=number, help='Explicit bulk IN address, e.g. 0x81; never guessed')
    parser.add_argument('--max-input-bytes', type=number, default=DEFAULT_MAX_INPUT_BYTES,
                        help='Per-file memory budget; default 128 MiB, checked before loading')
    parser.add_argument('--output', type=Path, required=True, help='New JSON receipt, never overwritten')
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error('Output already exists; choose a new receipt path')
    try:
        result = analyze(args.pcap, args.serial, bus=args.bus, device=args.device, endpoint=args.endpoint,
                         max_input_bytes=args.max_input_bytes)
        with args.output.open('x', encoding='utf8', newline='\n') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps({'receipt': str(args.output.resolve()), 'mode': result['mode'],
                      'analysis_complete': result['analysis_complete'],
                      'selected_stream_agreement_qualified': result['selected_stream_agreement_qualified'],
                      'comparison': result['comparison'],
                      'endpoint_inventory': result['pcap']['endpoint_inventory']}))
    return 0 if (result['selected_stream_agreement_qualified'] if args.serial else result['analysis_complete']) else 1


if __name__ == '__main__':
    raise SystemExit(main())
