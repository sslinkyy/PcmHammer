"""Offline FTDI packetization hypothesis and AutoCal host-envelope analysis.

Reads classic USBPcap only. An explicit max-packet size is a caller hypothesis,
not descriptor evidence. Status bytes are retained per derived USB packet, never
removed once per URB. No adapter, serial port, target DLL, or network is opened.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import struct

import compare_usb_serial_capture as usb
from audit_trace_wrappers import framed_message
from checksum import crc16


SOURCES = [
    {'url': 'https://ftdichip.com/Support/Knowledgebase/an232b_04smalldataend.htm',
     'supports': 'Each FTDI input USB packet starts with two driver status bytes; a timer may produce status-only packets.'},
    {'url': 'https://ftdichip.com/Support/Knowledgebase/an232beffectbuffsizeandlatency.htm',
     'supports': 'A host request may aggregate full USB packets until requested length, a short packet, or cancellation.'},
    {'url': 'https://ftdichip.com/wp-content/uploads/2020/08/TN_103_FTDI_USB_Data_Transfer_EfficiencyFT_000097.pdf',
     'supports': '64-byte packets contain two status bytes and 62 data bytes; FT245 returns status bytes without UART meaning.'},
]


def descriptor_evidence_from_report(raw, instance_id, device_address, in_endpoint, out_endpoint, max_packet_size):
    """Bind a supplied USBTreeView text snapshot to exact identity and descriptor bytes."""
    identity = instance_id.encode('ascii')
    if raw.startswith(b'\xff\xfe'):
        source_encoding, bom_bytes = 'utf-16le', 2
    elif raw.startswith(b'\xfe\xff'):
        source_encoding, bom_bytes = 'utf-16be', 2
    else:
        source_encoding, bom_bytes = 'utf-8', 3 if raw.startswith(b'\xef\xbb\xbf') else 0
    text_lines = raw[bom_bytes:].decode(source_encoding).splitlines(keepends=True)
    lines = [line.encode('utf8') for line in text_lines]
    offsets, source_line_lengths, cursor = [], [], bom_bytes
    for line in text_lines:
        length = len(line.encode(source_encoding))
        offsets.append(cursor); source_line_lengths.append(length); cursor += length
    if cursor != len(raw):
        raise ValueError('Descriptor text decoding did not retain complete byte coverage')
    ids = [i for i, line in enumerate(lines) if re.fullmatch(rb'Device ID\s*:\s*' + re.escape(identity) + rb'\s*', line, re.I)]
    if len(ids) != 1:
        raise ValueError('Descriptor report does not contain one exact requested device identity')
    center = ids[0]
    boundaries = [i for i, line in enumerate(lines) if re.match(rb'\s*=+\s+USB (?:Device|Port)', line)]
    start = max((i for i in boundaries if i < center), default=0)
    end = min((i for i in boundaries if i > center), default=len(lines))
    section = b''.join(lines[start:end])
    addresses = re.findall(rb'^Device Address\s*:\s*0x([0-9a-f]+)\s*\(', section, re.I | re.M)
    if len(addresses) != 1 or int(addresses[0], 16) != device_address:
        raise ValueError('Descriptor report USB device address differs from capture selection')
    speeds = re.findall(rb'^Device Bus Speed\s*:\s*(.+)', section, re.M)
    if len(speeds) != 1:
        raise ValueError('Descriptor report lacks a unique device bus speed')

    def dump_after(title):
        headings = [i for i in range(start, end) if title in lines[i] and b'---' in lines[i]]
        if len(headings) != 1:
            raise ValueError('Descriptor heading absent or ambiguous: ' + title.decode())
        first = next((i for i in range(headings[0] + 1, end) if lines[i].startswith(b'Data (HexDump)')), None)
        if first is None:
            raise ValueError('Descriptor raw hex dump absent')
        pieces, evidence_lines = [], []
        for i in range(first, end):
            value = lines[i].split(b':', 1)[1] if i == first else lines[i]
            value = re.split(rb' {2,}', value.strip(), maxsplit=1)[0]
            if not re.fullmatch(rb'[0-9A-Fa-f]{2}(?: [0-9A-Fa-f]{2})*', value):
                break
            pieces.append(bytes.fromhex(value.decode('ascii')))
            evidence_lines.append({'line_one_based': i + 1, 'file_offset': offsets[i], 'bytes': source_line_lengths[i]})
        if not pieces:
            raise ValueError('No descriptor bytes extracted')
        return b''.join(pieces), evidence_lines

    device_raw, device_lines = dump_after(b'Device Descriptor')
    if len(device_raw) != 18 or device_raw[:2] != b'\x12\x01':
        raise ValueError('Unsupported device descriptor shape')
    identity_parts = re.fullmatch(r'USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})\\(.+)', instance_id, re.I)
    if identity_parts is None or struct.unpack_from('<HH', device_raw, 8) != (int(identity_parts[1], 16), int(identity_parts[2], 16)):
        raise ValueError('Device descriptor VID/PID does not match exact device identity')
    config_raw, config_lines = dump_after(b'Configuration Descriptor')
    if len(config_raw) < 9 or config_raw[:2] != b'\x09\x02' or int.from_bytes(config_raw[2:4], 'little') != len(config_raw):
        raise ValueError('Configuration descriptor total length is incomplete')
    cursor, endpoints = 0, []
    while cursor < len(config_raw):
        length = config_raw[cursor]
        if length < 2 or cursor + length > len(config_raw):
            raise ValueError('Malformed descriptor chain')
        item = config_raw[cursor:cursor + length]
        if item[1] == 5:
            if length != 7:
                raise ValueError('Unsupported endpoint descriptor length')
            endpoints.append({'configuration_byte_offset': cursor, 'endpoint': item[2],
                              'attributes': item[3], 'max_packet_size': int.from_bytes(item[4:6], 'little'),
                              'descriptor_hex': item.hex()})
        cursor += length
    for endpoint in (in_endpoint, out_endpoint):
        selected = [item for item in endpoints if item['endpoint'] == endpoint]
        if len(selected) != 1 or selected[0]['attributes'] & 3 != 2 or selected[0]['max_packet_size'] != max_packet_size:
            raise ValueError('Selected bulk endpoint/max-packet size disagrees with descriptor')
    return {'source_sha256': usb.sha256(raw), 'source_text_encoding': source_encoding,
            'instance_id': instance_id, 'device_address': device_address,
            'section_start_file_offset': offsets[start], 'section_end_file_offset_exclusive': offsets[end] if end < len(offsets) else len(raw),
            'section_line_start_one_based': start + 1, 'section_line_end_inclusive': end,
            'device_bus_speed_display': speeds[0].strip().decode('ascii'),
            'device_descriptor_hex': device_raw.hex(), 'device_descriptor_source_lines': device_lines,
            'configuration_descriptor_hex': config_raw.hex(), 'configuration_descriptor_source_lines': config_lines,
            'endpoints': endpoints, 'capture_same_attachment_assertion': 'Caller correlates this separate snapshot to the capture; no hotplug history is inferred'}


def record_views(raw):
    """Preserve records after the established producer has validated file structure."""
    endian, units = usb.PCAP_MAGICS[raw[:4]]
    offset, ordinal = 24, 0
    while offset < len(raw):
        sec, frac, captured, original = struct.unpack_from(endian + 'IIII', raw, offset)
        record_offset = offset
        offset += 16
        header, irp, status, function, info, bus, device, endpoint, transfer, declared = usb.USB_HEADER.unpack_from(raw, offset)
        payload_offset = offset + header
        ordinal += 1
        yield {'record': ordinal, 'record_file_offset': record_offset, 'irp': irp,
               'status': status, 'function': function, 'info': info, 'completion': bool(info & 1),
               'bus': bus, 'device': device, 'endpoint': endpoint, 'transfer': transfer,
               'header_bytes': header, 'declared_bytes': declared,
               'timestamp_seconds': sec, 'timestamp_fraction': frac,
               'timestamp_units_per_second': units, 'payload_file_offset': payload_offset,
               'data': raw[payload_offset:offset + captured]}
        offset += captured


def location(record):
    return {key: record[key] for key in ('record', 'record_file_offset', 'payload_file_offset',
        'timestamp_seconds', 'timestamp_fraction', 'timestamp_units_per_second', 'endpoint',
        'function', 'transfer', 'completion', 'status', 'declared_bytes')}


def packetize(data, max_packet_size):
    """Return literal spans under an explicit packet-size hypothesis, retaining status."""
    if type(max_packet_size) is not int or max_packet_size not in (64, 512):
        raise ValueError('FTDI max-packet hypothesis must be explicitly 64 or 512')
    result = []
    for start in range(0, len(data), max_packet_size):
        packet = data[start:start + max_packet_size]
        if len(packet) < 2:
            raise ValueError('Derived packet is too short to contain both status bytes')
        result.append({'offset': start, 'bytes': len(packet), 'status_hex': packet[:2].hex(),
                       'application_offset': start + 2, 'application_bytes': packet[2:]})
    return result


def mapped_spans(parts, start, end):
    spans = []
    for part in parts:
        low, high = max(start, part['stream_start']), min(end, part['stream_end_exclusive'])
        if high > low:
            spans.append({'record': part['record'], 'stream_start': low, 'stream_end_exclusive': high,
                          'pcap_file_offset': part['pcap_file_offset'] + low - part['stream_start'],
                          'bytes': high - low})
    if sum(item['bytes'] for item in spans) != end - start:
        raise ValueError('Application-stream provenance has a gap')
    return spans


def envelopes(stream, parts, channel):
    """Decode the already-established 12-byte wrapper shape without resynchronizing."""
    cursor, found, private = 0, [], []
    prefix = b'\x01T' if channel == 1 else b'\x01R'
    trailer_size = 2 if channel == 1 else 3
    reason = None
    while cursor < len(stream):
        if len(stream) - cursor < 12 or stream[cursor:cursor + 2] != prefix:
            reason = 'Unsupported prefix or incomplete 12-byte header; no scan/resynchronization'
            break
        length = int.from_bytes(stream[cursor + 10:cursor + 12], 'little')
        end = cursor + 12 + length + trailer_size
        if end > len(stream):
            reason = 'Declared envelope extends past retained stream; no repair'
            break
        wrapper = stream[cursor:end]
        framed = framed_message({'kind': 0x42, 'channel': channel, 'payload': wrapper})
        if framed is None:
            reason = 'Existing wrapper producer rejected the shape'
            break
        payload_end = 12 + length
        stored = int.from_bytes(wrapper[payload_end:payload_end + 2], 'little')
        calculated = crc16(wrapper[:payload_end], 0)
        item = {'ordinal': len(found), 'stream_start': cursor, 'stream_end_exclusive': end,
                'bytes': len(wrapper), 'sha256': usb.sha256(wrapper), 'prefix_12_hex': wrapper[:12].hex(),
                'route_bytes_hex': wrapper[2:4].hex(), 'opaque_metadata_4_to_9_hex': wrapper[4:10].hex(),
                'payload_bytes': length, 'payload_sha256': usb.sha256(wrapper[12:payload_end]),
                'crc16': {'stored': stored, 'calculated': calculated, 'matches': stored == calculated,
                          'algorithm': 'reflected A001, seed0000, no final XOR, stored LE16'},
                'rx_trailing_byte_hex': wrapper[-1:].hex() if channel == 2 else None,
                'pcap_spans': mapped_spans(parts, cursor, end),
                'route_semantics_verified': False, 'request_response_pairing': None}
        found.append(item)
        private.append({'ordinal': item['ordinal'], 'wrapper_hex': wrapper.hex()})
        cursor = end
    remainder = stream[cursor:]
    return {'stream_bytes': len(stream), 'stream_sha256': usb.sha256(stream),
            'envelopes': found, 'envelope_count': len(found),
            'crc_failed_ordinals': [item['ordinal'] for item in found if not item['crc16']['matches']],
            'unparsed': {'stream_start': cursor, 'bytes': len(remainder), 'sha256': usb.sha256(remainder),
                         'reason': reason, 'pcap_spans': mapped_spans(parts, cursor, len(stream))},
            'all_retained_bytes_frame_and_crc_match': bool(found) and not remainder and all(item['crc16']['matches'] for item in found)}, private


def analyze(raw, *, bus, device, in_endpoint, out_endpoint, max_packet_size, descriptor_evidence=None):
    usb.validate_selection(bus, device, in_endpoint)
    if type(out_endpoint) is not int or not 1 <= out_endpoint <= 15:
        raise ValueError('Explicit non-control OUT endpoint required')
    packetize(b'', max_packet_size)
    producer, raw_in, _ = usb.parse_pcap(raw, (bus, device, in_endpoint))
    structural = {code: count for code, count in producer['issues']['counts_by_code'].items()
                  if code not in ('unsupported_selected_transfer', 'selected_non_success_status')}
    if not producer['source_fully_read'] or structural:
        raise ValueError('Established USBPcap producer found structural/integrity issues: ' + json.dumps(structural))
    rx, tx = bytearray(), bytearray()
    rx_parts, tx_parts, packet_ledger, data_transfers = [], [], [], []
    status_hist, input_lengths = Counter(), Counter()
    pending_out, completed_out, out_issues, control_records, other_records = {}, [], [], [], []
    in_completion_count, status_only_count, raw_in_bytes = 0, 0, 0
    issues = []
    for record in record_views(raw):
        if (record['bus'], record['device']) != (bus, device):
            continue
        endpoint = record['endpoint']
        if record['transfer'] == 2:
            entry = location(record)
            entry.update(data_bytes=len(record['data']), data_sha256=usb.sha256(record['data']))
            if not record['completion'] and record['header_bytes'] == 28 and len(record['data']) == 8:
                entry['setup_hex'] = record['data'].hex()
            control_records.append(entry)
            continue
        if record['transfer'] != 3 or record['function'] != 9 or record['header_bytes'] != 27 or record['info'] not in (0, 1):
            entry = location(record)
            entry.update(data_sha256=usb.sha256(record['data']))
            other_records.append(entry)
            continue
        if endpoint == in_endpoint and record['completion'] and record['status'] == 0:
            data = record['data']
            in_completion_count += 1
            raw_in_bytes += len(data)
            input_lengths[len(data)] += 1
            initial = len(rx)
            try:
                packets = packetize(data, max_packet_size)
            except ValueError as error:
                issues.append({'record': record['record'], 'reason': str(error), 'data_sha256': usb.sha256(data)})
                continue
            for index, packet in enumerate(packets):
                start = len(rx)
                rx.extend(packet['application_bytes'])
                status_hist[packet['status_hex']] += 1
                status_only_count += not packet['application_bytes']
                packet_ledger.append([record['record'], index, record['payload_file_offset'] + packet['offset'],
                                      packet['bytes'], packet['status_hex'], start, len(rx) - start])
                if packet['application_bytes']:
                    rx_parts.append({'record': record['record'], 'stream_start': start, 'stream_end_exclusive': len(rx),
                                     'pcap_file_offset': record['payload_file_offset'] + packet['application_offset']})
            if len(rx) != initial:
                data_transfers.append({**location(record), 'raw_sha256': usb.sha256(data), 'derived_packet_count': len(packets),
                                       'application_stream_start': initial, 'application_stream_end_exclusive': len(rx)})
        elif endpoint == out_endpoint:
            if not record['completion']:
                if record['irp'] in pending_out:
                    out_issues.append({'kind': 'reused_pending_submission', 'record': record['record']})
                pending_out[record['irp']] = record
            else:
                submitted = pending_out.pop(record['irp'], None)
                if submitted is None or record['status'] != 0 or record['data']:
                    out_issues.append({'kind': 'unmatched_failed_or_data_bearing_completion', **location(record)})
                elif submitted is not None:
                    completed_out.append((submitted, record))
    for record in pending_out.values():
        out_issues.append({'kind': 'submission_pending_at_capture_end', **location(record)})
    for submitted, completion in sorted(completed_out, key=lambda item: item[0]['record']):
        start = len(tx)
        tx.extend(submitted['data'])
        tx_parts.append({'record': submitted['record'], 'stream_start': start, 'stream_end_exclusive': len(tx),
                         'pcap_file_offset': submitted['payload_file_offset'], 'completion_record': completion['record']})
    if raw_in_bytes != len(raw_in):
        raise ValueError('New packet analysis disagrees with established successful-IN byte accounting')
    rx_result, private_rx = envelopes(bytes(rx), rx_parts, 2)
    tx_result, private_tx = envelopes(bytes(tx), tx_parts, 1)
    result = {'schema': 'offline-autocal-ftdi-usb-v1',
        'selection': {'bus': bus, 'device': device, 'in_endpoint': in_endpoint, 'out_endpoint': out_endpoint},
        'packetization': {'max_packet_size_argument': max_packet_size,
                         'basis': 'identity-bound descriptor snapshot' if descriptor_evidence else 'caller-supplied hypothesis',
                         'descriptor_verified': descriptor_evidence is not None, 'descriptor_evidence': descriptor_evidence,
                         'status_bytes_per_packet': 2,
                         'warning': 'USBPcap records URBs, not physical USB packets. Packet boundaries are derived from the declared/verified maximum packet size.'},
        'usb_producer': producer, 'input_successful_bulk_completions': in_completion_count,
        'input_length_histogram': dict(sorted(input_lengths.items())), 'raw_successful_input_bytes': raw_in_bytes,
        'raw_successful_input_sha256': usb.sha256(raw_in), 'derived_status_only_packet_count': status_only_count,
        'status_pair_histogram': dict(sorted(status_hist.items())), 'packetization_issues': issues,
        'packet_ledger_columns': ['pcap_record_one_based', 'packet_index_zero_based', 'pcap_packet_file_offset',
                                  'packet_bytes', 'status_hex', 'application_stream_start', 'application_bytes'],
        'packet_ledger': packet_ledger, 'data_bearing_input_transfers': data_transfers,
        'output_successfully_completed_submissions': len(completed_out), 'output_pairing_issues': out_issues,
        'output_submission_status_interpretation': 'Not interpreted as completion status; raw USB submission fields may be unset.',
        'control_records': control_records, 'unsupported_or_other_records': other_records,
        'rx': rx_result, 'tx': tx_result,
        'framing_agreement_under_packet_hypothesis': not issues and rx_result['all_retained_bytes_frame_and_crc_match'] and tx_result['all_retained_bytes_frame_and_crc_match'],
        'sources': SOURCES,
        'limits': ['Matching outer CRCs corroborate this packetization/framing hypothesis for retained bytes; they are not descriptor evidence.',
                   'All status-byte pairs and derived packet/file boundaries are retained; their UART meaning is not assumed for a FIFO device.',
                   'Unknown/control transfers, pending URBs and raw parser findings remain visible.',
                   'No unknown envelope is repaired or resynchronized, and metadata/trailing-byte meanings are unassigned.',
                   'Application payloads are hashed in this report; optional private envelope output retains literal bytes separately.',
                   'USBPcap has no capture-drop count and the owned pipe close need not drain all outstanding driver reads.',
                   'This is adapter-local host traffic; it does not establish VPW monitoring, controller programming, or recovery.'],
        'complete_capture_proven': False, 'descriptor_packet_size_verified': descriptor_evidence is not None,
        'active_transport_implemented': False, 'adapter_opened': False, 'live_write_enabled': False}
    return result, {'schema': 'private-autocal-usb-envelopes-v1', 'rx': private_rx, 'tx': private_tx}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap', required=True, type=Path)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--bus', required=True, type=usb.number)
    parser.add_argument('--device', required=True, type=usb.number)
    parser.add_argument('--in-endpoint', required=True, type=usb.number)
    parser.add_argument('--out-endpoint', required=True, type=usb.number)
    parser.add_argument('--max-packet-size', required=True, type=int, choices=(64, 512))
    parser.add_argument('--descriptor-report', type=Path)
    parser.add_argument('--expected-descriptor-sha256')
    parser.add_argument('--expected-instance-id')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--private-envelope-output', type=Path)
    args = parser.parse_args(argv)
    if any((args.descriptor_report, args.expected_descriptor_sha256, args.expected_instance_id)) and not all((args.descriptor_report, args.expected_descriptor_sha256, args.expected_instance_id)):
        parser.error('Descriptor binding requires report, expected SHA256 and exact instance ID together')
    outputs = [path for path in (args.output, args.private_envelope_output) if path is not None]
    if len(set(path.resolve() for path in outputs)) != len(outputs) or any(path.exists() or path.resolve() == args.pcap.resolve() for path in outputs):
        parser.error('Output paths must be new, distinct, and different from the PCAP')
    try:
        raw, source = usb.read_input(args.pcap, usb.DEFAULT_MAX_INPUT_BYTES)
        if source['sha256'] != args.expected_sha256.lower():
            raise ValueError('Input differs from caller-pinned SHA256')
        descriptor = None
        if args.descriptor_report is not None:
            descriptor_raw, descriptor_source = usb.read_input(args.descriptor_report, usb.DEFAULT_MAX_INPUT_BYTES)
            if descriptor_source['sha256'] != args.expected_descriptor_sha256.lower():
                raise ValueError('Descriptor report differs from pinned SHA256')
            descriptor = descriptor_evidence_from_report(descriptor_raw, args.expected_instance_id, args.device,
                                                         args.in_endpoint, args.out_endpoint, args.max_packet_size)
            descriptor['source'] = descriptor_source
        result, private = analyze(raw, bus=args.bus, device=args.device, in_endpoint=args.in_endpoint,
                                  out_endpoint=args.out_endpoint, max_packet_size=args.max_packet_size,
                                  descriptor_evidence=descriptor)
        result['input'] = source
        result['implementation_sha256'] = {name: usb.sha256(Path(__file__).with_name(name).read_bytes()) for name in
            (Path(__file__).name, 'compare_usb_serial_capture.py', 'audit_trace_wrappers.py', 'checksum.py')}
        if usb.read_input(args.pcap, usb.DEFAULT_MAX_INPUT_BYTES)[0] != raw:
            raise ValueError('PCAP changed during analysis')
        if args.descriptor_report is not None and usb.read_input(args.descriptor_report, usb.DEFAULT_MAX_INPUT_BYTES)[0] != descriptor_raw:
            raise ValueError('Descriptor report changed during analysis')
        if args.private_envelope_output is not None:
            private['input'] = source
            with args.private_envelope_output.open('x', encoding='utf8', newline='\n') as stream:
                json.dump(private, stream, indent=2); stream.write('\n')
            result['private_envelope_output'] = {'path': str(args.private_envelope_output.resolve()),
                'sha256': usb.sha256(args.private_envelope_output.read_bytes())}
        with args.output.open('x', encoding='utf8', newline='\n') as stream:
            json.dump(result, stream, separators=(',', ':')); stream.write('\n')
    except (OSError, ValueError, KeyError, struct.error) as error:
        parser.error(str(error))
    print(json.dumps({'output': str(args.output.resolve()), 'rx_envelopes': result['rx']['envelope_count'],
        'tx_envelopes': result['tx']['envelope_count'], 'rx_application_bytes': result['rx']['stream_bytes'],
        'tx_application_bytes': result['tx']['stream_bytes'],
        'framing_agreement_under_packet_hypothesis': result['framing_agreement_under_packet_hypothesis'],
        'descriptor_packet_size_verified': result['descriptor_packet_size_verified'], 'complete_capture_proven': False}))
    return 0 if result['framing_agreement_under_packet_hypothesis'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
