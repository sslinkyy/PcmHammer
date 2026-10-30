"""Compare a bounded AutoCal read journal with a saved EFILive E54 read.

File-only, standard-library analysis. No adapter, executable, port or firmware
is opened. Whole framed messages are compared; private image/kernel payloads
are represented only by lengths and digests, never scanned for inner messages.
"""
import argparse
from collections import Counter
import json
import math
from pathlib import Path
import struct

from al5_segment import sha256
from audit_trace_wrappers import framed_message
from checksum import crc16
from decode_trace_containers import decode, records, RECORD_BYTES
from inspect_trace_containers import MAX_INPUT


FIRST_READ = bytes.fromhex('6d10f035011000000000')
SHORT_ACK = bytes.fromhex('6df010750154')
SETUP_LENGTHS = {0x8603: (4,), 0x8604: (1, 6), 0x8800: (2,), 0x8b01: (4,)}


def pin(path, data):
    return {'path': str(Path(path).resolve()), 'bytes': len(data), 'sha256': sha256(data)}


def frame(raw, direction):
    """Validate one complete observed long-header wrapper, including its CRC."""
    if direction not in (1, 2) or len(raw) < (14 if direction == 1 else 15):
        raise ValueError('Incomplete AutoCal wrapper')
    result = framed_message({'kind': 0x42, 'channel': direction, 'payload': raw})
    if result is None or (direction == 2 and raw[-1] != 0x19):
        raise ValueError('Unsupported AutoCal wrapper extent/prefix/trailer')
    payload = result[1]
    end = 12 + len(payload)
    if crc16(raw[:end], 0) != int.from_bytes(raw[end:end + 2], 'little'):
        raise ValueError('AutoCal outer CRC mismatch')
    return {'raw': raw, 'payload': payload, 'direction': direction,
            'command': int.from_bytes(raw[2:4], 'little') if direction == 1 else None}


def is_vpw(item):
    # RX context is a bounded empirical grouping, not request association.
    return (item['command'] == 0x8a00 if item['direction'] == 1
            else item['raw'][2:6] in (bytes(4), bytes.fromhex('10000000')))


def is_first_read(item):
    return item['direction'] == 1 and item['command'] == 0x8a00 and item['payload'] == FIRST_READ


def summary(item):
    result = {key: item[key] for key in ('journal_line_one_based', 'record_ordinal_zero_based',
              'record_decoded_offset', 'wrapper_decoded_offset', 'elapsed_ms',
              'saved_date_f64_le_hex') if key in item}
    result.update(direction='host_to_device' if item['direction'] == 1 else 'device_to_host',
                  header_hex=item['raw'][:12].hex(), wrapper_bytes=len(item['raw']),
                  wrapper_sha256=sha256(item['raw']), payload_bytes=len(item['payload']),
                  payload_sha256=sha256(item['payload']), outer_crc_matches=True)
    if item['direction'] == 1:
        result['command_hex'] = f"{item['command']:04X}"
    if is_vpw(item):
        result['vpw_prefix_hex'] = item['payload'][:4].hex()
    if item['payload'] == FIRST_READ or item['payload'] == SHORT_ACK:
        result['literal_fixed_diagnostic_payload_hex'] = item['payload'].hex()
    if item['direction'] == 1 and len(item['payload']) in SETUP_LENGTHS.get(item['command'], ()):
        result['literal_small_setup_payload_hex'] = item['payload'].hex()
    return result


def analyze_trace(source):
    decoded = decode(source)
    rows = list(records(decoded))
    if not rows:
        raise ValueError('Empty saved trace')
    envelopes = []
    for ordinal, row in enumerate(rows):
        if row['kind'] != 0x42:
            continue
        item = frame(row['payload'], row['channel'])
        item.update(record_ordinal_zero_based=ordinal, record_decoded_offset=row['offset'],
                    wrapper_decoded_offset=row['offset'] + RECORD_BYTES,
                    elapsed_ms=(row['date'] - rows[0]['date']) * 86400000,
                    saved_date_f64_le_hex=struct.pack('<d', row['date']).hex())
        envelopes.append(item)
    selected = [item for item in envelopes if is_first_read(item)]
    if len(selected) != 1:
        raise ValueError('Expected one exact first-address 4096-byte request in saved trace')
    first = selected[0]
    start = envelopes.index(first)
    data = [item for item in envelopes[start:] if item['direction'] == 2 and is_vpw(item)
            and item['payload'].startswith(bytes.fromhex('6df01036'))]
    if not data:
        raise ValueError('Saved comparison has no subsequent E54 data reply')
    end = envelopes.index(data[-1]) + 1
    interval = envelopes[start:end]
    requests = [item for item in interval if item['direction'] == 1 and item['command'] == 0x8a00
                and item['payload'].startswith(bytes.fromhex('6d10f035'))]
    short = [item for item in interval if item['direction'] == 2 and is_vpw(item)
             and item['payload'].startswith(bytes.fromhex('6df01075'))]
    setup = [item for item in envelopes[:start] if item['direction'] == 1 and
             len(item['payload']) in SETUP_LENGTHS.get(item['command'], ())]
    uploads = [item for item in envelopes[:start] if item['direction'] == 1 and
               item['command'] == 0x8a00 and item['payload'].startswith(bytes.fromhex('6d10f03680'))]
    markers = [item for item in envelopes[:start] if item['direction'] == 1 and
               item['command'] == 0x8a00 and item['payload'] in
               (bytes.fromhex('6cfef0a0'), bytes.fromhex('6cfef0a1'))]
    nonbus = [summary(item) for item in interval if item['direction'] == 1 and item['command'] != 0x8a00]
    first_data_index = envelopes.index(data[0])
    return first, {
        'decoded_bytes': len(decoded), 'decoded_sha256': sha256(decoded),
        'record_count': len(rows), 'binary_wrapper_count': len(envelopes),
        'all_binary_wrappers_validated': True,
        'timestamp_regression_record_ordinals': [i for i in range(1, len(rows)) if rows[i]['date'] < rows[i - 1]['date']],
        'first_request': summary(first),
        'first_data_window': [summary(item) for item in envelopes[start:first_data_index + 1]],
        'first_data_saved_log_delay_ms': data[0]['elapsed_ms'] - first['elapsed_ms'],
        'setup_before_first_request': [summary(item) for item in setup],
        'last_small_setup_before_first_request': summary(setup[-1]) if setup else None,
        'preceding_execute_wrappers': [summary(item) for item in uploads],
        'preceding_a0_a1_markers': [summary(item) for item in markers],
        'data_phase': {
            'first_record': first['record_ordinal_zero_based'],
            'last_data_record': data[-1]['record_ordinal_zero_based'],
            'request_35_count': len(requests), 'short_75_count': len(short), 'data_36_count': len(data),
            'exact_known_short_75_count': sum(item['payload'] == SHORT_ACK for item in short),
            'data_vpw_length_counts': dict(sorted(Counter(str(len(item['payload'])) for item in data).items())),
            'data_returned_metadata_le32_hex_counts': dict(Counter(item['raw'][2:6].hex() for item in data)),
            'request_caller_metadata_le32_hex_counts': dict(Counter(item['raw'][6:10].hex() for item in requests)),
            'nonbus_host_commands': nonbus,
            'no_additional_nonbus_host_poll_observed': not nonbus,
            'request_reply_pairing': None,
        },
    }


def analyze_journal(source):
    rows = [json.loads(line) for line in source.decode('utf-8-sig').splitlines() if line.strip()]
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError('Journal rows must be objects')
    envelopes, reads = [], []
    pending_write = None
    pending_receive = bytearray()
    previous_time = -1
    for ordinal, row in enumerate(rows):
        kind = row.get('kind')
        if kind not in ('write_attempt', 'write_completed', 'read_completed'):
            continue
        time = row.get('elapsed_ms')
        if type(time) not in (int, float) or not math.isfinite(time) or time < previous_time:
            raise ValueError('Journal I/O times must be finite and monotonic')
        previous_time = time
        value = row['data']
        count = value.get('count')
        if type(count) is not int or count < 0:
            raise ValueError('Invalid native transfer count')
        if kind == 'write_attempt':
            raw = bytes.fromhex(value['hex'])
            # The observed experiment used only complete writes. Do not silently
            # infer reconstruction/acceptance for partial or overlapping writes.
            if pending_write is not None or value.get('offset') != 0 or count != len(raw):
                raise ValueError('Only nonoverlapping complete observed writes are supported')
            item = frame(raw, 1)
            item.update(journal_line_one_based=ordinal + 1, elapsed_ms=time)
            envelopes.append(item)
            pending_write = item
        elif kind == 'write_completed':
            if pending_write is None or count != len(pending_write['raw']):
                raise ValueError('Unmatched or partial write completion')
            pending_write['completed_elapsed_ms'] = time
            pending_write = None
        else:
            raw = bytes.fromhex(value['hex'])
            if len(raw) != count:
                raise ValueError('Native read count differs from preserved bytes')
            reads.append({'journal_line_one_based': ordinal + 1, 'elapsed_ms': time, 'bytes': count})
            pending_receive.extend(raw)
            while len(pending_receive) >= 12:
                extent = int.from_bytes(pending_receive[10:12], 'little') + 15
                if len(pending_receive) < extent:
                    break
                item = frame(bytes(pending_receive[:extent]), 2)
                del pending_receive[:extent]
                item.update(journal_line_one_based=ordinal + 1, elapsed_ms=time)
                envelopes.append(item)
    if pending_write is not None or pending_receive:
        raise ValueError('Incomplete native write or received wrapper remains in journal')
    selected = [item for item in envelopes if is_first_read(item)]
    if len(selected) != 1:
        raise ValueError('Expected one first-address read submission in bounded journal')
    first = selected[0]
    after = [row for row in reads if row['journal_line_one_based'] > first['journal_line_one_based']]
    if not after:
        raise ValueError('No native read observations follow the request')
    setup = [item for item in envelopes if item['direction'] == 1 and
             item['journal_line_one_based'] < first['journal_line_one_based'] and
             len(item['payload']) in SETUP_LENGTHS.get(item['command'], ())]
    vpw_tx = [item for item in envelopes if item['direction'] == 1 and is_vpw(item)]
    vpw_rx = [item for item in envelopes if item['direction'] == 2 and is_vpw(item)]
    plans = [row['data'] for row in rows if row.get('kind') == 'plan']
    results = [row['data'] for row in rows if row.get('kind') == 'kernel_result']
    if len(plans) != 1 or len(results) != 1:
        raise ValueError('Expected one plan and one kernel result')
    return first, plans[0], results[0], {
        'journal_record_count': len(rows), 'first_request': summary(first),
        'first_request_completed_elapsed_ms': first['completed_elapsed_ms'],
        'application_tx_count': sum(item['direction'] == 1 for item in envelopes),
        'application_rx_count': sum(item['direction'] == 2 for item in envelopes),
        'vpw_tx_count': len(vpw_tx), 'vpw_rx_count': len(vpw_rx),
        'all_completed_wrapper_crcs_valid': True, 'uncompleted_writes': 0, 'partial_rx_bytes': 0,
        'vpw_tx_prefix_counts': dict(Counter(item['payload'][:4].hex() for item in vpw_tx)),
        'vpw_rx_prefix_counts': dict(Counter(item['payload'][:4].hex() for item in vpw_rx)),
        'setup_before_first_request': [summary(item) for item in setup],
        'last_small_setup_before_first_request': summary(setup[-1]) if setup else None,
        'after_first_request_native_reads': {
            'completion_count': len(after), 'total_returned_bytes': sum(row['bytes'] for row in after),
            'first_completion_elapsed_ms': after[0]['elapsed_ms'],
            'last_completion_elapsed_ms': after[-1]['elapsed_ms'],
            'last_completion_from_request_ms': after[-1]['elapsed_ms'] - first['elapsed_ms'],
            'every_completion_returned_zero': all(row['bytes'] == 0 for row in after),
            'bus_reply_absence_proven': False,
        },
    }


def compare(receipt_bytes, journal_bytes, trace_bytes):
    receipt = json.loads(receipt_bytes.decode('utf-8-sig'))
    actual, plan, kernel_result, journal = analyze_journal(journal_bytes)
    saved, trace = analyze_trace(trace_bytes)
    if receipt.get('plan') != plan or receipt.get('kernel_result') != kernel_result:
        raise ValueError('Receipt and journal plan/result differ')
    if (kernel_result.get('VpwTransmissions') != journal['vpw_tx_count'] or
            kernel_result.get('VpwReceivedFrames') != journal['vpw_rx_count'] or
            receipt.get('vpw_payload_commands_completed') != journal['vpw_tx_count']):
        raise ValueError('Receipt VPW counts do not match journal')
    if plan.get('profile') != 'e54-read-baseline' or plan.get('flash_programming_enabled') is not False:
        raise ValueError('Receipt is outside the bounded read-only profile')
    a_setup = journal['last_small_setup_before_first_request']
    b_setup = trace['last_small_setup_before_first_request']
    return {
        'schema': 'autocal-saved-read-gap-v1',
        'scope': 'Exact first-read host-envelope comparison and saved receive observations; file-only.',
        'actual': journal, 'saved_efilive': trace,
        'comparison': {
            'first_request_vpw_equal': actual['payload'] == saved['payload'],
            'first_request_complete_outer_wrapper_equal': actual['raw'] == saved['raw'],
            'same_last_small_setup_command_and_payload': (a_setup is not None and b_setup is not None and
                a_setup['command_hex'] == b_setup['command_hex'] and
                a_setup['literal_small_setup_payload_hex'] == b_setup['literal_small_setup_payload_hex']),
            'physical_setup_state_equivalence_proven': False,
            'kernel_equivalence_proven': False,
            'actual_kernel_pin_from_plan': plan.get('kernel'),
            'saved_kernel_scope': 'Saved preceding Execute wrappers are hashed above; they are not the actual PcmHammer kernel.',
            'short75_scope': 'Saved EFILive read has short75 observations. Zero bytes after the actual request cannot establish what its kernel sent on VPW.',
        },
        'receipt_observations': {key: receipt.get(key) for key in (
            'setup_accepted', 'recorded_cleanup_accepted', 'readback_saved_bytes',
            'transport_disposed', 'retained_native_owners', 'channel_fault', 'cleanup_exception')},
        'kernel_result_observations': {key: kernel_result.get(key) for key in (
            'Success', 'InitialIdentityVerified', 'KernelVersionVerified', 'ExitAcknowledged',
            'PostExitIdentityVerified', 'ReadbackLength', 'ReadbackCrcVerified',
            'BaselineMatched', 'BenchPowerCycleRequired', 'FlashWriteEnabled')},
        'policy_observations': {key: receipt.get('kernel_policy', {}).get(key) for key in (
            'CurrentPhase', 'Failure', 'ReadBlockAttempts', 'ReadBlockReplies',
            'CrcQueryAttempts', 'VerifiedCrcRanges')},
        'limits': [
            'Native USB writes establish host submission only, not physical VPW transmission or ECU processing.',
            'Zero returned USB bytes do not distinguish absent ECU output, invalid physical frames, adapter filtering or firmware withholding.',
            'The same final8604 command does not establish the same persistent adapter state; earlier8603/8604 and A0/A1 paths differ.',
            'No request/reply association is inferred solely from saved record adjacency. Saved host times are not wire timings.',
            'The saved EFILive loader and actual PcmHammer kernel differ. A short75-dependent receive path is a hypothesis, not proven firmware behavior.',
            'Large data bodies and kernel payloads remain private. The analyzer exports lengths, checksums and hashes, not firmware bytes.',
            'No adapter, native target, vehicle, flash programming or recovery test is performed by this analyzer.',
        ],
        'adapter_opened': False, 'live_write_enabled': False, 'ready_to_flash': False,
    }


def inspect(receipt_path, journal_path, trace_path, expected_hashes=None):
    paths = [Path(path) for path in (receipt_path, journal_path, trace_path)]
    helpers = [Path(__file__).with_name(name) for name in (
        'inspect_autocal_read_gap.py', 'al5_segment.py', 'audit_trace_wrappers.py',
        'checksum.py', 'decode_trace_containers.py', 'inspect_trace_containers.py')]
    snapshots = {}
    for path in paths + helpers:
        if not 0 < path.stat().st_size <= MAX_INPUT:
            raise ValueError('Input exceeds the existing16MiB analysis bound')
        snapshots[path] = path.read_bytes()
        if len(snapshots[path]) > MAX_INPUT:
            raise ValueError('Input grew beyond analysis bound')
    if expected_hashes is not None:
        for path, expected in zip(paths, expected_hashes):
            if sha256(snapshots[path]) != expected.lower():
                raise ValueError('Input SHA256 mismatch: ' + str(path))
    result = compare(*(snapshots[path] for path in paths))
    if any(path.read_bytes() != data for path, data in snapshots.items()):
        raise ValueError('Input or implementation changed during analysis')
    result['inputs'] = {key: pin(path, snapshots[path]) for key, path in zip(('receipt', 'journal', 'trace'), paths)}
    result['implementation'] = [pin(path, snapshots[path]) for path in helpers]
    result['input_stability'] = 'All inputs and implementation files compared before and after analysis; no hardware or file locking.'
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--journal', type=Path, required=True)
    parser.add_argument('--trace', type=Path, required=True)
    parser.add_argument('--input-sha256', nargs=3, metavar=('RECEIPT', 'JOURNAL', 'TRACE'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.output.exists():
            raise ValueError('Output already exists; evidence must not be overwritten')
        result = inspect(args.receipt, args.journal, args.trace, args.input_sha256)
        with args.output.open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.error(str(error))
    print(json.dumps({'outer_wrapper_equal': result['comparison']['first_request_complete_outer_wrapper_equal'],
                      'actual_after_request_usb_bytes': result['actual']['after_first_request_native_reads']['total_returned_bytes'],
                      'bus_reply_absence_proven': False, 'ready_to_flash': False}))


if __name__ == '__main__':
    main()
