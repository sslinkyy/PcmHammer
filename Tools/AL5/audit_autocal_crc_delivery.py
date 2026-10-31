"""Offline CRC-delivery differential for the pinned full AutoCal read.

No adapter access, executable launch, binary output, or live-policy changes.
"""
from collections import Counter
import json
from pathlib import Path
import subprocess

from audit_ack_prefix_success import inspect as audit_full
from compare_autocal_gt_prefix import audit_gt
from derive_autocal_ack_kernel import SOURCE_COMMIT, source_audit
from inspect_autocal_read_gap import frame, is_vpw, pin

ROOT = Path(__file__).resolve().parents[2]
REQUEST = bytes.fromhex('6c10f03d02020000060000')
REPLY = bytes.fromhex('6cf0107d02020000060000d6703728')


def crc_shape(request, reply):
    """Exact experiment geometry, independent of the production parser."""
    if len(request) != 11 or request[:5] not in (bytes.fromhex('6c10f03d02'), bytes.fromhex('6d10f03d02')):
        raise ValueError('Unsupported CRC request')
    expected = request[:1] + bytes.fromhex('f0107d') + request[4:]
    if len(reply) != 15 or reply[:11] != expected:
        raise ValueError('CRC reply header, range or extent mismatch')
    return {'priority_hex': request[:1].hex(), 'size': int.from_bytes(request[5:8], 'big'),
            'address': int.from_bytes(request[8:11], 'big'), 'crc_hex': reply[11:].hex()}


def inspect():
    full = audit_full(True)
    folder = ROOT / 'LocalOnly/AutoCalBackendProbe'
    journal = folder / 'e54_full_ack_gt_01.json.journal.jsonl'
    capture = folder / 'gt_e54_full_ack_1x_01.jsonl'
    raw = journal.read_bytes()
    pending = bytearray(); received = []; requests = []
    for row in map(json.loads, raw.splitlines()):
        if row['kind'] == 'write_attempt':
            item = frame(bytes.fromhex(row['data']['hex']), 1)
            if is_vpw(item) and item['payload'] == REQUEST:
                requests.append(row['elapsed_ms'])
        if row['kind'] != 'read_completed':
            continue
        pending.extend(bytes.fromhex(row['data']['hex']))
        while len(pending) >= 12:
            extent = int.from_bytes(pending[10:12], 'little') + 15
            if len(pending) < extent:
                break
            item = frame(bytes(pending[:extent]), 2); del pending[:extent]
            if is_vpw(item):
                received.append(item['payload'])
    assert not pending and len(requests) == 2
    network, messages, gt = audit_gt(capture, capture.read_bytes())
    crc_indices = [i for i, m in enumerate(messages) if m == REPLY]
    assert len(crc_indices) == 2 and REPLY not in received
    counts = Counter((m[:5].hex(), len(m)) for m in received)
    sources = source_audit(ROOT)
    source = subprocess.check_output(['git', '-C', str(ROOT), 'show', SOURCE_COMMIT + ':Kernels/68k-VPW-Asm/Kernel.S']).decode()
    # The source pin is authoritative; these windows keep the derivation reviewable.
    windows = {}
    lines = source.splitlines()
    for start, end in [('ProcessCRC:', 'ProcessCRCPolynomial:'), ('VPWSend:', 'VPWSendFlush:'), ('VPWReceiveReadComplete:', 'VPWReceiveRTS:')]:
        a, b = lines.index(start), lines.index(end)
        windows[start[:-1]] = {'first_line': a+1, 'last_line': b, 'source': '\n'.join(lines[a:b])}
    candidate_request = bytes([0x6d]) + REQUEST[1:]
    candidate_reply = bytes([0x6d]) + REPLY[1:]
    assert crc_shape(candidate_request, candidate_reply)['crc_hex'] == crc_shape(REQUEST, REPLY)['crc_hex']
    return {'schema': 'autocal-crc-delivery-differential-v1',
        'implementation': pin(__file__, Path(__file__).read_bytes()),
        'inputs': full['inputs'], 'source_commit': SOURCE_COMMIT, 'source_pins': sources, 'source_windows': windows,
        'observed': {'autocal_vpw_reply_shapes': [{'prefix_hex': k[0], 'bytes_without_bus_crc': k[1], 'count': v} for k,v in sorted(counts.items())],
            'crc_request_hex': REQUEST.hex(), 'crc_reply_hex': REPLY.hex(), 'crc_reply_shape': crc_shape(REQUEST, REPLY),
            'crc_host_request_elapsed_ms': requests, 'gt_crc_network_ordinals': crc_indices,
            'gt_crc_reply_spacing_ms': (network[crc_indices[1]]['host_monotonic_ns_at_chunk_end']-network[crc_indices[0]]['host_monotonic_ns_at_chunk_end'])/1e6,
            'gt_physical_crc_valid': gt['all_network_vpw_crcs_valid'], 'autocal_crc_reply_count': 0,
            'complete_image_matches_baseline': full['complete_data_matches_baseline']},
        'derivation': ['Pinned ProcessCRC retains byte zero of MessageBuffer, writes response fields and sends 15 bytes.',
            'Pinned VPWSend copies buffer bytes unchanged into the TX FIFO.',
            'Pinned VPWReceive masks bit zero before comparing 6C, so source accepts both 6C and 6D.',
            'Existing production CRC parser and probe guard both require 6C; changing request alone would not create a valid end-to-end test.'],
        'hypothesis': 'AutoCal delivery may depend on the combination of header and reply length. This run cannot separate header, length, service and adapter state.',
        'offline_candidate': {'request_hex': candidate_request.hex(), 'predicted_reply_hex': candidate_reply.hex(),
            'changed_request_byte_offsets': [0], 'kernel_patch_required_by_source': False,
            'requires_separate_explicit_host_policy_and_parser': True, 'live_implemented': False,
            'next_control': 'Compare fixed CRC request headers in separate reset sessions with GT listening; preserve exact range and expected CRC. Do not relax normal parser or verification gates.'},
        'limits': ['Host timestamps are not physical edge timestamps and AutoCal/GT clocks are not synchronized.',
            'Source-derived 6D acceptance and response are predictions until bench observed.',
            'No firmware-wide length threshold, internal filtering rule or fix is proven.',
            'No adapter was opened; bench remains off; flashing and recovery remain unqualified.']}

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Output already exists; preserve evidence')
    report = inspect()
    with args.output.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(report, stream, indent=2); stream.write('\n')
    print(json.dumps(report['observed'], indent=2))
