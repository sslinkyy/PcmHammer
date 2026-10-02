"""Bounded, metadata-only inspection of saved V03VPW AutoCal EFX traces."""
import argparse
from collections import Counter
import json
import math
from pathlib import Path
import re
import zlib
from al5_segment import sha256
from decode_trace_containers import decode
from inspect_trace_containers import MAX_INPUT, MAX_OUTPUT, HEADER_WINDOW, probe_zlib

NAME = re.compile(r'USR_[0-9]{4}\.efx', re.I)
SIGNATURE = b'V03VPW'


def inspect(path):
    path = Path(path)
    if not NAME.fullmatch(path.name):
        raise ValueError('explicit USR_nnnn.efx path required')
    if not 24 <= path.stat().st_size <= MAX_INPUT:
        raise ValueError('device trace size outside policy')
    data = path.read_bytes()
    if not 24 <= len(data) <= MAX_INPUT or not data.startswith(SIGNATURE):
        raise ValueError('unsupported device trace signature or size')
    try:
        decode(data)
    except ValueError:
        existing_htx_decoder_accepts = False
    else:
        existing_htx_decoder_accepts = True
    transformed = bytes((((((b - 0x87) & 255) << 3) |
                         (((b - 0x87) & 255) >> 5)) & 255) ^ 0xA5 for b in data)
    matches = []
    for offset in range(min(HEADER_WINDOW, len(transformed))):
        try:
            stream = zlib.decompressobj()
            output = stream.decompress(transformed[offset:], MAX_OUTPUT + 1)
        except zlib.error:
            continue
        if output and len(output) <= MAX_OUTPUT and stream.eof and not stream.unused_data:
            matches.append({'offset': offset, 'bytes': len(output), 'sha256': sha256(output)})
    counts = Counter(data)
    return {
        'source_name': path.name, 'source_sha256': sha256(data), 'bytes': len(data),
        'observed_signature': SIGNATURE.decode('ascii'),
        'entropy_bits_per_byte': round(-sum(n / len(data) * math.log2(n / len(data))
                                           for n in counts.values()), 6),
        'htx_decoder_accepts': existing_htx_decoder_accepts,
        'bounded_rotation_xor_zlib_probe': probe_zlib(data),
        'bounded_existing_htx_transform_offset_probe': {
            'offset_window_bytes': HEADER_WINDOW, 'output_limit_bytes': MAX_OUTPUT,
            'complete_streams': matches},
        'unframed_header_signature_hits': {h: data.count(bytes.fromhex(h))
                                          for h in ('6c18f0', '6d18f0', '6cf018',
                                                    '6c18f1', '6d18f1', '6cf118')},
        'signature_hits_are_packet_evidence': False,
        'device_record_framing_verified': False,
        'controller_identity_verified': False, 'operation_outcome': None}


def report(paths, *, user_reports_encryption=False):
    traces = [inspect(path) for path in paths]
    if not traces:
        raise ValueError('at least one device trace required')
    return {
        'schema_version': 1,
        'scope': 'Metadata and bounded saved-file probes only. No device or EFILive executable opened.',
        'limits': 'V03VPW is an observed signature, not decoded AL5 identity. Entropy does not prove encryption. Probe failure does not prove absent traffic. No framing, timestamps, direction, payload, acknowledgment or flash outcome is decoded.',
        'generator_sha256': sha256(Path(__file__).read_bytes()),
        'encryption_context': {'user_reports_efilive_encryption': user_reports_encryption,
                               'algorithm_independently_verified': False},
        'trace_count': len(traces), 'unique_file_hashes': len({t['source_sha256'] for t in traces}),
        'traces': traces, 'format_decoding_verified': False,
        'complete_programming_exchange_verified': False,
        'physical_transport_verified': False, 'recovery_verified': False,
        'ready_to_flash': False, 'live_write_enabled': False, 'erase_scope': None,
        'would_send': [], 'erase_packets': [], 'program_packets': []}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--user-reports-encryption', action='store_true',
                        help='Record user provenance only; does not establish a cipher or decode traffic.')
    args = parser.parse_args()
    if any(args.output.resolve() == path.resolve() for path in args.trace):
        parser.error('output must not overwrite an input trace')
    result = report(args.trace, user_reports_encryption=args.user_reports_encryption)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'trace_count': result['trace_count'], 'format_decoding_verified': False}))
