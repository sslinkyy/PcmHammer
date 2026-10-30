"""File-only structure inventory of four pinned installed V2 EFW artifacts.

No firmware execution, update, decompression or hardware access occurs. The
observed positive LE32-length framing is not a firmware instruction format.
"""
import argparse
from collections import Counter
import json
import math
from pathlib import Path

from al5_segment import sha256
from validate_vm_buffers import read_bounded


MAX_INPUT_BYTES = 16 * 1024 * 1024  # Explicit file-analysis resource ceiling.
ARTIFACTS = {
    'autocal_program': ('ACProgV2_08_221.efw', '9886721c6d6ca919bad833192cc147f2f4657328b4024b0ac4aa5af28c2cb07c'),
    'flashscan_program': ('FSProgV2_08_221.efw', '1ba8677d15772e7dcfc569f301dcbaea521f0eccc2f22785b64cf473e418ad7b'),
    'autocal_boot': ('Boot Block/ACBootV2_08_009.efw', '2c3ae5fce085d40c937bf9756c32e5490d425cf860a26eb202f78fe267b73885'),
    'flashscan_boot': ('Boot Block/FSBootV2_08_009.efw', 'ea2551a99c0ca2bb433fbc313ea97b9ab3bc775eae5a61fd61add8e98887a670'),
}
KNOWN_STRINGS = ('EFILive', 'AutoCal', 'FlashScan', 'J1850')


def entropy(data):
    if not data:
        return None
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in Counter(data).values())


def framed_regions(source):
    """Parse the observed framing exactly; no recovery or inner-byte resync."""
    if not isinstance(source, bytes) or not 0 < len(source) <= MAX_INPUT_BYTES:
        raise ValueError('Nonempty bounded firmware bytes required')
    regions, offset = [], 0
    while offset < len(source):
        if len(source) - offset < 4:
            raise ValueError('Truncated LE32 region length')
        length = int.from_bytes(source[offset:offset + 4], 'little')
        if length == 0:
            raise ValueError('Zero region length is outside the observed profile')
        if length > len(source) - offset - 4:
            raise ValueError('Declared region exceeds remaining source bytes')
        regions.append((offset, source[offset + 4:offset + 4 + length]))
        offset += 4 + length
    return regions


def bounded_tail_period(data):
    """Find the longest periodic suffix in the final <=4096 bytes, period<=256.

    At least two periods and 64 bytes must match. No alignment, padding meaning,
    codec or contents beyond this precisely bounded window are inferred.
    """
    tail = data[-4096:]
    best = None
    for period in range(1, min(256, len(tail) // 2) + 1):
        matched = 0
        for index in range(len(tail) - 1, period - 1, -1):
            if tail[index] != tail[index - period]:
                break
            matched += 1
        extent = matched + period
        if extent >= max(64, 2 * period) and (best is None or extent > best['matched_suffix_bytes']):
            best = {'period_bytes': period, 'matched_suffix_bytes': extent,
                    'suffix_offset_within_region': len(data) - extent,
                    'examined_tail_bytes': len(tail)}
    return best


def prefix_signatures(data):
    """Only prefix candidates, not parsers or proof of a codec/architecture."""
    signatures = (('ELF', b'\x7fELF'), ('DOS_MZ', b'MZ'), ('gzip', b'\x1f\x8b'),
                  ('ZIP_local_header', b'PK\x03\x04'), ('XZ', b'\xfd7zXZ\x00'),
                  ('bzip2', b'BZh'))
    result = [name for name, prefix in signatures if data.startswith(prefix)]
    if len(data) >= 2 and data[0] & 15 == 8 and data[0] >> 4 <= 7 and int.from_bytes(data[:2], 'big') % 31 == 0:
        result.append('zlib_header_candidate')
    return result


def known_string_counts(data):
    return [{'literal': value, 'ascii_occurrences': data.count(value.encode('ascii')),
             'utf16le_occurrences': data.count(value.encode('utf-16le'))} for value in KNOWN_STRINGS]


def analyze_bytes(source):
    regions = framed_regions(source)
    result = []
    for ordinal, (offset, payload) in enumerate(regions):
        result.append({
            'region_ordinal_zero_based': ordinal,
            'length_field_file_offset': offset, 'length_field_le32_hex': source[offset:offset + 4].hex(),
            'payload_file_offset': offset + 4, 'payload_bytes': len(payload),
            'end_file_offset_exclusive': offset + 4 + len(payload),
            'payload_sha256': sha256(payload), 'payload_prefix_up_to_16_bytes_hex': payload[:16].hex(),
            'length_multiple_of_256': len(payload) % 256 == 0,
            'byte_entropy_bits': entropy(payload), 'distinct_byte_values': len(set(payload)),
            'zero_bytes': payload.count(0), 'ff_bytes': payload.count(255),
            'recognized_prefix_signature_candidates': prefix_signatures(payload),
            'known_string_counts': known_string_counts(payload),
            'bounded_tail_period': bounded_tail_period(payload),
            'instruction_architecture': None, 'compression_format': None, 'encryption_format': None,
            'firmware_load_address': None, 'region_purpose': None,
        })
    return {'source_bytes': len(source), 'source_sha256': sha256(source),
            'source_prefix_up_to_16_bytes_hex': source[:16].hex(),
            'region_count': len(result), 'regions': result,
            'framing': 'Observed positive LE32 byte length followed immediately by that many opaque bytes, repeated to exact EOF',
            'framing_covers_complete_file': True,
            'byte_entropy_bits': entropy(source),
            'physical_protocol_or_handler_identified': False}


def compare_regions(left, right):
    left_regions, right_regions = framed_regions(left), framed_regions(right)
    compared = []
    for ordinal, ((lo, lb), (ro, rb)) in enumerate(zip(left_regions, right_regions)):
        overlap = min(len(lb), len(rb))
        prefix = next((index for index in range(overlap) if lb[index] != rb[index]), overlap)
        suffix = 0
        for a, b in zip(reversed(lb), reversed(rb)):
            if a != b:
                break
            suffix += 1
        compared.append({'region_ordinal_zero_based': ordinal,
                         'left_payload_file_offset': lo + 4, 'right_payload_file_offset': ro + 4,
                         'left_bytes': len(lb), 'right_bytes': len(rb),
                         'exact_region_bytes_equal': lb == rb,
                         'common_prefix_bytes': prefix, 'common_suffix_bytes': suffix,
                         'same_offset_overlap_bytes_examined': overlap,
                         'equal_bytes_at_same_region_offset': sum(a == b for a, b in zip(lb, rb)),
                         'common_prefix_sha256': sha256(lb[:prefix])})
    return {'regions_compared_by_ordinal': compared,
            'unpaired_left_regions': list(range(len(compared), len(left_regions))),
            'unpaired_right_regions': list(range(len(compared), len(right_regions))),
            'same_function_or_memory_mapping_inferred': False}


def inspect(firmware_root):
    root = Path(firmware_root)
    helpers = [(p, p.read_bytes()) for p in (Path(__file__), Path(__file__).with_name('al5_segment.py'),
                                            Path(__file__).with_name('validate_vm_buffers.py'))]
    loaded = {}
    for role, (relative, expected_sha) in ARTIFACTS.items():
        path = root / relative
        source = read_bounded(path, 1, MAX_INPUT_BYTES)
        if sha256(source) != expected_sha:
            raise ValueError('Exact installed artifact identity required: ' + role)
        loaded[role] = (path, source)
    artifacts = []
    for role, (path, source) in loaded.items():
        artifacts.append({'role': role, 'source_path': str(path.resolve()), **analyze_bytes(source)})
    comparisons = []
    for left, right in (('autocal_program', 'flashscan_program'), ('autocal_boot', 'flashscan_boot')):
        comparisons.append({'left_role': left, 'right_role': right,
                            **compare_regions(loaded[left][1], loaded[right][1])})
    for path, source in list(loaded.values()) + helpers:
        if path.read_bytes() != source:
            raise ValueError('Input or implementation changed during collection')
    return {
        'schema': 'autocal-v2-efw-container-static-v1', 'artifacts': artifacts, 'comparisons': comparisons,
        'implementation': [{'path': str(path.resolve()), 'bytes': len(source), 'sha256': sha256(source)}
                           for path, source in helpers],
        'observations': [
            'Each pinned program file has three LE32-length regions; each pinned boot file has one. Framing consumes every source byte.',
            'The first payloads begin with bytes B0 7B. Program payloads at ordinals1 and2 begin E2 AC 4B CA.',
            'All eight observed payload lengths are multiples of256; this does not establish flash page size or target alignment.',
            'AutoCal and FlashScan program middle regions share a9312-byte prefix but are not identical. The remaining same-offset bytes differ.',
            'The final4096 bytes of both middle regions are periodic with period4. Other bounded periodic tails are reported per region.'],
        'derivations': [
            'The exact outer lengths expose stable byte ranges that a native EFW reader could consume independently.',
            'High byte entropy coexists with repeated suffix patterns. Entropy is a measurement, not evidence sufficient to choose compression, encryption, obfuscation or machine architecture.'],
        'unknowns': [
            'No decode transform, cryptographic mode/key, compression format, checksums or signatures have been established by this collector.',
            'No raw executable region, instruction architecture, load address or purpose is established.',
            '8603/8604/A1 firmware handler locations and physical1x/4x behavior remain unknown; short random byte-pattern matches would not establish handlers.',
            'Missing known strings and unrecognized leading signatures do not prove encrypted content or exclude compression.',
            'Installed filenames and pinned package versions do not establish the firmware currently running on a connected adapter.'],
        'limits': ['Only four exact local artifacts are accepted; this is not a general EFW parser.',
                   'No raw region export, target execution, decompression, update or device I/O occurs.',
                   'Public output contains lengths, offsets, digests, scalar statistics, <=16-byte prefixes and fixed-string counts only.',
                   'Tail tests cover at most4096 bytes and periods1..256; same-ordinal comparisons do not establish same function or memory mapping.'],
        'adapter_opened': False, 'firmware_executed': False, 'firmware_update_attempted': False,
        'physical_protocol_validation': False, 'live_write_enabled': False, 'ready_to_flash': False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firmware-root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    if args.output.exists():
        raise FileExistsError('Preserve existing output or evidence: ' + str(args.output))
    result = inspect(args.firmware_root)
    with args.output.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'output': str(args.output.resolve()), 'artifacts': len(result['artifacts']), 'adapter_opened': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
