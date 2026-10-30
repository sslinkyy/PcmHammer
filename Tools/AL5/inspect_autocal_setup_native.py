"""Pin HAPI transport setup/compatibility evidence without target or device I/O.

The one-byte 8604 use here is separate from the six-byte saved VPW setup
messages. This collector does not provide a bus initialization recipe.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

import pefile

from inspect_autocal_transport import HAPI_SHA256


HEADER_SHA256 = 'cf2ad290c68137373b26629bf9feed6f4847f4e9e5cde4b980a212cebeb4ff6a'
WINDOWS = (
    ('connection_backend_selection', 0xA13723, 0xA13798),
    ('available_device_setup_call', 0xA13858, 0xA138A4),
    ('one_byte_8604_first_attempt', 0xA169EA, 0xA16A85),
    ('one_byte_8604_short_header_fallback', 0xA16A96, 0xA16AFA),
    ('fallback_error_clears_header_mode', 0xA16B0B, 0xA16B25),
    ('two_byte_8800_followup', 0xA16B33, 0xA16B62),
    ('restore_prior_host_timeout', 0xA16B8F, 0xA16B9A),
    ('request_then_receive', 0xA14022, 0xA14047),
    ('metadata_zero_request_wrapper', 0xA140A5, 0xA140C3),
    ('receive_header_mode_selection', 0xA173CA, 0xA173DD),
    ('positive_timeout_clamp_and_backend_dispatch', 0xA13E65, 0xA13EB9),
    ('signed_clamp_helper', 0x6E2A44, 0x6E2A51),
    ('logical_timeout_cache', 0x6ECE04, 0x6ECE90),
    ('ftdi_settimeouts_binding', 0x6EC246, 0x6EC25B),
    ('ftdi_purge_binding', 0x6EC36F, 0x6EC384),
    ('backend_purge_dispatch', 0xA16C00, 0xA16C43),
    ('ftdi_purge_call_and_result', 0x6EE5A6, 0x6EE5DC),
)
STRINGS = (
    (0x6EC57C, 'FT_SetTimeouts'),
    (0x6EC6AC, 'FT_Purge'),
    (0x6ECEC8, 'Setting USB timeouts to Read=%dms Write=%dms'),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def inspect(hapi_path, dumpbin_path, header_path):
    hapi_path, dumpbin_path, header_path = map(Path, (hapi_path, dumpbin_path, header_path))
    snapshots = [(p, p.read_bytes()) for p in (hapi_path, dumpbin_path, header_path, Path(__file__))]
    source, disassembler, header, generator = [raw for _, raw in snapshots]
    if digest(source) != HAPI_SHA256:
        raise ValueError('HAPI identity differs; address profile cannot be reused')
    if digest(header) != HEADER_SHA256:
        raise ValueError('FTDI header differs; purge flag attribution cannot be reused')
    pe = pefile.PE(data=source, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase

    def location(va, size):
        rva = va - base
        for section in pe.sections:
            relative = rva - section.VirtualAddress
            if 0 <= relative and relative + size <= section.SizeOfRawData:
                offset = section.PointerToRawData + relative
                data = source[offset:offset + size]
                if len(data) != size:
                    raise ValueError('Truncated source range')
                return {'va': hex(va), 'rva': hex(rva), 'file_offset': offset,
                        'bytes': size, 'sha256': digest(data),
                        'section': section.Name.rstrip(b'\0').decode('ascii')}, data
        raise ValueError('Range not wholly backed by one section')

    strings = []
    for va, value in STRINGS:
        expected = value.encode('utf-16le') + b'\0\0'
        where, actual = location(va, len(expected))
        if actual != expected:
            raise ValueError('Expected binding/log string differs')
        strings.append({'value': value, 'source': where})
    flags = []
    for ordinal, line in enumerate(header.splitlines(), 1):
        match = re.fullmatch(rb'#define\s+(FT_PURGE_RX|FT_PURGE_TX)\s+([12])', line)
        if match:
            flags.append({'name': match[1].decode('ascii'), 'value': int(match[2]), 'line': ordinal, 'source_line': line.decode('ascii')})
    if {row['name']: row['value'] for row in flags} != {'FT_PURGE_RX': 1, 'FT_PURGE_TX': 2}:
        raise ValueError('Expected FTDI purge declarations are missing or different')
    windows = []
    for role, start, end in WINDOWS:
        where, _ = location(start, end - start)
        lookahead, _ = location(start, end - start + 16)
        command = [str(dumpbin_path), '/disasm:nobytes', f'/range:{hex(start)},{hex(end + 15)}', str(hapi_path)]
        output = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
        lines = []
        for line in output.stdout.splitlines():
            match = re.match(r'\s+([0-9A-F]{8}):', line)
            if match and start <= int(match[1], 16) < end:
                lines.append(line.strip())
        if not lines or not lines[0].startswith(f'{start:08X}:'):
            raise ValueError('Disassembler did not begin at requested boundary')
        windows.append({'role': role, 'source': where, 'end_exclusive_va': hex(end),
                        'lookahead_source': lookahead, 'command': command, 'instructions': lines})
    exception_metadata = []
    for va in (0xA16A85, 0xA16AFA):
        where, raw = location(va, 17)
        exception_metadata.append({'source': where, 'raw_hex': raw.hex(),
                                   'candidate_count_le32_at_5': int.from_bytes(raw[5:9], 'little'),
                                   'candidate_type_pointer_at_9': hex(int.from_bytes(raw[9:13], 'little')),
                                   'candidate_handler_pointer_at_13': hex(int.from_bytes(raw[13:17], 'little')),
                                   'interpretation_limit': 'Retained descriptor values after the runtime helper jump; exception-class matching is not reimplemented or executed'})
    # Raw immediate encodings are candidate searches, not decoded instructions.
    searches = []
    for word in (0x8603, 0x8604, 0x8B01):
        for prefix, width in ((b'\x66\xba', 2), (b'\x66\xb9', 2), (b'\x68', 4)):
            pattern = prefix + word.to_bytes(width, 'little')
            matches = []
            for section in pe.sections:
                if not section.Characteristics & 0x20000000:
                    continue
                lo, hi = section.PointerToRawData, section.PointerToRawData + section.SizeOfRawData
                offset = source.find(pattern, lo, hi)
                while offset >= 0:
                    matches.append({'file_offset': offset,
                                    'va': hex(base + section.VirtualAddress + offset - lo)})
                    offset = source.find(pattern, offset + 1, hi)
            searches.append({'command_candidate': f'0x{word:04X}', 'byte_pattern_hex': pattern.hex(),
                             'matches': matches, 'instruction_boundaries_verified_by_search': False})
    for path, raw in snapshots:
        if path.read_bytes() != raw:
            raise ValueError(f'Source changed during collection: {path}')
    return {
        'schema': 'autocal-transport-setup-static-v1',
        'scope': 'Offline native host initialization/compatibility helpers; not AutoCal VPW bus setup or live implementation',
        'source': {'path': str(hapi_path.resolve()), 'bytes': len(source), 'sha256': digest(source)},
        'generator_sha256': digest(generator),
        'disassembler': {'path': str(dumpbin_path.resolve()), 'sha256': digest(disassembler)},
        'ftdi_header': {'path': str(header_path.resolve()), 'sha256': digest(header), 'purge_flags': flags},
        'input_stability': 'HAPI, dumpbin, header and generator bytes compared before/after collection; no file lock prevents transient replacement',
        'strings': strings, 'disassembly_windows': windows, 'exception_descriptor_candidates': exception_metadata,
        'bounded_raw_pattern_searches': searches,
        'observations': [
            {'kind': 'static_derivation', 'addresses': ['0xA13858', '0xA13879', '0xA169EA'],
             'finding': 'After an available-device check, the caller invokes A169C8 then purge helper A16BD8. No complete bus initialization semantics are established.'},
            {'kind': 'static_derivation', 'addresses': ['0xA16A3F', '0xA16A64', '0xA16A6B', '0xA14031', '0xA14042'],
             'finding': 'A169C8 first constructs exactly one zero byte for command8604, uses logical timeout1500ms and sends then receives in the same command context. Purge calls surround this attempt. This is different from six-byte8604 messages in saved VM traces.'},
            {'kind': 'static_derivation', 'addresses': ['0xA16AA3', '0xA16ADC', '0xA16AF8', '0xA16B0E'],
             'finding': 'Its backend2 exception fallback sets host+51 to1 and retries the same one-byte8604. The success jump bypasses clearing that byte; the retry error handler clears it. The already-pinned receive header selector identifies +51 nonzero as the short8-byte-header mode, not VPW speed.'},
            {'kind': 'static_derivation', 'addresses': ['0xA16B33', '0xA16B43', '0xA16B49', '0xA16B56', '0xA16B95'],
             'finding': 'The helper follows with command8800 carrying two zero bytes at logical timeout500ms, then restores the prior host timeout. The command payload effect in firmware remains unknown.'},
            {'kind': 'static_derivation', 'addresses': ['0xA13E65', '0xA13E79', '0x6E2A44', '0xA13E89', '0x6ECE6F', '0x6ECE72'],
             'finding': 'Positive requested host timeouts clamp to250..65535ms. A changed value updates host+14 and backend2 caches equal read/write values at wrapper+78/+7C. Nonpositive requests leave state unchanged. 6ECE04 stores these logical values and does not call FT_SetTimeouts directly.'},
            {'kind': 'static_derivation', 'addresses': ['0x6EC256', '0x6EC57C'],
             'finding': 'FTDI wrapper slot+2C binds FT_SetTimeouts. The fixed native driver timeout invocation is a separate path, not the logical cache setter traced here.'},
            {'kind': 'static_derivation', 'addresses': ['0xA16C22', '0xA16C27', '0x6EE5BB', '0x6EC37F', '0x6EC6AC'],
             'finding': 'For backend2, A16BD8 passes mask3 to6EE564, which calls bound FT_Purge at slot+58 with the selected handle. The installed header defines3 as RX1|TX2. Static invocation does not establish successful queue clearing or bus silence.'},
        ],
        'unknowns': [
            'No complete six-byte8604, four-byte8603 or four-byte8B01 producer was recovered by the three bounded immediate-encoding searches. Computed commands, data tables and other artifacts remain outside that search.',
            'Raw word occurrences and byte-pattern absences are not whole-program command reachability proofs.',
            'The helper error routes are bounded native windows, not proof of firmware compatibility or retry safety. They do not justify enabling short-header fallback in PcmHammer.',
            'Initial VPW mode, physical speed, filters, completion flags and firmware effects of8604/8800 remain unqualified.',
            'Linear windows exclude embedded Delphi exception-table data; full exception-class semantics and every caller are not recovered.',
        ],
        'target_executed': False, 'adapter_opened': False, 'vehicle_transmissions_enabled': False,
        'live_write_enabled': False, 'ready_to_flash': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hapi', required=True, type=Path)
    parser.add_argument('--dumpbin', required=True, type=Path)
    parser.add_argument('--ftdi-header', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = inspect(args.hapi, args.dumpbin, args.ftdi_header)
    with args.output.open('x', encoding='utf8', newline='\n') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'windows': len(WINDOWS), 'source_sha256': HAPI_SHA256, 'adapter_opened': False}))


if __name__ == '__main__':
    main()
