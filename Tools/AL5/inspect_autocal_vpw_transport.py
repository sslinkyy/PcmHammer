"""Collect pinned, file-only HAPI command-0x8A00 envelope evidence.

No target code, adapter, or vehicle I/O runs. dumpbin reads bounded HAPI file
ranges. The report distinguishes the host envelope from a physical VPW frame.
The requested command context is essential when interpreting received bytes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

import pefile

from inspect_autocal_transport import HAPI_SHA256


# End addresses are exclusive and lie at known instruction boundaries. Sixteen
# bytes of disassembly lookahead prevent a final instruction being cut short;
# only instruction starts within the declared range are retained.
WINDOWS = (
    ('ipc_send_and_receive_arguments', 0xA548E3, 0xA549F1),
    ('send_default_and_register_arguments', 0xA16CA8, 0xA16CDD),
    ('send_long_header_and_payload_copy', 0xA16DE4, 0xA16EA6),
    ('receive_shim_and_register_arguments', 0xA170DC, 0xA17117),
    ('receive_header_size', 0xA173CA, 0xA173DD),
    ('receive_prefix_and_header', 0xA174C4, 0xA1751A),
    ('receive_context_metadata_and_error_marker', 0xA1751A, 0xA175F5),
    ('receive_candidate_and_length_guards', 0xA176F7, 0xA177CF),
    ('receive_crc_comparison', 0xA17814, 0xA17886),
    ('receive_error_echo_check', 0xA17913, 0xA1795A),
    ('receive_error_echo_rejection_and_payload_copy', 0xA179F8, 0xA17A41),
    ('receive_error_status_raise', 0xA17A67, 0xA17AB7),
)

PRIOR_REPORTS = (
    ('EFILIVE_HOST_IPC.json', '2d7846ea73bf723dccd0318cfa0ad440c1fbf814a07d6785549c013af466e4ae'),
    ('VM_CALLBACK_OUTCOMES_STATIC.json', '5c3ced60f7db271ac8d8e09cfbc5b5ea52be7053a8a554e029c626ab3713d3d7'),
    ('VM_RETRY_HELPERS_STATIC.json', 'de0179fb250a497b1e1beaaabbc36295b62ce50d3e8fcc705864488a95228d18'),
)
METADATA_COMMANDS = (0, 0x8B00, 0x8B10, 0x8B11, 0x8B12, 0x8A00, 0x8A10, 0x8B23, 0x8B24)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def inspect(hapi_path, dumpbin_path, docs_path):
    hapi_path, dumpbin_path, docs_path = map(Path, (hapi_path, dumpbin_path, docs_path))
    source = hapi_path.read_bytes()
    if digest(source) != HAPI_SHA256:
        raise ValueError('HAPI identity differs; these static addresses must not be reused')
    disassembler = dumpbin_path.read_bytes()
    prior_bytes = {}
    for name, expected in PRIOR_REPORTS:
        prior_bytes[name] = (docs_path / name).read_bytes()
        if digest(prior_bytes[name]) != expected:
            raise ValueError(f'Prior evidence identity differs: {name}')
    pe = pefile.PE(data=source, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase

    def location(va, count):
        rva = va - base
        for section in pe.sections:
            relative = rva - section.VirtualAddress
            if 0 <= relative and relative + count <= section.SizeOfRawData:
                offset = section.PointerToRawData + relative
                data = source[offset:offset + count]
                if len(data) != count:
                    raise ValueError('Truncated file-backed range')
                return {'va': hex(va), 'rva': hex(rva), 'file_offset': offset,
                        'bytes': count, 'sha256': digest(data),
                        'section': section.Name.rstrip(b'\0').decode('ascii')}
        raise ValueError('Range not wholly backed by one PE section')

    windows = []
    for role, start, end in WINDOWS:
        where = location(start, end - start)
        lookahead = location(start, end - start + 16)
        command = [str(dumpbin_path), '/disasm:nobytes',
                   f'/range:{hex(start)},{hex(end + 15)}', str(hapi_path)]
        completed = subprocess.run(command, check=True, capture_output=True,
                                   text=True, timeout=30)
        lines = []
        for line in completed.stdout.splitlines():
            match = re.match(r'\s+([0-9A-F]{8}):', line)
            if match and start <= int(match[1], 16) < end:
                lines.append(line.strip())
        if not lines or not lines[0].startswith(f'{start:08X}:'):
            raise ValueError('Disassembler did not start at requested address')
        windows.append({'role': role, 'source': where,
                        'end_exclusive_va': hex(end), 'lookahead_source': lookahead,
                        'command': command, 'instructions': lines})

    if hapi_path.read_bytes() != source:
        raise ValueError('HAPI source changed during collection')
    if dumpbin_path.read_bytes() != disassembler:
        raise ValueError('Disassembler changed during collection')
    for name, data in prior_bytes.items():
        if (docs_path / name).read_bytes() != data:
            raise ValueError(f'Prior evidence changed during collection: {name}')

    return {
        'schema': 'autocal-vpw-host-transport-static-v1',
        'scope': 'Pinned file-only HAPI host-envelope interpretation for requested command 0x8A00; no physical protocol execution',
        'source': {'path': str(hapi_path.resolve()), 'bytes': len(source),
                   'sha256': HAPI_SHA256, 'preferred_image_base': hex(base)},
        'generator_sha256': digest(Path(__file__).read_bytes()),
        'disassembler': {'path': str(dumpbin_path.resolve()), 'sha256': digest(disassembler)},
        'input_stability': 'HAPI, disassembler and prior-report bytes compared before and after collection; transient replacement is not prevented by locking',
        'prior_evidence': [{'path': f'Docs/AL5/{name}', 'sha256': expected,
                            'bytes': len(prior_bytes[name])} for name, expected in PRIOR_REPORTS],
        'disassembly_windows': windows,
        'derived_contract': {
            'domain': 'Complete long-header AutoCal host envelope, independently delimited and CRC-checked; not a USB packet or a physical bus frame',
            'tx': {
                'prefix_hex': '0154', 'command_offset': 2, 'command_bytes': 2,
                'command_byte_order': 'little-endian', 'profile_command': '0x8A00',
                'selector_offset': 4, 'selector_derivation': 'Low byte of HAPI host object+0x1C; no physical bus address meaning established',
                'reserved_offset': 5, 'reserved_value_written_by_hapi': 0,
                'caller_metadata_offset': 6, 'caller_metadata_bytes': 4,
                'caller_metadata_byte_order': 'little-endian',
                'caller_metadata_derivation': 'A16CD6 saves ECX; A16E40..A16E66 copies it verbatim. Nonempty IPC send sources shared+0x16. Empty IPC send calls A16CA8, which clears ECX.',
                'payload_offset': 12, 'payload_length_offset': 10,
                'payload_length_bytes': 2, 'payload_length_byte_order': 'little-endian',
                'payload_derivation': 'A16E90..A16EA1 copies the caller bytes without an added or stripped bus prefix',
            },
            'rx_normal': {
                'prefix_hex': '0152', 'requested_command_context_required': True,
                'metadata_commands': [f'0x{value:04X}' for value in METADATA_COMMANDS],
                'profile_command': '0x8A00', 'returned_metadata_offset': 2,
                'returned_metadata_bytes': 4, 'returned_metadata_byte_order': 'little-endian',
                'returned_metadata_derivation': 'A17551..A175BC chooses interpretation by requested BX, bypasses command equality, and stores header[2:6] through caller metadata pointer. A5499D supplies shared+0x16.',
                'opaque_header_offset': 6, 'opaque_header_bytes': 4,
                'opaque_header_limit': 'No field extraction of bytes6..9 was found in the complete prior A170F8 receive window; no timestamp or sequence meaning assigned',
                'payload_offset': 12, 'payload_length_offset': 10,
                'payload_length_bytes': 2, 'payload_length_byte_order': 'little-endian',
                'consumer_max_payload_length': 49152,
                'length_guard': 'A17761 permits zero; A1776A rejects positive length above0xC000 with exception status0x108',
                'payload_derivation': 'A17A25..A17A36 copies declared payload unchanged; stripping an internal prefix is unsupported',
                'normal_marker_exclusion': 'Header bytes2..3 equal00FF take the error-envelope path before metadata interpretation',
            },
            'rx_error': {
                'marker_offset': 2, 'marker_hex': '00ff',
                'long_payload_echoed_command_offset': 0,
                'long_payload_error_status_offset': 2,
                'integer_bytes': 2, 'byte_order': 'little-endian',
                'echo_check': 'A1792A..A17954 compares echoed payload command with requested BX; mismatch raises0x26 atA179F8',
                'status_raise': 'A17A97..A17AB2 passes payload[2:4] as the exception status after echo validation',
                'exact_four_bytes_required_by_native_window': False,
                'safe_offline_projection_min_payload_bytes': 4,
                'short_payload_policy': 'Do not emulate native unchecked indexing; retain raw envelope and report insufficient error payload',
                'trailing_payload_policy': 'Preserve any bytes after the first four without assigning meaning',
                'not_a_bus_payload': True,
            },
            'integrity': 'CRC16 belongs to outer envelope; mismatch must remain visible. Algorithm and table are independently derived in AUTOCAL_TRANSPORT_STATIC.json.',
        },
        'corroborating_prior_observations': [
            {'evidence': 'VM_RETRY_HELPERS_STATIC.json', 'addresses': ['0x406EE4', '0x406FD8'],
             'observation': 'VM mode byte0x427648 equal1 selects requested command0x8A00 for send selector0x0B and receive selector0x0D. This is a host routing observation, not proof that every envelope reached the bus.'},
            {'evidence': 'VM_RETRY_HELPERS_STATIC.json', 'addresses': ['0x40702E', '0x407087', '0x40708A', '0x407129'],
             'observation': 'Metadata output and exception status use different callback pointers. Successful metadata is stored to VM0x42765A; separate status participates in receive flag handling. Returned metadata value0x10 is not thereby an ACK or success code.'},
            {'evidence': 'VM_CALLBACK_OUTCOMES_STATIC.json', 'addresses': ['0xBB06AB', '0xBB06B2'],
             'observation': 'Scan callback copies the metadata output unchanged through its caller pointer; raw exception status is a separate path.'},
        ],
        'unknowns': [
            'Meaning of individual returned metadata bits, including observed low bit0x10, remains unresolved.',
            'RX bytes6..9, source ownership, timing units and pairing semantics remain unassigned.',
            'A caller-supplied requested command context is not established merely by a nearby preceding TX record.',
            'Bus electrical transmission, adapter arbitration, speed transitions, filters and firmware behavior are not proven by these host envelopes.',
            'The whole0x8A00 payload must be retained. Any physical VPW CRC policy requires separate capture evidence.',
            'The prior VM/Scan reports are hash-pinned evidence references, not re-execution or fresh disassembly of those artifacts in this collection.',
            'Bounded linear disassembly is not a complete control-flow or reachability proof. Only the long-header profile is specified here.',
        ],
        'target_executed': False, 'adapter_opened': False,
        'vehicle_transmissions_enabled': False, 'live_write_enabled': False,
        'ready_to_flash': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hapi', type=Path, required=True)
    parser.add_argument('--dumpbin', type=Path, required=True)
    parser.add_argument('--docs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.hapi, args.dumpbin, args.docs)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'source_sha256': HAPI_SHA256, 'windows': len(WINDOWS),
                      'profile': 'requested command0x8A00', 'live_write_enabled': False}))


if __name__ == '__main__':
    main()
