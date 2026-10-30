"""Collect pinned, file-only evidence for the AutoCal adapter model query.

This does not load HAPI or FTDI libraries, open an adapter, or replay a request.
Only dumpbin is executed, to disassemble bounded ranges of the pinned HAPI file.
Private capture provenance is optional and is exported as hashes and offsets,
never as controller images or device serial numbers.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

import pefile

from checksum import crc16
from decode_trace_containers import decode, records, RECORD_BYTES
from inspect_autocal_transport import HAPI_SHA256


MODEL_REQUEST = bytes.fromhex('0154018207000000000000008177')
MODEL_PAYLOAD = b'ACV2\0'
READ_REPLY = bytes.fromhex('0152018200000100000005004143563200224819')
LICENSE_REPLY = bytes.fromhex('015201820000000000000500414356320026b419')
HEADER_SHA256 = 'cf2ad290c68137373b26629bf9feed6f4847f4e9e5cde4b980a212cebeb4ff6a'

# Inclusive byte ranges ending after complete instructions. These are bounded
# linear windows, not a claim of complete native or firmware control flow.
WINDOWS = (
    ('model_query_and_host_classification', 0xA15138, 0xA15210),
    ('model_property_label_caller', 0xA1523C, 0xA15292),
    ('string_response_conversion_normal_path', 0xA144CC, 0xA14573),
    ('empty_query_dispatch', 0xA13FB8, 0xA13FFE),
    ('query_forwarder', 0xA14074, 0xA1407D),
    ('send_defaults', 0xA16CB8, 0xA16CC5),
    ('literal_xor_loop', 0x6E5ACB, 0x6E5AF6),
    ('ftdi_character_function_binding', 0x6EC2CD, 0x6EC2E7),
    ('ftdi_character_argument_forwarding', 0x6ED7B4, 0x6ED83D),
    ('ftdi_setup_caller', 0x6EDBB8, 0x6EDC0A),
)

PRIVATE_PROOFS = (
    ('read12_htx',
     'LocalOnly/usb_capture_setup_20261030/e54_usb_read_01/crc_retained_E54_R.htx',
     '49e0b14e2e5deb3581baca6c00f8ac29e264e2006d999aa017e4c736c448987f'),
    ('license_check_only_htx',
     'LocalOnly/e54_write_license_check_20261030_01/20261030_025249_E54_W.htx',
     'a88c5cd0ec8ac3640c57e6efa3f03151cd1e7af6338444c58b87d9e8ffc423db'),
    ('usb_only_capture',
     'LocalOnly/autocal_usb_setup_20261030/autocal_usb_local_01/capture.pcap',
     '3c5ccaf8d8c661e56104faa9d138282e7f4be5f37fd7df763a66ef175911485f'),
    ('identity_receipt',
     'LocalOnly/autocal_identity_candidate_20261030/identity_candidate_receipt.json',
     '458efc52f81cbb4cb3ef9801a62ef02038af717e6487b6de91306984e579da73'),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def private_provenance(private_root):
    """Verify optional private evidence; never export unrelated record payloads."""
    result = []
    for role, relative, expected in PRIVATE_PROOFS:
        item = {'role': role, 'path_relative_to_checkout': relative,
                'expected_sha256': expected, 'checked_in_this_run': False}
        if private_root is None:
            result.append(item)
            continue
        source = (Path(private_root) / relative).read_bytes()
        if digest(source) != expected:
            raise ValueError(f'Private evidence identity differs: {role}')
        item.update({'checked_in_this_run': True, 'bytes': len(source),
                     'actual_sha256': digest(source)})
        if role.endswith('_htx'):
            decoded = decode(source)
            parsed = list(records(decoded))
            expected_reply = READ_REPLY if role == 'read12_htx' else LICENSE_REPLY
            selected = []
            for ordinal, channel, literal in ((8, 1, MODEL_REQUEST), (9, 2, expected_reply)):
                record = parsed[ordinal]
                if record['channel'] != channel or record['payload'] != literal:
                    raise ValueError('Pinned HTX identity exchange differs')
                selected.append({'record_ordinal_zero_based': ordinal,
                                 'record_decoded_offset': record['offset'],
                                 'wrapper_decoded_offset': record['offset'] + RECORD_BYTES,
                                 'wrapper_bytes': len(literal),
                                 'wrapper_sha256': digest(literal)})
            item.update({'decoded_sha256': digest(decoded), 'selected_records': selected})
        elif role == 'usb_only_capture':
            selected = []
            for ordinal, offset, value in ((313, 14129, MODEL_REQUEST),
                                            (317, 14317, b'\x31\x60' + READ_REPLY)):
                if source[offset:offset + len(value)] != value:
                    raise ValueError('Pinned USB identity exchange differs')
                selected.append({'pcap_record_ordinal_one_based_from_prior_parser': ordinal,
                                 'file_offset': offset, 'bytes': len(value),
                                 'sha256': digest(value)})
            item.update({'selected_file_slices': selected,
                         'verification_scope': 'Exact file slices; USBPcap transfer attribution comes from the prior private receipt'})
        result.append(item)
    return result


def inspect(hapi_path, dumpbin_path, ftdi_header_path, private_root=None):
    hapi_path, dumpbin_path = Path(hapi_path), Path(dumpbin_path)
    ftdi_header_path = Path(ftdi_header_path)
    source, disassembler = hapi_path.read_bytes(), dumpbin_path.read_bytes()
    if digest(source) != HAPI_SHA256:
        raise ValueError('HAPI identity differs; these static addresses must not be reused')
    header = ftdi_header_path.read_bytes()
    if digest(header) != HEADER_SHA256:
        raise ValueError('FTDI header identity differs; the recorded signature must not be reused')
    header_lines = header.decode('cp1252').splitlines()
    signature_start = next(index for index, line in enumerate(header_lines)
                           if 'FT_STATUS WINAPI FT_SetChars(' in line)
    signature = '\n'.join(header_lines[signature_start:signature_start + 7])
    for name in ('ftHandle', 'EventChar', 'EventCharEnabled', 'ErrorChar', 'ErrorCharEnabled'):
        if name not in signature:
            raise ValueError('FT_SetChars signature differs')
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
                        'section': section.Name.rstrip(b'\0').decode('ascii')}, data
        raise ValueError('Range not wholly backed by one PE section')

    disassembly = []
    for role, start, end in WINDOWS:
        where, _ = location(start, end - start + 1)
        command = [str(dumpbin_path), '/disasm:nobytes',
                   f'/range:{hex(start)},{hex(end)}', str(hapi_path)]
        completed = subprocess.run(command, check=True, capture_output=True,
                                   text=True, timeout=30)
        lines = [line.strip() for line in completed.stdout.splitlines()
                 if re.match(r'\s+[0-9A-F]{8}:', line)]
        if not lines or not lines[0].startswith(f'{start:08X}:'):
            raise ValueError('Disassembler did not start at requested address')
        disassembly.append({'role': role, 'source': where,
                            'inclusive_end_va': hex(end), 'command': command,
                            'instructions': lines})
    strings = []
    for va, expected in ((0xA15220, 'FSV2'), (0xA15234, 'ACV2')):
        where, data = location(va, 4)
        decoded = bytes(value ^ 0xA9 for value in data).decode('ascii')
        if decoded != expected:
            raise ValueError('Model-comparison literal differs')
        strings.append({'value': decoded, 'encoding': 'Byte XOR A9; native loop at0x6E5AD3',
                        'encoded_hex': data.hex(), 'source': where})
    for va, expected in ((0xA154C8, 'MODEL='), (0x6EC62C, 'FT_SetChars\0')):
        where, data = location(va, len(expected) * 2)
        if data.decode('utf-16le') != expected:
            raise ValueError('Native label or API-name literal differs')
        strings.append({'value': expected, 'encoding': 'UTF16LE', 'source': where})
    for frame, channel in ((MODEL_REQUEST, 1), (READ_REPLY, 2), (LICENSE_REPLY, 2)):
        size = int.from_bytes(frame[10:12], 'little')
        if len(frame) != size + 14 + (channel == 2):
            raise ValueError('Recorded identity wrapper length differs')
        if crc16(frame[:12 + size], 0) != int.from_bytes(frame[12 + size:14 + size], 'little'):
            raise ValueError('Recorded identity wrapper CRC differs')
    proofs = private_provenance(private_root)
    if hapi_path.read_bytes() != source or dumpbin_path.read_bytes() != disassembler:
        raise ValueError('Native input or disassembler changed during collection')
    if ftdi_header_path.read_bytes() != header:
        raise ValueError('FTDI header changed during collection')
    repo = Path(__file__).resolve().parents[2]
    return {
        'schema': 'autocal-model-query-static-v1',
        'scope': 'File-only model-query semantics and bounded FTDI event-character setup; no native target or adapter executed',
        'source': {'path': str(hapi_path.resolve()), 'bytes': len(source),
                   'sha256': HAPI_SHA256, 'preferred_image_base': hex(base)},
        'generator_sha256': digest(Path(__file__).read_bytes()),
        'disassembler': {'path': str(dumpbin_path.resolve()), 'sha256': digest(disassembler)},
        'ftdi_header': {'path': str(ftdi_header_path.resolve()), 'bytes': len(header),
                        'sha256': HEADER_SHA256, 'signature_first_line_one_based': signature_start + 1,
                        'signature': signature},
        'related_static_report': {'path': 'Docs/AL5/AUTOCAL_TRANSPORT_STATIC.json',
                                  'sha256': digest((repo / 'Docs/AL5/AUTOCAL_TRANSPORT_STATIC.json').read_bytes())},
        'disassembly_windows': disassembly, 'strings': strings,
        'model_query_derivation': [
            '0xA15163 loads DX=0x8201;0xA15169 calls the string-returning helper0xA144CC.',
            '0xA144CC forwards the route through0xA14074/0xA13FB8/0xA13FD0, using0xA16CB8 for send and0xA170DC for receive.',
            '0xA13FB8 initializes the request buffer pointer to zero;0xA16CB8 supplies two zero defaults to0xA16CC8.',
            '0xA15138 compares the returned string with decoded FSV2 and ACV2, setting host object+1E to2 or7 respectively.',
            'Caller0xA1523C invokes0xA15138 at0xA15273 and prefixes its returned string with MODEL=.',
            'These call-site uses establish intended adapter-model query semantics for route bytes0182 (LE16 word0x8201), beyond adapter-local route classification.'],
        'recorded_minimal_exchange': {
            'request_hex': MODEL_REQUEST.hex(), 'request_bytes': len(MODEL_REQUEST),
            'request_sha256': digest(MODEL_REQUEST), 'route_bytes_hex': '0182',
            'route_word_le16': 0x8201, 'declared_request_payload_bytes': 0,
            'expected_model_payload_hex': MODEL_PAYLOAD.hex(),
            'recorded_read12_reply_hex': READ_REPLY.hex(),
            'recorded_license_check_reply_hex': LICENSE_REPLY.hex(),
            'outer_crc_verified': True,
            'framing_domain': 'Long host-interface wrapper; exact request and read12 reply also corroborated by saved USB-only capture',
            'response_validation_limit': 'Metadata4:10 varies; an exact full-response literal is not a general acceptance rule'},
        'ftdi_event_character_derivation': [
            '0x6EC2CD names FT_SetChars;0x6EC2DD stores its function pointer at host object+40h.',
            '0x6EDBB8 setup passes CL=19h and stack values1,0,0 to helper0x6ED7B4.',
            '0x6ED7B4 stores CL, obtains a device handle, pushes ErrorCharEnabled, ErrorChar, EventCharEnabled, EventChar and handle, then calls object+40h at0x6ED83B.',
            'The bundled FT_SetChars declaration therefore supports EventChar=0x19, EventCharEnabled=1, ErrorChar=0, ErrorCharEnabled=0 for this setup path.',
            'The same byte19 follows recorded RX CRCs, but that correspondence does not independently establish firmware marker semantics or whether all future replies require it.'],
        'private_corroboration': proofs,
        'observations_and_unknowns': [
            'Static caller evidence establishes the intended query purpose; AutoCal firmware-internal side effects and persistence are not proven absent.',
            'The complete native model helper calls0xA14CC0 afterward; executing that helper would not be equivalent to sending this single model query.',
            'Native send can initialize a disconnected host object; direct D2XX open/configure/request requirements and exclusivity remain separately unqualified.',
            'This event-character derivation does not establish the complete USB initialization sequence or serial baud/data/flow settings.',
            'Opaque metadata fields and the RX trailing byte have no assigned sequence, status, or firmware framing semantics.',
            'The private USB capture came from a user-confirmed USB-only AutoCal; per-UI-action attribution is not established by these byte slices.',
            'Linear windows preserve bounded instructions, not full control-flow coverage or runtime reachability.',
            'Private sources and binaries remain local; the public report contains bounded disassembly, identity literals, hashes and offsets only.'],
        'target_executed': False, 'adapter_opened': False, 'request_replayed': False,
        'vehicle_transmissions_enabled': False, 'live_write_enabled': False,
        'ready_to_flash': False, 'would_send': [],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hapi', type=Path, required=True)
    parser.add_argument('--dumpbin', type=Path, required=True)
    parser.add_argument('--ftdi-header', type=Path, required=True)
    parser.add_argument('--private-root', type=Path,
                        help='Optionally recheck the four pinned LocalOnly sources under this checkout')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError('Refusing to replace an existing evidence report')
    result = inspect(args.hapi, args.dumpbin, args.ftdi_header, args.private_root)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'source_sha256': HAPI_SHA256, 'windows': len(WINDOWS),
                      'private_sources_checked': sum(p['checked_in_this_run'] for p in result['private_corroboration']),
                      'model_query_semantics_supported': True, 'adapter_opened': False,
                      'live_write_enabled': False}))


if __name__ == '__main__':
    main()
