"""Pin static AutoCal host-transport evidence; never load the inspected DLL/EXE.

Addresses are specific to the recorded HAPI SHA-256. dumpbin disassembles file
bytes only. Linear windows do not establish runtime reachability or coverage.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

import pefile


HAPI_SHA256 = 'c51bbf4795c2ee0ac54b95114e1d5ae509d7f53d35a160b35115085f444fbcf8'
WINDOWS = [
    ('crc16_loop', 0x6E2A64, 0x6E2A99),
    ('ftdi_library_and_function_binding', 0x6EC1A7, 0x6EC3BA),
    ('send_envelope_and_crc', 0xA16DE4, 0xA16ECF),
    ('send_backend_dispatch', 0xA16F49, 0xA16FBD),
    ('ftdi_partial_write_loop', 0x6EE137, 0x6EE222),
    ('receive_header', 0xA174C4, 0xA1751A),
    ('receive_crc_and_trailer', 0xA177F2, 0xA17880),
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def reflected_table(poly):
    result = []
    for value in range(256):
        for _ in range(8):
            value = (value >> 1) ^ poly if value & 1 else value >> 1
        result.append(value)
    return result


def inspect(hapi_path, dumpbin_path):
    source = hapi_path.read_bytes()
    if digest(source) != HAPI_SHA256:
        raise ValueError('HAPI identity differs; these static addresses must not be reused')
    disassembler = dumpbin_path.read_bytes()
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

    table_location, table_bytes = location(0xAD2CE4, 512)
    table = list(struct.unpack('<256H', table_bytes))
    generated = reflected_table(0xA001)
    if table != generated:
        raise ValueError('Observed CRC table differs from the proposed recurrence')
    disassembly = []
    for role, start, end in WINDOWS:
        where, _ = location(start, end - start + 1)
        command = [str(dumpbin_path), '/disasm:nobytes',
                   f'/range:{hex(start)},{hex(end)}', str(hapi_path)]
        result = subprocess.run(command, check=True, capture_output=True,
                                text=True, timeout=30)
        lines = [line.strip() for line in result.stdout.splitlines()
                 if re.match(r'\s+[0-9A-F]{8}:', line)]
        if not lines or not lines[0].startswith(f'{start:08X}:'):
            raise ValueError('Disassembler did not start at requested address')
        disassembly.append({'role': role, 'start': where,
                            'last_instruction_address_bound': hex(end),
                            'command': command, 'instructions': lines})
    strings = []
    for va, expected in [(0x6EC4B8, 'ftd2xx.dll'), (0x6EC66C, 'FT_Read'),
                         (0x6EC67C, 'FT_Write'), (0x6EC644, 'FT_OpenEx')]:
        where, data = location(va, (len(expected) + 1) * 2)
        if data != (expected + '\0').encode('utf-16le'):
            raise ValueError('Transport import name differs')
        strings.append({'value': expected, 'location': where})
    if hapi_path.read_bytes() != source:
        raise ValueError('HAPI source changed during collection')
    if dumpbin_path.read_bytes() != disassembler:
        raise ValueError('Disassembler changed during collection')
    return {
        'schema': 'autocal-host-transport-static-v1',
        'scope': 'Pinned file-only native analysis; no target code or device executed',
        'source': {'path': str(hapi_path.resolve()), 'bytes': len(source),
                   'sha256': HAPI_SHA256, 'preferred_image_base': hex(base)},
        'generator_sha256': digest(Path(__file__).read_bytes()),
        'disassembler': {'path': str(dumpbin_path.resolve()),
                         'sha256': digest(disassembler)},
        'input_stability': 'HAPI and disassembler bytes compared before and after collection; files are not locked against transient replacement',
        'strings': strings, 'disassembly_windows': disassembly,
        'crc_derivation': {
            'kind': 'derived from native loop, complete table and caller initial state',
            'table': table_location, 'matching_entries': 256,
            'reflected_polynomial': '0xA001', 'initial_value': 0,
            'final_xor': 0, 'stored_byte_order': 'little-endian',
            'update': 'crc = table[(crc ^ byte) & 255] ^ (crc >> 8)',
            'tx_coverage': 'header plus declared payload, excluding CRC',
            'rx_coverage': 'header plus declared payload, excluding CRC and final byte',
            'scope_limit': 'Outer host envelope only; not VPW CRC or calibration checksum'},
        'transport_derivation': [
            '0x6EC1AB passes ftd2xx.dll to loader thunk 0x41C7C4.',
            '0x6EC31E resolves FT_Read and 0x6EC32E stores function pointer at object+0x4C.',
            '0x6EC339 resolves FT_Write and 0x6EC349 stores function pointer at object+0x50.',
            'HAPI branch2 at 0xA16F9E calls 0x6EE0B8, whose 0x6EE1EA calls object+0x50.',
            'Write loop advances the buffer and reduces remaining length by actual reported bytes.',
            'HAPI receive reads 01 then52, the remaining header, declared payload, and three trailer bytes.',
            '0xA17821 computes CRC from initial zero; 0xA1787C compares it with received LE16.'],
        'unknowns': [
            'This static collector does not evaluate independent USB captures; see AUTOCAL_USB_LOCAL_20261030.json and AUTOCAL_DIRECT_MODEL_20261030.json for separate runtime evidence.',
            'Raw VPW initialization, filter/speed commands and firmware authorization boundaries remain unresolved.',
            'The meaning and validation of the final received byte remain unresolved.',
            'Both 8-byte and 12-byte header branches exist; only 12-byte recorded frames are implemented.',
            'FTDI function binding is static evidence, not proof of a current live device handle.',
            'Linear disassembly is bounded and may end at a partial instruction; it is not a full control-flow graph.'],
        'target_executed': False, 'adapter_opened': False,
        'vehicle_transmissions_enabled': False, 'live_write_enabled': False,
        'ready_to_flash': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hapi', type=Path, required=True)
    parser.add_argument('--dumpbin', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.hapi, args.dumpbin)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'source_sha256': HAPI_SHA256,
                      'crc_table_entries_matched': 256,
                      'windows': len(WINDOWS), 'live_write_enabled': False}))


if __name__ == '__main__':
    main()
