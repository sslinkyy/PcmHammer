"""Offline native V2 program-container layout; never loads firmware into a device.

Only dumpbin executes, against pinned file ranges. The layout function emits
offsets and digests, not firmware bytes, update packets or executable images.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess

import pefile
from al5_segment import sha256
from inspect_autocal_firmware_container import ARTIFACTS, framed_regions
from validate_vm_buffers import read_bounded


HAPI_SHA = 'c51bbf4795c2ee0ac54b95114e1d5ae509d7f53d35a160b35115085f444fbcf8'
DUMPBIN_SHA = '6ad86f7fa61936301fddafa97de7c8f0ac5c3cb225569dca68edfa021cce5919'
# Exclusive ends, selected instruction boundaries; exclude Delphi exception tables.
WINDOWS = (
    ('program_caller_loads_container_before_device_commands', 0xA1851A, 0xA18546),
    ('loader_file_stream_construction', 0x7ECC7A, 0x7ECC8E),
    ('file_stream_read_method', 0x4C8884, 0x4C8894),
    ('file_read_wrapper', 0x42E400, 0x42E42C),
    ('readfile_import_thunk', 0x41C82C, 0x41C832),
    ('loader_initialization_and_first_length', 0x7ECCC6, 0x7ECD2B),
    ('loader_first_region_allocation_and_read', 0x7ECD2B, 0x7ECD7E),
    ('loader_optional_8000_region_and_next_length', 0x7ECD7E, 0x7ECE20),
    ('loader_final_region_guard_and_read', 0x7ECE20, 0x7ECE8B),
    ('loader_release_and_total_length_return', 0x7ECE8B, 0x7ECEDA),
    ('transfer_chunk_size', 0xA195F1, 0xA19607),
    ('transfer_byte_copy_and_common_exchange', 0xA1966A, 0xA196B1),
)


def program_layout(source):
    """Strict complete positive-length profile of native 7ECC44's two branches.

    This is stronger than the inspected native stream path: it requires complete
    input consumption and never treats ignored stream read counts as evidence.
    It does not validate device model, checksum, codec or executable contents.
    """
    # Derived from first<=0x20000, optional middle=0x8000, final<=0x40000,
    # plus at most three four-byte lengths. Check before generic framing copies.
    if not isinstance(source, bytes) or not 0 < len(source) <= 0x6800C:
        raise ValueError('Input outside bounded native program-container extent')
    regions = framed_regions(source)
    if len(regions) not in (2, 3):
        raise ValueError('Program profile requires two regions or the optional middle region')
    if len(regions[0][1]) > 0x20000:
        raise ValueError('First region exceeds native 0x20000 guard')
    optional = len(regions[1][1]) == 0x8000
    if optional != (len(regions) == 3):
        raise ValueError('Native 0x8000 second length requires a following final region')
    if len(regions[-1][1]) > 0x40000:
        raise ValueError('Final region exceeds native 0x40000 guard')
    combined_offset, result = 0, []
    for ordinal, (offset, payload) in enumerate(regions):
        result.append({'region_ordinal': ordinal, 'length_field_file_offset': offset,
                       'payload_file_offset': offset + 4, 'payload_bytes': len(payload),
                       'concatenated_buffer_offset': combined_offset,
                       'payload_sha256': sha256(payload)})
        combined_offset += len(payload)
    return {'regions': result, 'concatenated_payload_bytes': combined_offset,
            'native_branch_value': 0x0E if optional else 0x0A,
            'optional_8000_middle_region_present': optional,
            'complete_file_consumption': True,
            'native_stream_short_read_behavior_emulated': False,
            'firmware_contents_validated': False, 'device_load_addresses_proven': False,
            'would_send': []}


def inspect(hapi, dumpbin, firmware_root):
    hapi, dumpbin, firmware_root = map(Path, (hapi, dumpbin, firmware_root))
    snapshots = {p: read_bounded(p, 1, 32 * 1024 * 1024) for p in (hapi, dumpbin)}
    if sha256(snapshots[hapi]) != HAPI_SHA or sha256(snapshots[dumpbin]) != DUMPBIN_SHA:
        raise ValueError('Exact native target and disassembler identities required')
    helpers = ('inspect_autocal_firmware_loader.py', 'inspect_autocal_firmware_container.py',
               'al5_segment.py', 'validate_vm_buffers.py')
    for name in helpers:
        p = Path(__file__).with_name(name); snapshots[p] = p.read_bytes()
    layouts = []
    for key in ('autocal_program', 'flashscan_program'):
        name, expected = ARTIFACTS[key]; p = firmware_root / name
        source = read_bounded(p, 1, 0x6800C)
        if sha256(source) != expected:
            raise ValueError('Exact installed program artifact required: ' + key)
        snapshots[p] = source
        layouts.append({'artifact': key, 'source': pin(p, source), **program_layout(source)})
    raw = snapshots[hapi]; pe = pefile.PE(data=raw, fast_load=True)

    def span(start, count):
        rva = start - pe.OPTIONAL_HEADER.ImageBase
        for section in pe.sections:
            relative = rva - section.VirtualAddress
            if 0 <= relative and relative + count <= section.SizeOfRawData:
                offset = section.PointerToRawData + relative
                return {'va': hex(start), 'file_offset': offset, 'bytes': count,
                        'sha256': sha256(raw[offset:offset + count])}
        raise ValueError('Native range is not wholly file-backed')

    bindings = []
    for address, expected in ((0x49CD54, 0x49CDAC), (0x49CD74, 0x49CE32),
                              (0x49CDAC + 0x18, 0x4C8884)):
        location = span(address, 4)
        value = int.from_bytes(raw[location['file_offset']:location['file_offset'] + 4], 'little')
        if value != expected:
            raise ValueError('Pinned file stream binding differs')
        bindings.append({**location, 'value_le32': hex(value)})
    class_name = span(0x49CE32, 12)
    if raw[class_name['file_offset']:class_name['file_offset'] + 12] != b'\x0bTFileStream':
        raise ValueError('Pinned stream class name differs')
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    imports = [{'dll': group.dll.decode('ascii'), 'name': item.name.decode('ascii'),
                'iat_va': hex(item.address)} for group in pe.DIRECTORY_ENTRY_IMPORT
               for item in group.imports if item.name and item.address == 0xAFD47C]
    if imports != [{'dll': 'kernel32.dll', 'name': 'ReadFile', 'iat_va': '0xafd47c'}]:
        raise ValueError('Pinned ReadFile import differs')

    windows = []
    for role, start, end in WINDOWS:
        location, lookahead = span(start, end - start), span(start, end - start + 16)
        command = [str(dumpbin), '/disasm:nobytes', f'/range:{hex(start)},{hex(end + 15)}', str(hapi)]
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
        lines = []
        for line in result.stdout.splitlines():
            match = re.match(r'\s+([0-9A-F]{8}):', line)
            if match and start <= int(match[1], 16) < end:
                lines.append(line.strip())
        if not lines or not lines[0].startswith(f'{start:08X}:'):
            raise ValueError('Disassembler did not start at the selected boundary')
        windows.append({'role': role, 'source': location, 'lookahead': lookahead,
                        'command': command, 'instructions': lines})
    for p, source in snapshots.items():
        if p.read_bytes() != source:
            raise ValueError('Input or implementation changed during collection')
    return {
        'schema': 'autocal-firmware-loader-static-v1',
        'scope': 'V2 adapter program containers only, not AL5 controller firmware or a firmware updater',
        'sources': [pin(p, b) for p, b in snapshots.items()], 'native_windows': windows,
        'stream_pointer_bindings': bindings, 'stream_class_name': {**class_name, 'value': 'TFileStream'},
        'read_import_binding': imports,
        'program_layouts': layouts,
        'observations': [
            'A1853E calls 7ECC44 with the selected filename before the following adapter-command path.',
            '7ECC44 reads four-byte native x86 lengths, then payloads into one concatenated array.',
            'The constructed class pointer resolves to TFileStream; its virtual read slot reaches 4C8884, then 42E400 and the kernel32!ReadFile import. This binds the file bytes without an intervening codec in the traced read path.',
            'The first length is checked against signed zero and 0x20000. A second length of exactly 0x8000 selects an optional middle region and branch value 0x0E; otherwise the branch value remains 0x0A.',
            'After an optional middle region, the next length is read. The final length is checked against signed zero and 0x40000. The return value is the sum of payload lengths, excluding length fields.',
            'The bounded loader contains no payload-decryption or decompression call. It does not check the return counts of the shown virtual stream reads or establish EOF after the final region.',
            'A19675..A19684 copies source bytes individually and unchanged into a transfer buffer at offset6, in chunks of at most256. A196A0 passes that buffer to the common exchange routine A14080.',
        ],
        'derivations': [
            'The two installed program containers match the optional-middle-region branch and all native size guards.',
            'The loader and chunk-copy stage do not yield a plaintext executable image for tracing VPW handlers. Their copied source bytes remain the opaque bytes already inventoried.',
            'The strict offline model rejects incomplete/trailing input and zero-length regions instead of relying on unverified native short-read or array-index behavior.',
        ],
        'unknowns': [
            'Whether later transport or device firmware transforms the copied bytes; the complete update path is outside this bounded trace.',
            'Compression/encryption format, architecture, executable entry point and loaded firmware memory map.',
            'Firmware implementations of 8603/8604/8B01 and physical VPW 1x/4x switching.',
            'Update permissions, device compatibility, flash completion and physical recovery; no updater is implemented or executed.',
        ],
        'adapter_opened': False, 'target_executed': False, 'firmware_update_enabled': False,
        'live_write_enabled': False, 'ready_to_flash': False, 'would_send': [],
    }


def pin(path, raw):
    return {'path': str(path.resolve()), 'bytes': len(raw), 'sha256': sha256(raw)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ('hapi', 'dumpbin', 'firmware-root', 'output'):
        parser.add_argument('--' + arg, type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists():
        raise FileExistsError('Preserve existing evidence; select a new output path')
    result = inspect(args.hapi, args.dumpbin, args.firmware_root)
    with args.output.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(result, stream, indent=2); stream.write('\n')
    print(json.dumps({'native_windows': len(WINDOWS), 'program_layouts': len(result['program_layouts']),
                      'target_executed': False, 'adapter_opened': False}))


if __name__ == '__main__':
    main()
