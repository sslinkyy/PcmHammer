"""Find source-bound Delphi method-address candidates without loading PCCS.

This reads one PE32 file. It does not execute code, open a transport, or infer
controller compatibility. A method descriptor is an analysis anchor, not proof
that the provider has discovered a complete function at its encoded address.
"""
import argparse
import hashlib
import json
import re
import struct
from collections import Counter
from pathlib import Path

DEFAULT_NAMES = ('EraseFlash', 'EraseButtonClick', 'WriteCalClick',
                 'WriteCalErasePO1Click', 'RecoverandErasePO1Click',
                 'UtilityFileViewer1Click')


def executable_sections(data):
    """Return checked file-backed executable mappings for an x86 PE32."""
    if len(data) < 64 or data[:2] != b'MZ':
        raise ValueError('not a complete DOS/PE header')
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    if pe + 24 > len(data) or data[pe:pe+4] != b'PE\0\0':
        raise ValueError('invalid PE signature or header boundary')
    machine, count = struct.unpack_from('<HH', data, pe+4)
    optional_bytes = struct.unpack_from('<H', data, pe+20)[0]
    optional = pe+24
    if machine != 0x14c or optional_bytes < 32:
        raise ValueError('only x86 PE32 mappings are supported')
    section_table = optional+optional_bytes
    if section_table+count*40 > len(data):
        raise ValueError('truncated optional header or section table')
    if struct.unpack_from('<H', data, optional)[0] != 0x10b:
        raise ValueError('only PE32 optional headers are supported')
    base = struct.unpack_from('<I', data, optional+28)[0]
    sections = []
    for index in range(count):
        offset = section_table+index*40
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from('<IIII', data, offset+8)
        flags = struct.unpack_from('<I', data, offset+36)[0]
        if raw_offset+raw_size > len(data):
            raise ValueError('section raw bytes extend beyond file')
        if base+rva+max(virtual_size, raw_size) > 0x100000000:
            raise ValueError('section mapping exceeds 32-bit address space')
        if flags & 0x20000000 and raw_size:
            sections.append({'section_index': index, 'va': base+rva,
                             'raw_offset': raw_offset, 'raw_bytes': raw_size})
    return sections


def inspect_bytes(data, names=DEFAULT_NAMES):
    sections = executable_sections(data)
    requested_names = list(names)
    candidates = []
    rejected = Counter()
    for name in dict.fromkeys(requested_names):
        try:
            encoded = name.encode('ascii')
        except UnicodeEncodeError as error:
            raise ValueError('method names must be ASCII') from error
        if not 1 <= len(encoded) <= 255:
            raise ValueError('Delphi short-string name length must be 1..255')
        for match in re.finditer(re.escape(encoded), data):
            name_offset = match.start()
            if name_offset < 7 or data[name_offset-1] != len(encoded):
                rejected['no_length_prefixed_name'] += 1
                continue
            record_offset = name_offset-7
            record_bytes, address = struct.unpack_from('<HI', data, record_offset)
            if record_bytes < 7+len(encoded) or record_offset+record_bytes > len(data):
                rejected['invalid_descriptor_boundary'] += 1
                continue
            mappings = [s for s in sections if s['va'] <= address < s['va']+s['raw_bytes']]
            if len(mappings) != 1:
                rejected['address_unmapped_or_ambiguous'] += 1
                continue
            mapping = mappings[0]
            candidates.append({'name': name, 'descriptor_offset': record_offset,
                               'descriptor_bytes': record_bytes,
                               'extended_descriptor': record_bytes != 7+len(encoded),
                               'name_offset': name_offset, 'address': address,
                               'code_file_offset': mapping['raw_offset']+address-mapping['va'],
                               'section_index': mapping['section_index'],
                               'provider_function_verified': False})
    return {'source_bytes': len(data), 'source_sha256': hashlib.sha256(data).hexdigest(),
            'requested_names': requested_names,
            'executable_sections': sections,
            'candidates': sorted(candidates, key=lambda c: (c['address'], c['descriptor_offset'])),
            'rejected_match_counts': dict(rejected),
            'scope': 'raw Delphi descriptor candidates in one PE32; no target execution',
            'controller_compatibility': None, 'live_write_enabled': False,
            'ready_to_flash': False, 'would_send': []}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('exe', type=Path)
    parser.add_argument('--name', action='append', help='exact ASCII method name; repeatable')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.exe.resolve() == args.output.resolve():
        parser.error('output must not overwrite the source executable')
    result = inspect_bytes(args.exe.read_bytes(), args.name or DEFAULT_NAMES)
    result['source_path'] = str(args.exe.resolve())
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'candidates': len(result['candidates']),
                      'source_sha256': result['source_sha256'],
                      'ready_to_flash': False}))
