"""Inspect AL5 VM object framing without callbacks, object execution or transport."""
import argparse
import json
from pathlib import Path
import re
import struct
from al5_segment import sha256

NAME = re.compile(r'AL5_[RFLW]\.obj', re.I)
HEADER_BYTES = 16
CODE_PREAMBLE_BYTES = 42
CODE_CAPACITY = 0x2E00
DATA_CAPACITY = 0x3E00


def inspect_bytes(data, name):
    if not NAME.fullmatch(name):
        raise ValueError('explicit installed AL5 R/F/L/W object required')
    if not HEADER_BYTES <= len(data) <= CODE_CAPACITY + DATA_CAPACITY:
        raise ValueError('object size outside observed VM section capacities')
    words = struct.unpack_from('<8H', data)
    code_offset, code_size, data_offset, data_size = words[1:5]
    # Deliberately stricter than the native clamping reader. Never silently
    # truncate oversized declarations or accept unseen layout variants.
    if code_offset != 0 or not CODE_PREAMBLE_BYTES <= code_size <= CODE_CAPACITY:
        raise ValueError('unsupported code-section offset or capacity')
    if not 0 < data_size <= DATA_CAPACITY:
        raise ValueError('unsupported data-section capacity')
    if data_offset != code_size or data_offset + data_size != len(data):
        raise ValueError('sections overlap, have gaps, are truncated or leave trailing bytes')
    if (code_size - CODE_PREAMBLE_BYTES) % 4 or data_size % 4:
        raise ValueError('local word transform requires four-byte section alignment')
    sections = []
    for label, start, end in [('code_transform_input', CODE_PREAMBLE_BYTES, code_size),
                              ('data_transform_input', data_offset, data_offset + data_size)]:
        sections.append({'role': label, 'file_offset': start, 'end_exclusive': end,
                         'bytes': end - start, 'source_sha256': sha256(data[start:end])})
    return {'source_name': name, 'source_sha256': sha256(data), 'bytes': len(data),
            'header_words_le16': list(words), 'uninterpreted_header_word_indices': [0, 5, 6, 7],
            'code_offset': code_offset, 'code_section_bytes': code_size,
            'data_offset': data_offset, 'data_section_bytes': data_size,
            'code_preamble_bytes': CODE_PREAMBLE_BYTES, 'sections': sections,
            'layout_matches_observed_reader_profile': True,
            'callback_transform_reproduced': False, 'object_contents_decoded': False,
            'object_crc_verified': False, 'object_executed': False}


def report(paths):
    objects = []
    for path in paths:
        path = Path(path)
        if not HEADER_BYTES <= path.stat().st_size <= CODE_CAPACITY + DATA_CAPACITY:
            raise ValueError('object size outside observed VM section capacities')
        objects.append(inspect_bytes(path.read_bytes(), path.name))
    if not objects:
        raise ValueError('at least one object required')
    return {'schema_version': 1, 'generator_sha256': sha256(Path(__file__).read_bytes()),
            'scope': 'File-only section framing derived from EFILive_VM.dll vmLoad. No proprietary object execution, callbacks, hardware or packets.',
            'limits': 'Framing is not content decoding. Native loader invokes host-supplied callbacks around section transforms and CRC validation; their implementation and effects are unresolved. Unknown header words retain source values.',
            'static_evidence': 'Docs/AL5/EFILIVE_VM_OBJECT_LOADING.json',
            'object_count': len(objects), 'objects': objects,
            'write_protocol_verified': False, 'physical_recovery_verified': False,
            'ready_to_flash': False, 'live_write_enabled': False,
            'erase_scope': None, 'would_send': [], 'erase_packets': [], 'program_packets': []}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--object', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if any(args.output.resolve() == path.resolve() for path in args.object):
        parser.error('output must not overwrite an input object')
    result = report(args.object)
    with args.output.open('x', encoding='utf8') as output:
        output.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'objects': result['object_count'], 'object_contents_decoded': False,
                      'ready_to_flash': False}))
