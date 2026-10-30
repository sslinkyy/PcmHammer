"""Replay one pinned E54 read object's saved transforms and inspect setup operands.

No object/VM callbacks execute. This is a separate, exact E54_R research profile;
the existing AL5 object/reconstruction admission rules remain unchanged.
"""
import argparse
import json
from pathlib import Path
import re
import struct
import subprocess

import pefile
from al5_segment import sha256
from audit_trace_wrappers import framed_message
from checksum import crc16
from decode_trace_containers import decode, records
from inspect_vm_flow import analyze_buffers
from replay_object_transform import local_transform
from validate_vm_buffers import inspect_buffers, read_bounded

OBJECT_SHA = '31f167ba34c13490675b2776f2a18b4472fa8fdf564d8c526ca79fbb0804d7e6'
TRACE_SHA = '49e0b14e2e5deb3581baca6c00f8ac29e264e2006d999aa017e4c736c448987f'
VM_SHA = '132832f80d7e5b642033fafc35df4ff3c0f3b19371081d23eacf696c4019ac00'
WINDOWS = (
    ('fourth_descriptor_dispatch', 0x4041B6, 0x4041D6),
    ('fourth_descriptor_high_opcode_dispatch', 0x404251, 0x404264),
    ('opcode99_dispatch', 0x404383, 0x40438D),
    ('opcode99_resolved_argument_callback', 0x4074DC, 0x407528),
    ('opcode93_dispatch', 0x4042F4, 0x4042FE),
    ('opcode93_byte_arguments_and_8b01_callback', 0x407350, 0x4073C1),
    ('opcode90_callback_then_unchecked_vm_route_store', 0x40392F, 0x403963),
    ('callback_table_slot_registration', 0x40B2AC, 0x40B312),
    ('special_reference_ff04', 0x4044A8, 0x4044DE),
)


def setup_payload_observations(first_byte, interval_word, third_dword, fourth_dword):
    """Model the proven callback byte layout for VM-width scalar arguments only."""
    for value, maximum in ((first_byte, 255), (interval_word, 65535),
                           (third_dword, 0xFFFFFFFF), (fourth_dword, 0xFFFFFFFF)):
        if type(value) is not int or not 0 <= value <= maximum:
            raise ValueError('Argument outside explicit VM byte/word/DWORD profile')
    result = []
    if interval_word:
        result.append({'command_le16': 0x8603,
                       'payload_hex': struct.pack('<HH', interval_word // 1000, interval_word % 1000).hex(),
                       'callback_argument4': 100})
    result.append({'command_le16': 0x8604,
                   'payload_hex': bytes((first_byte, third_dword & 255)).hex() + struct.pack('<I', fourth_dword).hex(),
                   'callback_argument4': 2000 if first_byte == 6 else 1000})
    return result


def cleanup_payload_observations(values):
    """Opcode93's four low bytes; no firmware filter or success meaning assigned."""
    if len(values) != 4 or any(type(v) is not int or not 0 <= v <= 0xFFFFFFFF for v in values):
        raise ValueError('Four resolved DWORD values required')
    return [{'command_le16': 0x8B01, 'payload_hex': bytes(v & 255 for v in values).hex(),
             'callback_argument4': 100}]


def replay_sections(parsed, obj, sections):
    """Bind every selected transform TX to source bytes in explicit section order."""
    exchanges = []
    for ordinal, row in enumerate(parsed):
        w = row['payload']
        if row['kind'] != 0x42 or w[2:4] not in (b'\x14\x84', b'\x15\x84'):
            continue
        framed = framed_message(row)
        if framed is None:
            raise ValueError('Malformed transform envelope')
        end = 12 + len(framed[1])
        if crc16(w[:end], 0) != int.from_bytes(w[end:end + 2], 'little'):
            raise ValueError('Invalid transform envelope CRC')
        exchanges.append((ordinal, row['offset'], int.from_bytes(w[2:4], 'little'), framed[0], framed[1]))
    cursor, stages, buffers = 0, [], []

    def pair(command, expected, section):
        nonlocal cursor
        if cursor + 2 > len(exchanges):
            raise ValueError('Missing transform exchange')
        tx, rx = exchanges[cursor:cursor + 2]
        cursor += 2
        if tx[2:4] != (command, 'host_tx_candidate') or rx[2:4] != (command, 'device_rx_candidate'):
            raise ValueError('Reordered or ambiguous transform exchange')
        if tx[4] != expected:
            raise ValueError('Transform request differs from exact object section')
        stages.append({'section': section, 'command_le16': command,
                       'tx_record': tx[0], 'rx_record': rx[0], 'tx_offset': tx[1], 'rx_offset': rx[1],
                       'tx_bytes': len(tx[4]), 'rx_bytes': len(rx[4]),
                       'tx_sha256': sha256(tx[4]), 'rx_sha256': sha256(rx[4])})
        return rx[4]

    for label, selector, start, end in sections:
        if cursor >= len(exchanges):
            raise ValueError('Missing transform section initialization')
        initial = exchanges[cursor][4]
        if len(initial) != 34 or initial[:2] != bytes((selector, 0)):
            raise ValueError('Unsupported section initializer')
        if pair(0x8414, initial, label) != b'\x01':
            raise ValueError('Initializer differs from witnessed one-byte reply')
        chunks = []
        for offset in range(start, end, 4096):
            expected = obj[offset:min(offset + 4096, end)]
            reply = pair(0x8415, expected, label)
            if len(reply) != len(expected):
                raise ValueError('Transform reply length differs from request')
            chunks.append(local_transform(reply))
        buffers.append(b''.join(chunks))
    if cursor != len(exchanges):
        raise ValueError('Unassociated extra transform exchanges')
    return buffers, stages


def inspect(trace, object_path, vm_path, dumpbin, docs):
    trace, object_path, vm_path, dumpbin, docs = map(Path, (trace, object_path, vm_path, dumpbin, docs))
    source = read_bounded(trace, 1, 16 * 1024 * 1024)
    obj = read_bounded(object_path, 16, 0x6C00)
    vm = read_bounded(vm_path, 1, 1024 * 1024)
    if object_path.name.lower() != 'e54_r.obj' or sha256(obj) != OBJECT_SHA or sha256(source) != TRACE_SHA or sha256(vm) != VM_SHA:
        raise ValueError('Exact E54 read trace, object and VM identities required')
    helper_names = ('inspect_vm_flow.py', 'replay_object_transform.py', 'validate_vm_buffers.py',
                    'inspect_vm_objects.py', 'audit_trace_wrappers.py', 'checksum.py', 'decode_trace_containers.py', 'al5_segment.py')
    snapshots = [(trace, source), (object_path, obj), (vm_path, vm), (dumpbin, dumpbin.read_bytes()),
                 (Path(__file__), Path(__file__).read_bytes())]
    snapshots += [(Path(__file__).with_name(n), Path(__file__).with_name(n).read_bytes()) for n in helper_names]
    evidence_names = ('EFILIVE_VM_DISPATCH.json', 'AUTOCAL_SETUP_CALLBACK_STATIC.json')
    snapshots += [(docs / n, (docs / n).read_bytes()) for n in evidence_names]
    parsed = list(records(decode(source)))
    words = struct.unpack_from('<8H', obj)
    if words != (55755, 0, 9674, 9674, 10816, 10282, 10184, 176):
        raise ValueError('Pinned object header changed')
    buffers, stages = replay_sections(parsed, obj, [('code', 12, 42, 9674), ('data', 13, 9674, len(obj))])
    code, data = obj[:42] + buffers[0], buffers[1]
    validation = inspect_buffers(code, data, sha256(code), sha256(data))
    if not validation['supplied_buffer_crc_matches']:
        raise ValueError('Reconstructed VM CRC differs')
    flow = analyze_buffers(code, data, words)
    nodes = flow['structural_instructions']
    setup_nodes = [n for n in nodes if n['opcode'] == 0x99]
    cleanup_nodes = [n for n in nodes if n['opcode'] == 0x93]
    references = [n for n in nodes if any(a['tag'] == 0xA0 and a.get('value') in (0x2142, 0xFF04) for a in n['operands'])]
    pe = pefile.PE(data=vm, fast_load=True)

    def span(start, length):
        rva = start - pe.OPTIONAL_HEADER.ImageBase
        for s in pe.sections:
            rel = rva - s.VirtualAddress
            if 0 <= rel and rel + length <= s.SizeOfRawData:
                offset = s.PointerToRawData + rel
                return {'va': hex(start), 'file_offset': offset, 'bytes': length,
                        'sha256': sha256(vm[offset:offset + length])}
        raise ValueError('Native window is not wholly file-backed')

    windows = []
    for role, start, end in WINDOWS:
        loc = span(start, end - start)
        command = [str(dumpbin), '/disasm:nobytes', f'/range:{hex(start)},{hex(end + 15)}', str(vm_path)]
        text = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30).stdout
        lines = []
        for line in text.splitlines():
            m = re.match(r'\s+([0-9A-F]{8}):', line)
            if m and start <= int(m[1], 16) < end:
                lines.append(line.strip())
        if not lines or not lines[0].startswith(f'{start:08X}:'):
            raise ValueError('Disassembly boundary mismatch')
        windows.append({'role': role, 'source': loc, 'lookahead': span(start, end - start + 16),
                        'command': command, 'instructions': lines})
    table_cells = []
    for opcode, cell, target in ((0x99, 0x4042DC, 0x404383), (0x93, 0x4042C4, 0x4042F4)):
        table_offset = pe.get_offset_from_rva(cell - pe.OPTIONAL_HEADER.ImageBase)
        if int.from_bytes(vm[table_offset:table_offset + 4], 'little') != target:
            raise ValueError('Setup/cleanup opcode table target differs')
        table_cells.append({**span(cell, 4), 'opcode': opcode, 'target_va': hex(target)})
    cases = []
    for label, opcode, arguments in [('four_zero_arguments', 0x99, [0, 0, 0, 0]),
                                     ('recorded_read_form', 0x99, [1, 1500, 0, 16]),
                                     ('cleanup_first_form', 0x93, [0, 1, 0, 0]),
                                     ('cleanup_second_form', 0x93, [1, 1, 0, 0])]:
        observations = setup_payload_observations(*arguments) if opcode == 0x99 else cleanup_payload_observations(arguments)
        for event in observations:
            matches = []
            for ordinal, row in enumerate(parsed):
                if row['kind'] != 0x42 or row['channel'] != 1:
                    continue
                framed = framed_message(row)
                if framed and int.from_bytes(row['payload'][2:4], 'little') == event['command_le16'] and framed[1].hex() == event['payload_hex']:
                    end = 12 + len(framed[1])
                    if crc16(row['payload'][:end], 0) != int.from_bytes(row['payload'][end:end + 2], 'little'):
                        raise ValueError('Matching setup observation has invalid CRC')
                    matches.append({'record_ordinal': ordinal, 'decoded_record_offset': row['offset']})
            event['matching_saved_tx_records'] = matches
        cases.append({'label': label, 'opcode': opcode, 'supplied_scalar_arguments': arguments, 'payload_observations': observations,
                      'dynamic_vm_statement_attribution_proven': False, 'setup_success_proven': False})
    for path, raw in snapshots:
        if path.read_bytes() != raw:
            raise ValueError('Input or implementation changed during collection')
    return {'schema': 'autocal-e54-read-vm-setup-v1',
            'scope': 'Exact saved-reply E54_R reconstruction and structural/native setup bridge; no VM, host callback or adapter execution',
            'sources': [{'path': str(p.resolve()), 'bytes': len(b), 'sha256': sha256(b)} for p, b in snapshots],
            'reconstruction_stages': stages, 'validation': validation,
            'structural_instruction_count': len(nodes), 'entries': flow['entries'],
            'setup_opcode99_nodes': setup_nodes, 'cleanup_opcode93_nodes': cleanup_nodes,
            'selector_opcode90_nodes': [n for n in nodes if n['opcode'] == 0x90], 'setup_related_reference_nodes': references,
            'initial_code_descriptor_at_2142': {'offset': 0x2142, 'raw_hex': code[0x2142:0x2146].hex(), 'initial_word_value': 1500, 'runtime_value_proven': False},
            'native_windows': windows, 'opcode_table_cells': table_cells,
            'bridge': ['Opcode99 consumes four descriptors and reaches404383 then4074DC.',
                       '4074DC resolves each scalar, narrows arg1 to byte and arg2 to word, and invokes callback4398CC.',
                       'vmCallback copies caller table+2C to4398CC. The pinned Scan callback report binds that slot toBB0A14.',
                       'Opcode90 calls4398BC (table+1C, Scan BB07F4), then resolves its input again and writes4398B8/427648 without checking the callback return. Its VM route change is not proof that the conditional8800 exchange ran or configured hardware.',
                       'FF04 resolves to native descriptor427652. Initial code descriptor2142 contains1500; a structural copy at283C writes16 throughFF04.',
                       'Opcode93 reaches407350, packs four resolved low bytes, and invokes callback4398A0(selector0C, command8B01, length4, argument4=100) with null optional outputs. No returned-status test follows.',
                       'The two opcode93 nodes are at27EE and2800, within the structural host-error/cleanup region entered at27C8. Matching saved TX forms occur after the final data block; this does not identify firmware filter or speed effects.',
                       'The shown values reproduce saved setup payloads, but unmodeled calls and runtime state prevent proving a complete dynamic argument trace.'],
            'modeled_cases': cases,
            'limits': ['Transform replies are replayed from the exact saved file; independent firmware object transformation is not reproduced.',
                       'Strict transform pairing is file order and exact source-chunk association, not general wire request correlation.',
                       'Structural grouping does not establish full VM execution, reachability, retry behavior or all reference side effects.',
                       'Payload equality does not prove setup success, physical speed, filter meaning, or an initialization recipe.',
                       'The existing AL5 object profile is unchanged. This E54 read profile does not qualify AL5 programming or recovery.'],
            'adapter_opened': False, 'target_executed': False, 'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('trace', 'object', 'vm', 'dumpbin', 'docs', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.trace, args.object, args.vm, args.dumpbin, args.docs)
    with args.output.open('x', encoding='utf8', newline='\n') as stream:
        json.dump(result, stream, indent=2); stream.write('\n')
    print(json.dumps({'output': str(args.output), 'crc_matches': result['validation']['supplied_buffer_crc_matches'],
                      'setup_nodes': len(result['setup_opcode99_nodes']), 'live_write_enabled': False}))
