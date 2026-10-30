"""Pin AutoCal V2 backend identity and connection-time host setup, file-only.

This bounded collector disassembles installed files without executing either
target or opening an adapter. It does not assign firmware semantics to 8800.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

import pefile

from inspect_autocal_transport import HAPI_SHA256
from inspect_autocal_setup_callback import SCAN_SHA256


WINDOWS = (
    ('scan', 'backend_query_and_cache', 0xBBA57C, 0xBBA5EA),
    ('scan', 'backend_query_return', 0xBBA613, 0xBBA648),
    ('scan', 'connection_refreshes_backend_cache', 0xBBC612, 0xBBC629),
    ('scan', 'conditional_8800_callback', 0xBB07F4, 0xBB088B),
    ('hapi', 'selector_first_dispatch', 0xA53E7D, 0xA53EA1),
    ('hapi', 'selector_second_dispatch', 0xA543B4, 0xA543D7),
    ('hapi', 'backend_selector_18_reply', 0xA548D1, 0xA548E3),
    ('hapi', 'backend_selection', 0xA13723, 0xA13798),
    ('hapi', 'connection_calls_compatibility_then_model', 0xA13858, 0xA138A4),
    ('hapi', 'compatibility_saved_timeout_and_first_8604', 0xA169EA, 0xA16A85),
    ('hapi', 'compatibility_short_header_fallback', 0xA16A96, 0xA16AFA),
    ('hapi', 'compatibility_fallback_failure', 0xA16B0B, 0xA16B25),
    ('hapi', 'compatibility_zero_8800', 0xA16B25, 0xA16B6C),
    ('hapi', 'compatibility_8800_exception_and_restore', 0xA16B7D, 0xA16BA4),
    ('hapi', 'request_then_receive', 0xA14022, 0xA14047),
    ('hapi', 'zero_metadata_request_wrapper', 0xA140A5, 0xA140C3),
    ('hapi', 'ipc_send_dispatch', 0xA548E3, 0xA5497E),
    ('hapi', 'ipc_receive_dispatch', 0xA5497E, 0xA549AB),
    ('hapi', 'receive_metadata_or_command_echo', 0xA17551, 0xA175F5),
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class Image:
    def __init__(self, path, expected_sha256):
        self.path = Path(path)
        self.raw = self.path.read_bytes()
        if digest(self.raw) != expected_sha256:
            raise ValueError(f'{self.path.name} identity differs; address profile cannot be reused')
        self.pe = pefile.PE(data=self.raw, fast_load=True)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase

    def location(self, va, count):
        if type(va) is not int or type(count) is not int or count <= 0:
            raise ValueError('A positive byte count and integer VA are required')
        rva = va - self.base
        for section in self.pe.sections:
            relative = rva - section.VirtualAddress
            if 0 <= relative and relative + count <= section.SizeOfRawData:
                offset = section.PointerToRawData + relative
                raw = self.raw[offset:offset + count]
                if len(raw) != count:
                    raise ValueError('Truncated source range')
                return {'va': hex(va), 'rva': hex(rva), 'file_offset': offset,
                        'bytes': count, 'sha256': digest(raw),
                        'section': section.Name.rstrip(b'\0').decode('ascii')}, raw
        raise ValueError('Range is not wholly backed by one PE section')


def decode_exception_descriptor(raw, va):
    """Decode only the pinned jump/count/type/handler layout, not RTTI matching."""
    if len(raw) != 17 or raw[0] != 0xE9:
        raise ValueError('Expected 17-byte descriptor beginning with relative jump')
    count, type_pointer, handler = struct.unpack_from('<III', raw, 5)
    if count != 1:
        raise ValueError('Only the pinned single-entry exception descriptor is supported')
    return {'runtime_jump_target': hex(va + 5 + struct.unpack_from('<i', raw, 1)[0]),
            'entry_count': count, 'type_pointer': hex(type_pointer), 'handler_va': hex(handler)}


def resolve_selector(selector, index_table, target_table, second_table):
    """Decode the two exact HAPI tables; caller must supply their full bytes."""
    if type(selector) is not int or not 3 <= selector <= 0x1C:
        raise ValueError('Selector is outside the bounded two-stage dispatch')
    if len(index_table) != 29 or not target_table or len(target_table) % 4 or len(second_table) != 27 * 4:
        raise ValueError('Dispatch table coverage is incomplete')
    index = index_table[selector]
    if (index + 1) * 4 > len(target_table):
        raise ValueError('First-stage dispatch index is outside supplied table')
    first = struct.unpack_from('<I', target_table, index * 4)[0]
    if first != 0xA542DC:
        raise ValueError('Selector does not enter the selected second-stage dispatcher')
    second_index = selector - 3
    target = struct.unpack_from('<I', second_table, second_index * 4)[0]
    return {'selector': hex(selector), 'first_index': index, 'first_target': hex(first),
            'second_index': second_index, 'final_target': hex(target)}


def inspect(hapi_path, scan_path, dumpbin_path):
    images = {'hapi': Image(hapi_path, HAPI_SHA256), 'scan': Image(scan_path, SCAN_SHA256)}
    dumpbin_path = Path(dumpbin_path)
    snapshots = [(dumpbin_path, dumpbin_path.read_bytes()), (Path(__file__), Path(__file__).read_bytes())]
    prior_evidence = []
    docs = Path(__file__).resolve().parents[2] / 'Docs' / 'AL5'
    for name in ('AUTOCAL_SETUP_RESPONSES_STATIC.json', 'AUTOCAL_VPW_TRANSPORT_STATIC.json',
                 'AUTOCAL_VM_SETUP_20261030.json'):
        path = docs / name
        raw = path.read_bytes()
        parsed = json.loads(raw)
        snapshots.append((path, raw))
        prior_evidence.append({'path': str(path), 'bytes': len(raw), 'sha256': digest(raw),
                               'schema': parsed['schema'],
                               'use': 'Retained common parser and VM callback interpretation; not fresh runtime evidence'})
    windows = []
    for key, role, start, end in WINDOWS:
        image = images[key]
        where, _ = image.location(start, end - start)
        lookahead, _ = image.location(start, end - start + 16)
        command = [str(dumpbin_path), '/disasm:nobytes', f'/range:{hex(start)},{hex(end + 15)}', str(image.path)]
        output = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
        lines = []
        for line in output.stdout.splitlines():
            match = re.match(r'\s+([0-9A-F]{8}):', line)
            if match and start <= int(match[1], 16) < end:
                lines.append(line.strip())
        if not lines or not lines[0].startswith(f'{start:08X}:'):
            raise ValueError('Disassembler did not begin at requested instruction boundary')
        windows.append({'image': key, 'role': role, 'source': where,
                        'end_exclusive_va': hex(end), 'lookahead_source': lookahead,
                        'command': command, 'instructions': lines})

    hapi = images['hapi']
    tables = []
    table_bytes = []
    for role, va, count in [('first_index', 0xA53EA1, 29), ('first_targets', 0xA53EBE, 4),
                            ('second_targets', 0xA543D7, 27 * 4)]:
        where, raw = hapi.location(va, count)
        table_bytes.append(raw)
        tables.append({'role': role, 'source': where, 'raw_hex': raw.hex(),
                       'coverage': 'Only first target entry is needed for the selected selectors' if role == 'first_targets' else 'Complete bounded table'})
    selectors = [resolve_selector(value, *table_bytes) for value in (0x0B, 0x0C, 0x0D, 0x18)]
    if [row['final_target'] for row in selectors] != ['0xa548e3'] * 3 + ['0xa548d1']:
        raise ValueError('Pinned selector destinations differ')

    descriptors = []
    for va, expected_handler in [(0xA16A85, 0xA16A96), (0xA16AFA, 0xA16B0B), (0xA16B6C, 0xA16B7D)]:
        where, raw = hapi.location(va, 17)
        decoded = decode_exception_descriptor(raw, va)
        if decoded != {'runtime_jump_target': '0x40b700', 'entry_count': 1,
                       'type_pointer': '0x425398', 'handler_va': hex(expected_handler)}:
            raise ValueError('Pinned exception descriptor differs')
        descriptors.append({'source': where, 'raw_hex': raw.hex(), **decoded})
    type_where, type_raw = hapi.location(0x425398, 36)
    name_where, name_raw = hapi.location(0x425520, 10)
    if struct.unpack_from('<I', type_raw, 32)[0] != 0x425520 or name_raw != b'\x09Exception':
        raise ValueError('Pinned exception type/name data differs')

    for key, image in images.items():
        if image.path.read_bytes() != image.raw:
            raise ValueError(f'{key} changed during collection')
    for path, raw in snapshots:
        if path.read_bytes() != raw:
            raise ValueError(f'Source changed during collection: {path}')
    return {
        'schema': 'autocal-backend-init-static-v1',
        'scope': 'Bounded native backend selection, compatibility setup, and IPC send/receive dispatch; file-only',
        'sources': {key: {'path': str(image.path.resolve()), 'bytes': len(image.raw), 'sha256': digest(image.raw)}
                    for key, image in images.items()},
        'disassembler': {'path': str(dumpbin_path.resolve()), 'sha256': digest(snapshots[0][1])},
        'generator_sha256': digest(snapshots[1][1]),
        'prior_evidence': prior_evidence,
        'input_stability': 'Target, disassembler and generator bytes checked before/after collection; no lock excludes transient replacement',
        'disassembly_windows': windows, 'dispatch_table_ranges': tables, 'resolved_selectors': selectors,
        'exception_descriptors': descriptors,
        'exception_type_metadata': {'source': type_where, 'raw_hex': type_raw.hex(),
                                    'name_source': name_where, 'name_raw_hex': name_raw.hex(),
                                    'name': 'Exception', 'class_matching_runtime_reimplemented': False},
        'derived_contract': {
            'backend_identity': {
                'evidence_kind': 'static_derivation',
                'scan_query': 'BBA57C invokes IPC selector18, copies the first returned byte to receiverword+7A, defaults to0 if absent, and returns that word.',
                'hapi_query': 'Selector18 resolves via the retained tables toA548D1, which copies hostbyte+56 to replypayload[0] and sets replylength1.',
                'selection': 'A13792 stores hostword+56=2 after the FTDI AD99A0 path. A1374E stores3 for the separate AD9AA4 backend.',
                'meaning': 'Scan receiver+7A carries HAPI backend type, not a VPW protocol number, physical speed, or controller model.',
                'autocal_v2_ftdi_backend_type': 2,
            },
            'conditional_vm_protocol_callback': {
                'entry': '0xBB07F4', 'guard_backend_type': 3, 'command': '0x8800',
                'payload_formula': 'BYTE(argument) || 00', 'host_timeout_argument_ms': 750,
                'ftdi_backend_2_sends_this_command': False,
                'skipped_result': -1,
                'implication': 'Do not add VM opcode90 payload0100 to AutoCal V2 FTDI initialization merely because the VM selects route1.',
                'limit': 'The separate VM evidence establishes opcode90 can update its routing globals even when this callback returns-1.',
            },
            'connection_compatibility': {
                'entry': '0xA169C8',
                'ordering': 'A13879 calls this helper before a further purge and modelqueryA15138. It can precede the later HTX read-session log.',
                'first_exchange': {'command': '0x8604', 'payload_hex': '00', 'payload_bytes': 1,
                                   'metadata': 0, 'logical_timeout_ms': 1500,
                                   'operations': ['purge', 'send', 'receive in8604 context', 'purge'],
                                   'normal_reply_payload_value_checked': False,
                                   'normal_reply_length_checked_by_caller': False},
                'fallback': {'condition': 'Caught Exception on first attempt and backendtype2',
                             'host_change': 'Set hostbyte+51=1 selecting the separate8-byte header profile; retry8604 payload00 at1500ms with surrounding purges.',
                             'success': 'Leaves+51 set; no payload-value check.',
                             'caught_failure': 'Clears+51; control still proceeds to zero8800.',
                             'enable_independent_short_header_fallback': False},
                'followup': {'command': '0x8800', 'payload_hex': '0000', 'payload_bytes': 2,
                             'metadata': 0, 'logical_timeout_ms': 500,
                             'operations': ['send', 'receive in8800 context'],
                             'normal_reply_payload_value_checked': False,
                             'normal_reply_length_checked_by_caller': False,
                             'caught_failure': 'A16B7D only calls exception cleanup40BAF0 and joins timeout restoration; it does not return an initialization-failed result.',
                             'firmware_meaning': None},
                'finally': 'A16B8F restores the saved logical host timeout.',
                'proof_limit': 'This is an observed native compatibility routine, not proof its commands are mandatory, enter VPW mode, succeed on current firmware, or produce electrical silence.',
            },
            'normal_long_setup_reply': {
                'commands': ['0x8604', '0x8800'], 'prefix_hex': '0152', 'header_bytes': 12,
                'command_echo_offset': 2, 'command_echo_byte_order': 'little-endian',
                'payload': 'Opaque; empty payload is a normal return, not an absent reply. No expected01,00, or other value is tested by the compatibility caller.',
                'outer_validation': 'The existing common parser requires length/CRC validity and treats00ff as an error marker, including raw status0.',
                'echo_evidence': 'Neither command is in the bypass list atA17551; both take command equality checksA175C7..A175EA.',
                'shared_parser_evidence': 'AUTOCAL_SETUP_RESPONSES_STATIC.json and AUTOCAL_VPW_TRANSPORT_STATIC.json',
                'firmware_success_proven_by_accepted_reply': False,
            },
            'ipc_operations': {
                '0x0B': {'send': True, 'receive': False},
                '0x0C': {'send': True, 'receive': True},
                '0x0D': {'send': False, 'receive': True},
                'derivation': 'A548E3 subtracts11 then compares unsigned16 against2 for send; A54987 subtracts12 then compares against2 for receive.',
                'receive_only_polls_by_sending_empty_8a00': False,
                'completion_limit': 'Successful host send does not establish a controller acknowledgement or distinct firmware bus-transmit completion.',
            },
            'receive_phase_boundary': {
                'finding': 'Receivecontext8A00 bypasses command equality and treats headerbytes2..5 as metadata. Setupcontexts require bytes2..3 to echo the requested command. The header alone is therefore not an unambiguous unsolicited-frame demultiplexer.',
                'implementation_implication': 'Serialize setup exchanges and raw VPW reads with explicit command context; preserve unexpected envelopes and fail on unresolved phase ambiguity rather than project stale setup data as VPW.',
                'universal_async_demultiplexing_proven': False,
            },
        },
        'unknowns': [
            'No firmware effect or electrical mode is assigned to connection-time8800 payload0000 or one-byte8604 payload00.',
            'The initial value of host+51 before the selected compatibility helper is not established by these bounded windows.',
            'The alternate backend3 is distinguished by its native path; its hardware product name is not inferred.',
            'Caught exception paths are pinned, but arbitrary native exception/runtime behavior is not reimplemented.',
            'Setup success, cold bus communication, 1x/4x speed behavior, asynchronous receive ordering, and safe programming remain physically unqualified.',
        ],
        'target_executed': False, 'adapter_opened': False, 'vehicle_transmissions_enabled': False,
        'live_write_enabled': False, 'ready_to_flash': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hapi', type=Path, required=True)
    parser.add_argument('--scan', type=Path, required=True)
    parser.add_argument('--dumpbin', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.hapi, args.scan, args.dumpbin)
    with args.output.open('x', encoding='utf8', newline='\n') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'windows': len(WINDOWS), 'backend_type': 2, 'adapter_opened': False}))


if __name__ == '__main__':
    main()
