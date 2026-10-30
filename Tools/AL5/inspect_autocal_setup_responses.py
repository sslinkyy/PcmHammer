"""Collect file-only AutoCal setup-response acceptance and return evidence.

Reads pinned HAPI/Scan binaries and prior static reports. Runs only dumpbin on
bounded file ranges; never executes either target, opens an adapter, or sends
an IPC/USB/vehicle command. The report describes host acceptance, not firmware
success or a qualified physical speed transition.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

import pefile


SOURCE_HASHES = {
    'hapi': 'c51bbf4795c2ee0ac54b95114e1d5ae509d7f53d35a160b35115085f444fbcf8',
    'scan': '9d3aad921df7ac8848b7d7cdb82fea0fd7695070f1c4d1f6bf9f68f0a0f34a3a',
}
PRIOR_REPORTS = {
    'AUTOCAL_VPW_TRANSPORT_STATIC.json': 'd2551b0df3e646469abde42324872b3b3b17a8fe162cccc99bc95db78d738f74',
    'AUTOCAL_SETUP_CALLBACK_STATIC.json': '244511cb52211c2424614f42f6a0d320b846229b6be7c69409b00e5e7bba15b0',
    'AUTOCAL_VM_SETUP_20261030.json': '1af2b09f12257a8d375984cb1def62cbffd5b4a67b9c32d10fe581db73578a7b',
    'EFILIVE_HOST_IPC.json': '2d7846ea73bf723dccd0318cfa0ad440c1fbf814a07d6785549c013af466e4ae',
    'VM_CALLBACK_OUTCOMES_STATIC.json': '5c3ced60f7db271ac8d8e09cfbc5b5ea52be7053a8a554e029c626ab3713d3d7',
}
# Exclusive ends; instructions, rather than linear decoding through Delphi
# exception tables, establish all starts. The collector excludes lookahead.
WINDOWS = (
    ('hapi', 'exception_constructor_preserves_status', 0x7EC090, 0x7EC0D0),
    ('hapi', 'status_exception_raise', 0x7EC124, 0x7EC173),
    ('hapi', 'ipc_result_initial_zero', 0xA53CC2, 0xA53CCA),
    ('hapi', 'receive_length_and_ipc_buffer', 0xA549A6, 0xA549F1),
    ('hapi', 'ipc_typed_exception_status', 0xA54A27, 0xA54A5C),
    ('hapi', 'ipc_other_exception_status', 0xA54AA6, 0xA54AFB),
    ('hapi', 'receive_error_cleanup_and_reraise', 0xA17B24, 0xA17B5A),
    ('hapi', 'receive_normal_length_return', 0xA17BDA, 0xA17BE7),
    ('scan', 'ipc_wrapper_preserves_exchange_result', 0xBBC3B4, 0xBBC408),
    ('scan', 'ipc_result_copy_and_length', 0xBBC4ED, 0xBBC552),
    ('scan', 'ipc_exchange_length_return', 0xBBC579, 0xBBC585),
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def file_range(pe, raw, start, size):
    rva = start - pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        relative = rva - section.VirtualAddress
        if 0 <= relative and relative + size <= section.SizeOfRawData:
            offset = section.PointerToRawData + relative
            selected = raw[offset:offset + size]
            if len(selected) != size:
                raise ValueError('Truncated source range')
            return {'va': hex(start), 'rva': hex(rva), 'file_offset': offset,
                    'bytes': size, 'sha256': digest(selected),
                    'section': section.Name.rstrip(b'\0').decode('ascii')}
    raise ValueError('Disassembly range is not wholly file-backed')


def inspect(hapi_path, scan_path, dumpbin_path, docs_path):
    paths = {'hapi': Path(hapi_path), 'scan': Path(scan_path)}
    dumpbin_path, docs_path = Path(dumpbin_path), Path(docs_path)
    snapshots = {path: path.read_bytes() for path in
                 (*paths.values(), dumpbin_path, Path(__file__),
                  *(docs_path / name for name in PRIOR_REPORTS))}
    for key, path in paths.items():
        if digest(snapshots[path]) != SOURCE_HASHES[key]:
            raise ValueError(f'{key} identity differs; addresses cannot be reused')
    for name, expected in PRIOR_REPORTS.items():
        if digest(snapshots[docs_path / name]) != expected:
            raise ValueError(f'Prior evidence identity differs: {name}')
        json.loads(snapshots[docs_path / name])
    images = {key: pefile.PE(data=snapshots[path], fast_load=True)
              for key, path in paths.items()}
    windows = []
    for target, role, start, end in WINDOWS:
        raw, pe = snapshots[paths[target]], images[target]
        location = file_range(pe, raw, start, end - start)
        lookahead = file_range(pe, raw, start, end - start + 16)
        command = [str(dumpbin_path), '/disasm:nobytes',
                   f'/range:{hex(start)},{hex(end + 15)}', str(paths[target])]
        output = subprocess.run(command, check=True, capture_output=True,
                                text=True, timeout=30)
        lines = []
        for line in output.stdout.splitlines():
            match = re.match(r'\s+([0-9A-F]{8}):', line)
            if match and start <= int(match[1], 16) < end:
                lines.append(line.strip())
        if not lines or not lines[0].startswith(f'{start:08X}:'):
            raise ValueError('Disassembler did not start at requested boundary')
        windows.append({'target': target, 'role': role, 'source': location,
                        'end_exclusive_va': hex(end), 'lookahead_source': lookahead,
                        'command': command, 'instructions': lines})
    for path, raw in snapshots.items():
        if path.read_bytes() != raw:
            raise ValueError(f'Source changed during collection: {path}')
    return {
        'schema': 'autocal-setup-responses-static-v1',
        'scope': 'Long-header setup replies for explicit requested commands8603/8604/8800/8B01; host acceptance and return propagation only',
        'sources': {key: {'path': str(path.resolve()), 'sha256': digest(snapshots[path]),
                          'bytes': len(snapshots[path])} for key, path in paths.items()},
        'prior_evidence': [{'path': str((docs_path / name).resolve()), 'sha256': sha}
                           for name, sha in PRIOR_REPORTS.items()],
        'generator_sha256': digest(snapshots[Path(__file__)]),
        'disassembler': {'path': str(dumpbin_path.resolve()),
                         'sha256': digest(snapshots[dumpbin_path])},
        'input_stability': 'All targets, evidence, disassembler and generator bytes compared before and after; transient replacement is not prevented by locking',
        'disassembly_windows': windows,
        'derived_contract': {
            'requested_commands': ['0x8603', '0x8604', '0x8800', '0x8B01'],
            'context': 'Requested command is an explicit caller input; adjacency or payload shape alone does not prove pairing.',
            'ordinary_reply': {
                'prefix_hex': '0152', 'header_bytes': 12,
                'command_echo_offset': 2, 'command_echo_bytes': 2,
                'command_echo_byte_order': 'little-endian',
                'comparison': 'A17551..A175EA: none of these four requested commands is in the metadata bypass list; header[2:4] must equal the requested command.',
                'opaque_header_offset': 4, 'opaque_header_bytes': 6,
                'opaque_header_limit': 'No extraction of bytes4..9 for these commands was found in the complete pinned A170F8 receive routine; preserve all six without assigning status, speed or timestamp meaning.',
                'payload_length_offset': 10, 'payload_length_bytes': 2,
                'payload_length_byte_order': 'little-endian', 'payload_offset': 12,
                'accepted_payload_length_min': 0, 'accepted_payload_length_max': 49152,
                'length_evidence': 'A17761 allows zero; A1776A rejects positive values above0xC000 with exception0x108.',
                'payload_interpretation': 'Opaque unchanged bytes. No normal-payload status-value comparison exists in these common transport and identified setup callers.',
                'one_byte_01': 'An ordinary reply payload01 yields received length1; it is not interpreted as a Boolean firmware success by the traced path.',
                'outer_crc_required': True,
                'empty_reply': 'Outer header/CRC acceptance with payload length0 is a normal return0, not a missing reply.',
                'evidence': ['AUTOCAL_VPW_TRANSPORT_STATIC.json:receive_context_metadata_and_error_marker',
                             'AUTOCAL_VPW_TRANSPORT_STATIC.json:receive_candidate_and_length_guards',
                             'AUTOCAL_VPW_TRANSPORT_STATIC.json:receive_crc_comparison'],
            },
            'error_reply': {
                'marker_offset': 2, 'marker_hex': '00ff',
                'precedence': 'A1751A..A17536 recognizes marker before ordinary command equality.',
                'long_payload_echoed_command_offset': 0, 'long_payload_status_offset': 2,
                'integer_bytes': 2, 'byte_order': 'little-endian',
                'safe_projection_min_payload_bytes': 4,
                'native_length_caveat': 'The inspected native code indexes error fields without a separate four-byte minimum; an offline implementation must reject too-short error payloads instead of copying that behavior.',
                'echo_mismatch': 'A1792A..A17954 compares error payload echo with requested command; mismatch raises0x26 atA179F8.',
                'status': 'A17A97..A17AB2 passes LE16(payload[2:4]) to7EC124; constructor7EC090 stores the raw status unchanged at exception+18 and7EC124 invokes the raise helper unconditionally.',
                'status_zero': 'An error marker remains an error envelope even when the raw status is zero; do not accept it as normal success.',
                'trailing_bytes': 'Preserve payload bytes beyond4 without interpretation.',
                'short_header_exclusion': 'Hostobject+51 selects a separate8-byte profile; that profile takes error status from payload[0:2] without the long-profile echo check. It is not covered by this projection.',
            },
            'return_propagation': {
                'hapi_receive': 'A17A02 saves declared payload length to local-12; A17BDA returns it zero-extended inEAX after ordinary success.',
                'hapi_ipc': 'A549AB..A549B4 writes received length to shared+14. Zero clears shared payload storage; positive length copies the received array to shared+1E.',
                'hapi_status': 'A53CC2 initializes message result+0C to0. A54A27..A54A4D catches typed exceptions and stores their+18 status there; other exceptions produce0x2D atA54AF4.',
                'scan_ipc': 'BBC4ED tests synchronous-message result: nonzero calls exception helperAF55A4; zero copies shared fields and returns response length from localrecord+10 throughBBC543/BBC579.',
                'scan_wrapper': 'BBC3F7 callsBBC408 and does not change EAX before returning; BB06A8 stores EAX andBB0737 returns it.',
                'scan_caught_failure': 'BB06F8 changes result to-1 on the caught error class, andBB06FF..BB070B only writes exception detail if optional status pointer is nonnull.',
                'metadata_is_separate': 'BB06AB..BB06B2 optionally returns metadata through a separate pointer; it is not the callback return value.',
                'no_status_byte_test': 'The common return is received payload length, not payload[0] and not a firmware success code.',
            },
            'caller_policy': [
                {'command': '0x8603', 'caller': 'ScanBB0A14 viaBB0614 selector0C',
                 'result_policy': 'Ignores callback return and supplies null optional metadata/status outputs; proceeds to8604 after ordinary callback return, including caught-failure return-1.',
                 'evidence': 'AUTOCAL_SETUP_CALLBACK_STATIC.json:setup_interval_words_and_8603_call'},
                {'command': '0x8604', 'caller': 'ScanBB0A14 viaBB0614 selector0C',
                 'result_policy': 'Ignores callback return and supplies null optional metadata/status outputs.',
                 'evidence': 'AUTOCAL_SETUP_CALLBACK_STATIC.json:setup_fourth_argument_dword_and_8604_call'},
                {'command': '0x8800', 'caller': 'ScanBB07F4 viaBB0614 selector0C',
                 'result_policy': 'Receiverword+7A must be3 before command. EAX>=0 caches lowword argument in155B9FC and returns argument. Empty response0 therefore passes the host length check; negative callback result returns-1.',
                 'downstream_caveat': 'VMopcode90 helper40392F ignores selector callback return before storing VM route4398B8/427648.',
                 'evidence': ['AUTOCAL_SETUP_CALLBACK_STATIC.json:conditional_protocol_callback_and_host_state',
                              'AUTOCAL_VM_SETUP_20261030.json:opcode90_callback_then_unchecked_vm_route_store']},
                {'command': '0x8B01', 'caller': 'VMopcode93 helper407350 via common callback4398A0 selector0C',
                 'result_policy': 'Null metadata/status outputs and no callback-result or reply-byte check.',
                 'evidence': 'AUTOCAL_VM_SETUP_20261030.json:opcode93_byte_arguments_and_8b01_callback'},
            ],
        },
        'static_caveats': [
            {'classification': 'derived', 'name': 'zero_length_scan_array_retention',
             'finding': 'BBC50B..BBC50E skips received-array resizing when returned length is0. BB0614 allocated that array from the original request length; BB06B4..BB06D8 subsequently uses array length for optional buffer copy. Therefore a successful empty reply can leave/copy original request bytes while returning0.',
             'offline_rule': 'Use the declared/returned response length; do not infer response contents from a retained request buffer.',
             'evidence': ['ipc_result_copy_and_length', 'AUTOCAL_SETUP_CALLBACK_STATIC.json:shared_callback_argument_roles',
                          'AUTOCAL_SETUP_CALLBACK_STATIC.json:shared_callback_optional_outputs']},
            {'classification': 'conditional_static_derivation', 'name': 'zero_status_error_ipc_collision',
             'finding': 'If a valid matching error envelope carries status0000, the receive path raises typed status0. HAPI stores0 in message result and bypasses A549AB returned-length update. Scan tests message result0 as normal completion and can reuse the shared request length. No actual such firmware reply is established.',
             'offline_rule': 'Reject error markers independently of status numeric value; do not copy this host ambiguity.',
             'evidence': ['exception_constructor_preserves_status', 'status_exception_raise',
                          'ipc_typed_exception_status', 'receive_length_and_ipc_buffer',
                          'ipc_result_copy_and_length']},
            {'classification': 'observation', 'name': 'candidate_mismatch_is_not_an_immediate_fatal_status',
             'finding': 'Ordinary command mismatch follows the receive candidate loop. A175F5..A176AA conditionally drains declared positive payload<=C000 and three trailing bytes. The loop can examine50 candidates; unresolved rejection raises0x26. CRC mismatch instead raises0x104 atA17909.',
             'offline_rule': 'A complete-frame projector may label a mismatched candidate rejected without emulating port draining or retries.',
             'evidence': ['EFILIVE_HOST_IPC.json:hapi_handler_evidence.receive',
                          'AUTOCAL_VPW_TRANSPORT_STATIC.json:receive_candidate_and_length_guards']},
        ],
        'unknowns': [
            'Firmware semantics of any ordinary setup payload byte, including01.',
            'Actual physical VPW mode or1x/4x speed as a consequence of an accepted setup envelope.',
            'Runtime occurrence of retained-array or zero-status-error branches; these are static derivations.',
            'Coverage of unrelated native callers or other firmware/header versions.',
            'Electrical quietness, transmission suppression, flash programming and physical recovery.',
        ],
        'target_executed': False, 'adapter_opened': False,
        'vehicle_transmissions_enabled': False, 'live_write_enabled': False,
        'ready_to_flash': False, 'would_send': [],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('hapi', 'scan', 'dumpbin', 'docs', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.hapi, args.scan, args.dumpbin, args.docs)
    with args.output.open('x', encoding='utf8', newline='\n') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'windows': len(WINDOWS), 'live_write_enabled': False,
                      'adapter_opened': False, 'target_executed': False}))


if __name__ == '__main__':
    main()
