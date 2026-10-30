"""Inspect E54 cleanup and compare existing AL5 structure, strictly offline.

Models accept supplied state only. They do not execute a VM, call a target,
open an adapter, or prove a controller reset, bus speed, or physical recovery.
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
from inspect_vm_flow import analyze_buffers, descriptor
from inspect_autocal_speed_vm import CODE_SHA, DATA_SHA, TRACE_SHA, VM_SHA, DUMPBIN_SHA
from validate_vm_buffers import read_bounded

SCAN_SHA = '9d3aad921df7ac8848b7d7cdb82fea0fd7695070f1c4d1f6bf9f68f0a0f34a3a'
AL5_REPORT_SHA = 'f82ee19151b92d34630a4ff68793d6519f1e30e03f79bf0a282604cc9e820ad7'
WINDOWS = (
    ('vm', 'opcode81_raw_status_and_stop_marker', 0x40387A, 0x403890),
    ('vm', 'ordinary_step_status_510', 0x40449D, 0x4044A8),
    ('vm', 'opcode59_countdown_store', 0x403C3C, 0x403C64),
    ('vm', 'countdown_export', 0x40B93C, 0x40B944),
    ('vm', 'vm_step_export', 0x40B4D4, 0x40B52F),
    ('vm', 'vm_done_export', 0x40B2A4, 0x40B2AC),
    ('vm', 'vm_done_body', 0x402FF0, 0x40300B),
    ('vm', 'vm_closeall_export', 0x40B4CC, 0x40B4D4),
    ('vm', 'vm_closeall_body', 0x40360C, 0x403683),
    ('vm', 'error_status_and_flag80', 0x4034D4, 0x4034F7),
    ('scan', 'vm_import_thunks', 0xBB0018, 0xBB0050),
    ('scan', 'host_step_loop_and_bailout_setup', 0xED84A7, 0xED8515),
    ('scan', 'host_completion_and_cleanup_calls', 0xED8583, 0xED8605),
    ('scan', 'get_countdown_to_ui_handler', 0x119327C, 0x119329C),
    ('scan', 'countdown_ui_handler', 0x1194DFC, 0x1194E9F),
)


def cleanup_route(entry, error_word=0, negative_word=0, entered_byte=0, cached_word=0):
    """Project the structural entry gate using supplied word/byte state.

    Normal calls/returns, initial descriptor types and no host redirects or
    exceptions are assumed. Existing pending VM frames are not unwound here.
    """
    for value, maximum in ((error_word, 65535), (negative_word, 65535),
                           (entered_byte, 255), (cached_word, 65535)):
        if type(value) is not int or not 0 <= value <= maximum:
            raise ValueError('Explicit unsigned state words and byte required')
    if entry not in ('normal', 'script_error', 'host_error_entry', 'host_bailout'):
        raise ValueError('Unsupported supplied entry')
    common, status, guard = True, error_word, entered_byte
    if entry == 'normal':
        status = 0
    elif entry == 'script_error':
        if entered_byte == 1:
            common, status = False, cached_word
        else:
            guard = 1
            if negative_word:
                status = (0x300 + negative_word) & 0xFFFF
    elif entry == 'host_bailout':
        common, status = False, 0x508
    return {'entry': entry, 'shared_cleanup_selected': common,
            'status_word': status, 'entered_byte_after_gate': guard,
            'direct_host_zero_setup_requested': entry == 'host_bailout',
            'existing_pending_frames_unwound': False,
            'hardware_reset_proven': False, 'would_send': False}


def classify_3c55_receive(flags, payload):
    """Project helper188's next branch after supplied opcode61 flags/payload.

    This is not framing validation: flags, native classification and current
    expected service3C/PID55 are supplied assumptions. No retry is performed.
    """
    if type(flags) is not int or not 0 <= flags <= 0xFFFF or not isinstance(payload, bytes):
        raise ValueError('Supplied unsigned flags and bytes required')
    positive = False
    if flags & 1:
        if len(payload) < 5:
            raise ValueError('Negative branch byte4 is unavailable; native read not modeled')
        branch = 'return_with_negative_flag' if payload[4] == 0x3C else 'decrement_receive_budget'
    elif flags & 0x80:
        branch = 'decrement_transmit_budget'
    else:
        if len(payload) < 5:
            raise ValueError('Positive branch bytes3/4 unavailable; native read not modeled')
        positive = payload[3:5] == b'\x7c\x55'
        branch = 'return_with_matching_service_pid' if positive else 'decrement_receive_budget'
    return {'supplied_flags': flags, 'payload_hex': payload.hex(), 'next_branch': branch,
            'matching_positive_service_pid': positive, 'controller_acknowledgement_verified': False,
            'automatic_retry_performed': False, 'would_send': False}


def inspect(code_path, data_path, listing_path, trace_path, vm_path, scan_path, dumpbin, docs):
    paths = dict(zip(('code', 'data', 'listing', 'trace', 'vm', 'scan', 'dumpbin'),
                     map(Path, (code_path, data_path, listing_path, trace_path, vm_path, scan_path, dumpbin))))
    raw = {name: read_bounded(path, 1, 32 * 1024 * 1024) for name, path in paths.items()}
    expected = {'code': CODE_SHA, 'data': DATA_SHA, 'trace': TRACE_SHA,
                'vm': VM_SHA, 'scan': SCAN_SHA, 'dumpbin': DUMPBIN_SHA}
    for name, digest in expected.items():
        if sha256(raw[name]) != digest:
            raise ValueError('Exact pinned input identity required: ' + name)
    snapshots = [(paths[name], value) for name, value in raw.items()]
    docs = Path(docs)
    evidence = {}
    for name in ('AUTOCAL_VM_SETUP_20261030.json', 'AUTOCAL_SPEED_VM_STATIC.json',
                 'EFILIVE_VM_DISPATCH.json', 'VM_RETRY_HELPERS_STATIC.json',
                 'VM_CALLBACK10_STATIC.json', 'VM_PROGRAMMING_FLOW.json', 'EFILIVE_HOST_CALLBACKS.json'):
        path = docs / name; value = path.read_bytes(); snapshots.append((path, value))
        evidence[name] = value
    if sha256(evidence['VM_PROGRAMMING_FLOW.json']) != AL5_REPORT_SHA:
        raise ValueError('Pinned existing AL5 structural report differs')
    for name in (Path(__file__).name, 'inspect_autocal_speed_vm.py', 'inspect_vm_flow.py',
                 'audit_trace_wrappers.py', 'checksum.py', 'decode_trace_containers.py',
                 'validate_vm_buffers.py', 'al5_segment.py', 'inspect_vm_objects.py'):
        path = Path(__file__).with_name(name); snapshots.append((path, path.read_bytes()))
    flow = analyze_buffers(raw['code'], raw['data'], struct.unpack_from('<8H', raw['code']))
    if flow['structural_instructions'] != json.loads(raw['listing']).get('structural_instructions'):
        raise ValueError('Saved listing differs from reconstructed buffers')
    nodes = flow['structural_instructions']
    ranges = ((0x44, 0xAA), (0x102, 0x144), (0x188, 0x28E),
              (0x2A4, 0x2B8), (0x31A, 0x3BC), (0x2742, 0x282A),
              (0x28FC, 0x2964), (0x2A1C, 0x2A30))
    selected = [node for node in nodes if any(start <= node['offset'] < end for start, end in ranges)]
    initial = []
    for offset in (0x40, 0x70, 0x2146, 0x214A, 0x2476, 0x247A, 0x247E,
                   0x2484, 0x2488, 0x24AE, 0x24B6, 0x24C0):
        desc, end = descriptor(raw['code'], offset)
        out = {**desc, 'raw_hex': raw['code'][offset:end].hex(), 'runtime_value_proven': False}
        if desc['tag'] == 0xB0:
            out['payload_hex'] = raw['code'][offset + 6:offset + 6 + desc['payload_bytes']].hex()
        initial.append(out)
    al5 = json.loads(evidence['VM_PROGRAMMING_FLOW.json'])
    matches = []
    for start, end in ((0x102, 0x144), (0x188, 0x28E), (0x31A, 0x3BC)):
        e = [n['source_sha256'] for n in nodes if start <= n['offset'] < end]
        a = [n['source_sha256'] for n in al5['structural_instructions'] if start <= n['offset'] < end]
        matches.append({'start': start, 'end_exclusive': end, 'e54_nodes': len(e), 'al5_nodes': len(a),
                        'instruction_hash_sequences_equal': e == a})
    al5_selected = [n for n in al5['structural_instructions']
                    if 0x2A76 <= n['offset'] < 0x2AD8 or 0x2C6C <= n['offset'] < 0x2C80]
    pes = {name: pefile.PE(data=raw[name]) for name in ('vm', 'scan')}

    def span(name, start, length):
        rva = start - pes[name].OPTIONAL_HEADER.ImageBase
        for section in pes[name].sections:
            relative = rva - section.VirtualAddress
            if 0 <= relative and relative + length <= section.SizeOfRawData:
                offset = section.PointerToRawData + relative
                return {'source': name, 'va': hex(start), 'file_offset': offset, 'bytes': length,
                        'sha256': sha256(raw[name][offset:offset + length])}
        raise ValueError('Native evidence is not wholly file-backed')

    windows = []
    for name, role, start, end in WINDOWS:
        source = span(name, start, end - start); lookahead = span(name, start, end - start + 16)
        command = [str(paths['dumpbin']), '/disasm:nobytes', f'/range:{hex(start)},{hex(end + 15)}', str(paths[name])]
        output = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30).stdout
        lines = []
        for line in output.splitlines():
            match = re.match(r'\s+([0-9A-F]{8}):', line)
            if match and start <= int(match[1], 16) < end:
                lines.append(line.strip())
        if not lines or not lines[0].startswith(f'{start:08X}:'):
            raise ValueError('Disassembly boundary mismatch')
        windows.append({'role': role, 'source': source, 'lookahead': lookahead,
                        'command': command, 'instructions': lines})
    import_expected = {'vmStep': 0x174A428, 'vmCloseAll': 0x174A42C,
                       'vmGetCountdown': 0x174A43C, 'vmDone': 0x174A44C}
    imports = {}
    for library in pes['scan'].DIRECTORY_ENTRY_IMPORT:
        if library.dll != b'EFILive_VM.dll':
            continue
        for item in library.imports:
            name = item.name.decode('ascii') if item.name else ''
            if name in import_expected:
                imports[name] = item.address
    if imports != import_expected:
        raise ValueError('Pinned Scan VM import bindings differ')
    exports = {s.name.decode('ascii'): s.address + pes['vm'].OPTIONAL_HEADER.ImageBase
               for s in pes['vm'].DIRECTORY_ENTRY_EXPORT.symbols if s.name and s.name.decode('ascii') in import_expected}
    if exports != {'vmStep': 0x40B4D4, 'vmCloseAll': 0x40B4CC, 'vmGetCountdown': 0x40B93C, 'vmDone': 0x40B2A4}:
        raise ValueError('Pinned VM exports differ')
    event_rows = []
    parsed = list(records(decode(raw['trace'])))
    if len(parsed) != 1216:
        raise ValueError('Pinned cleanup trace record coverage differs')
    for ordinal, row in enumerate(parsed):
        if ordinal < 1182:
            continue
        event = {'record_ordinal': ordinal, 'decoded_record_offset': row['offset'],
                 'kind': row['kind'], 'channel': row['channel']}
        if row['kind'] == 0x42:
            framed = framed_message(row)
            if framed is None:
                raise ValueError('Malformed selected cleanup envelope')
            envelope = row['payload']; end = 12 + len(framed[1])
            if crc16(envelope[:end], 0) != int.from_bytes(envelope[end:end + 2], 'little'):
                raise ValueError('Selected cleanup envelope CRC differs')
            event.update(direction=framed[0], envelope_prefix_hex=envelope[:12].hex(),
                         payload_hex=framed[1].hex(), outer_crc_valid=True)
        else:
            event['saved_text'] = row['payload'].decode('utf-8', errors='replace')
        event_rows.append(event)
    by_ordinal = {event['record_ordinal']: event for event in event_rows}
    expected_payloads = {1193: '6c10f03c55', 1200: '6c10f03c55', 1202: '6cf0107f3c5531',
                         1203: '6cfef020', 1205: '6cf01060', 1208: '686af004',
                         1209: '486b1044', 1212: '6cfef014', 1213: '6cf01054'}
    if any(by_ordinal[index].get('payload_hex') != value for index, value in expected_payloads.items()):
        raise ValueError('Pinned cleanup payload observation differs')
    for path, value in snapshots:
        if path.read_bytes() != value:
            raise ValueError('Input or implementation changed during collection')
    return {
        'schema': 'autocal-cleanup-vm-static-v1',
        'scope': 'Pinned E54 saved-read cleanup, native host exit and comparison with existing AL5 structure; no target execution',
        'sources': [{'path': str(path.resolve()), 'bytes': len(value), 'sha256': sha256(value)} for path, value in snapshots],
        'selected_structural_nodes': selected, 'initial_code_descriptors': initial,
        'native_windows': windows, 'scan_import_bindings': imports, 'vm_export_bindings': exports,
        'saved_trace_events': event_rows,
        'al5_structural_comparison': {'e54_cleanup_entry': 0x27C8, 'al5_cleanup_entry': 0x2A76,
            'identical_helper_instruction_hashes': matches, 'al5_selected_nodes': al5_selected,
            'e54_countdown_literal': 15, 'al5_countdown_literal': 30,
            'al5_code_pool_values_independently_revalidated': False,
            'physical_controller_behavior_equivalent': False},
        'observations': [
            'Normal path295E branches2742, writes zeroFF07, then branches shared cleanup27C8. It savesFF07 into code descriptor70 before further cleanup calls.',
            'Error entry2752 checks code byte214A. If equal1 it jumps directly2824 and returns saved70. Otherwise it writes1, preservesFF07 ifFF05 is zero, or writes0x300+FF05 toFF07, invokes opcode84, then falls through27C8.',
            'Shared27C8 restores the receive timeout, requests zero8604, requests8B01(00010000), requests8B01(01010000), invokes purge selector0A, clears2146 and calls2A1C.',
            'Helper2A1C calls364, then31A, then sets opcode59 value15 and returns. Helper364 itself clears2146, requests another zero8604, constructs6C10F03C55, sets receive timeout1000 and calls retry helper188.',
            'Helper188 calls the send helper44, then sets inner receive budget8 and calls opcode61. Flag1 branches to the negative-service check before the flag80 test. Matching byte4=expected3C returns via278 without requiring positive7C55.',
            'Unmatched responses decrement the inner receive budget. Exhaustion or receive flag80 decrements transmit budget2476; if nonzero it purges, requests Sleep(100), and resends. If exhausted it setsflag80. Exit278 restores transmit budget3 and the default timeout250.',
            'Helper364 does not branch on the returned3C55 result. It next calls broadcast20 helper2A4, requests Sleep(1000), explicitly clears flags0x81 and returns.',
            'Helper31A constructs686AF004 and6CFEF014 using initial code headers, sends each through44 and drains through102. The drain does not validate a specific response payload.',
            'Read12 cleanup records show first3C55 followed by timeout text, second3C55 followed by negative6CF0107F3C5531, then20/60,686AF004/486B1044 and6CFEF014/6CF01054. These are observed exchanges, not positive reset acknowledgements.',
            'Opcode59 stores its low byte in4274C6. vmGetCountdown returns that byte; Scan imports it throughBB0048 and passes it to countdown UI helper1194DFC. E54 supplies15; the compared AL5_W structure supplies30.',
            'Opcode81 at2824 sets the native stop marker4274C4 and returns raw status word70. The ordinary step route returns0x510. Scan ED84CC callsvmStep, continues only while status0x510 and host object byteDD is zero, and records the terminating signed status.',
            'If the host object byteDD is nonzero, the shown host path forcesstatus0x508 and invokesBB0A14 with four zero arguments before completion. This bailout can stop the VM before remaining script cleanup executes.',
            'The shown completion path calls vmDone, additional host cleanup helpers, then vmCloseAll. vmDone itself copies two stored values and returns; vmGetCountdown itself only reads a byte. Neither export contains an adapter command.'
        ],
        'derivations': [
            'The3C55 exchange can terminate with a negative-response flag; the following20,04,14 commands are attempted under ordinary return assumptions even if3C55 did not receive a positive service/PID match.',
            'Shared VM cleanup, guarded script-error reentry and host bailout are different paths. There is no single unconditional cleanup sequence covering all failures.',
            'Pending VM return frames are not cleared by the shown direct error branches. Newly called cleanup helpers return normally to2824; opcode81 terminates without requiring older pending frames to unwind.',
            'The existing AL5_W report has exactly matching instruction hashes for the selected drain, exchange and cleanup helper ranges, but the final countdown literal differs. Shared implementation is not controller-specific speed or recovery proof.'
        ],
        'inferences': [
            'The observed negative3C55 followed by the remaining cleanup commands is consistent with the matching-negative terminal branch; saved trace data does not expose the exact VM flag state.',
            'The tail commands and zero8604/8B01 forms are candidates for restoring communication state. Their physical1x effects require firmware or linked bench evidence.'
        ],
        'unknowns': [
            'Which command or firmware behavior restores physical1x, and whether it does so after every interrupted operation, remain unproven.',
            'The report does not execute the VM or fully resolve native callback redirects, exceptions, host helper side effects, indirect descriptor writes or all pending-stack states.',
            'The initial transmit budget depends on preceding VM state. The generic exit resets it to3, but this does not prove3 attempts on every path.',
            'The meanings of20,04,14 and3C55 at the particular controller and adapter are not inferred solely from generic service names or matching shared code.',
            'A negative3C55 reply, successful host completion, countdown value or disabled setup is not proof of a safe reset, valid programming recovery or flash readiness.',
            'The host byteDD bailout meaning is not independently mapped to a UI event. Untraced host cleanup helpers and countdown virtual calls may have effects beyond the shown bounded windows.'
        ],
        'modeled_route_cases': [cleanup_route('normal', 0x123), cleanup_route('script_error', 0x123),
                               cleanup_route('script_error', 0x123, 0x31),
                               cleanup_route('script_error', 0x123, 0x31, 1, 0x456),
                               cleanup_route('host_error_entry', 0x536), cleanup_route('host_bailout')],
        'modeled_reply_cases': [classify_3c55_receive(1, bytes.fromhex('6cf0107f3c5531')),
                               classify_3c55_receive(0x80, b''),
                               classify_3c55_receive(0, bytes.fromhex('6cf0107c55'))],
        'adapter_opened': False, 'target_executed': False, 'return_to_1x_proven': False,
        'physical_recovery_verified': False, 'live_write_enabled': False, 'ready_to_flash': False, 'would_send': False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ('code', 'data', 'listing', 'trace', 'vm', 'scan', 'dumpbin', 'docs', 'output'):
        parser.add_argument('--' + argument, required=True)
    args = parser.parse_args(argv)
    output = Path(args.output)
    if output.exists():
        raise FileExistsError('Preserve existing output or evidence: ' + str(output))
    report = inspect(args.code, args.data, args.listing, args.trace, args.vm, args.scan, args.dumpbin, args.docs)
    with output.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'report': str(output.resolve()), 'native_windows': len(report['native_windows']),
                      'selected_nodes': len(report['selected_structural_nodes']), 'live_write_enabled': False}))


if __name__ == '__main__':
    main()
