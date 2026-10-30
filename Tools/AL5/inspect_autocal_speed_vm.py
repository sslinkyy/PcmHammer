"""Inspect the pinned E54 read VM's speed-request path without executing it.

All inputs are files. Native disassembly invokes dumpbin only. The two small
models expose supplied VM conditions; they do not emulate an adapter or a bus.
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
from validate_vm_buffers import read_bounded

CODE_SHA = 'fb9bc77f076cb5ee5c1e0228317bddd8448383bf1797d83154f40aced1568626'
DATA_SHA = 'c10236503cc23011df5e46c4f19e6ebc4e5d94059c1163488a899afe3235eceb'
TRACE_SHA = '49e0b14e2e5deb3581baca6c00f8ac29e264e2006d999aa017e4c736c448987f'
VM_SHA = '132832f80d7e5b642033fafc35df4ff3c0f3b19371081d23eacf696c4019ac00'
HAPI_SHA = 'c51bbf4795c2ee0ac54b95114e1d5ae509d7f53d35a160b35115085f444fbcf8'
DUMPBIN_SHA = '6ad86f7fa61936301fddafa97de7c8f0ac5c3cb225569dca68edfa021cce5919'

WINDOWS = (
    ('vm', 'host_step_word_supplies_ff18', 0x40B4D4, 0x40B52F),
    ('vm', 'ff18_special_reference', 0x4046CC, 0x4046DF),
    ('vm', 'opcode17_bitwise_and', 0x404CDF, 0x404D06),
    ('vm', 'arithmetic_result_flag_update', 0x404DB0, 0x404DC8),
    ('vm', 'arithmetic_zero_flag20', 0x4049D0, 0x4049F0),
    ('vm', 'opcode80_positive_signed_word_delay', 0x40390F, 0x40392F),
    ('vm', 'sleep_import_thunk', 0x4188F0, 0x4188F6),
    ('vm', 'opcode60_send_route', 0x4038D7, 0x4038FC),
    ('vm', 'send_helper_and_metadata', 0x406EC4, 0x406F8F),
    ('vm', 'opcode64_callback_selector0a', 0x407338, 0x40734D),
    ('hapi', 'secondary_selector_dispatch', 0xA543B4, 0xA543D7),
    ('hapi', 'selector0a_purge_route', 0xA5488C, 0xA54898),
    ('hapi', 'purge_availability_and_backend_selection', 0xA16BD8, 0xA16C43),
)


def gate_from_supplied_values(host_step_word, enable_byte):
    """Project two conditions with initial literals and normal return assumed.

    The supplied values are not read from hardware. Indirect descriptor writes,
    host redirects and exceptions are not modeled.
    """
    for value, maximum in ((host_step_word, 0xFFFF), (enable_byte, 0xFF)):
        if type(value) is not int or not 0 <= value <= maximum:
            raise ValueError('Explicit unsigned word and byte values required')
    return {'host_step_word': host_step_word, 'enable_byte': enable_byte,
            'a0_a1_send_path_selected': enable_byte == 1 and bool(host_step_word & 0x10),
            'physical_speed_proven': False, 'would_send': False}


def drain_from_supplied_receive_flags(receive_flags):
    """Bounded 0x102 helper projection using caller-supplied post-receive flags.

    Flag0x80 exits before decrement; otherwise arithmetic decrements a byte from
    20 and updates flag0x20. A short list is incomplete, not a fabricated timeout.
    Initial descriptors and ordinary return from the purge callback are assumed;
    callback exceptions, host redirects and indirect writes are not modeled.
    """
    if not isinstance(receive_flags, (list, tuple)) or len(receive_flags) > 20:
        raise ValueError('At most 20 supplied receive flag words required')
    if any(type(v) is not int or not 0 <= v <= 0xFFFF for v in receive_flags):
        raise ValueError('Receive flags must be unsigned words')
    remaining, flags, reason = 20, None, 'more_receive_outcomes_required'
    calls = 0
    for flags in receive_flags:
        calls += 1
        if flags & 0x80:
            reason = 'receive_flag80_exit'
            break
        remaining -= 1
        flags = (flags | 0x20) if remaining == 0 else (flags & ~0x20)
        if not remaining:
            reason = 'twenty_receive_budget_exhausted'
            break
    complete = reason != 'more_receive_outcomes_required'
    return {'receive_calls': calls, 'remaining_counter': remaining,
            'exit_reason': reason, 'completed': complete,
            'flags_after_explicit_81_clear': flags & ~0x81 if complete else None,
            'purge_callback_requested': complete,
            'payload_acknowledgement_validated': False,
            'adapter_opened': False, 'would_send': False}


def selected_trace_events(parsed):
    """Preserve records around the witnessed A0/A1 sequence and cleanup."""
    result = []
    for ordinal in list(range(114, 125)) + list(range(1182, 1194)):
        row = parsed[ordinal]
        entry = {'record_ordinal': ordinal, 'decoded_record_offset': row['offset'],
                 'kind': row['kind'], 'channel': row['channel']}
        if row['kind'] == 0x42:
            framed = framed_message(row)
            if framed is None:
                raise ValueError('Selected trace record is not a valid long envelope')
            raw = row['payload']; end = 12 + len(framed[1])
            if crc16(raw[:end], 0) != int.from_bytes(raw[end:end + 2], 'little'):
                raise ValueError('Selected trace envelope CRC differs')
            entry.update(direction=framed[0], envelope_prefix_hex=raw[:12].hex(),
                         payload_hex=framed[1].hex(), outer_crc_valid=True)
            if row['channel'] == 1:
                entry.update(command_le16=int.from_bytes(raw[2:4], 'little'),
                             caller_metadata_le32=int.from_bytes(raw[6:10], 'little'))
        else:
            entry['saved_text'] = row['payload'].decode('utf-8', errors='replace')
        result.append(entry)
    by_ordinal = {r['record_ordinal']: r for r in result}
    for index, payload in ((118, '6cfef0a0'), (119, '6cf010e0aa'), (122, '6cfef0a1')):
        if by_ordinal[index].get('payload_hex') != payload:
            raise ValueError('Pinned speed-request observation differs')
    if not by_ordinal[123].get('payload_hex', '').startswith('6c10f034'):
        raise ValueError('Pinned following mode34 observation differs')
    return result


def inspect(code_path, data_path, listing_path, trace_path, vm_path, hapi_path, dumpbin, docs):
    paths = dict(zip(('code', 'data', 'listing', 'trace', 'vm', 'hapi', 'dumpbin'),
                     map(Path, (code_path, data_path, listing_path, trace_path, vm_path, hapi_path, dumpbin))))
    raw = {name: read_bounded(path, 1, 32 * 1024 * 1024) for name, path in paths.items()}
    expected = {'code': CODE_SHA, 'data': DATA_SHA, 'trace': TRACE_SHA,
                'vm': VM_SHA, 'hapi': HAPI_SHA, 'dumpbin': DUMPBIN_SHA}
    for name, digest in expected.items():
        if sha256(raw[name]) != digest:
            raise ValueError('Exact pinned input identity required: ' + name)
    snapshots = [(paths[name], value) for name, value in raw.items()]
    docs = Path(docs)
    for name in ('AUTOCAL_VM_SETUP_20261030.json', 'EFILIVE_VM_DISPATCH.json',
                 'VM_RETRY_HELPERS_STATIC.json', 'AUTOCAL_SETUP_NATIVE_STATIC.json', 'EFILIVE_HOST_IPC.json'):
        path = docs / name; snapshots.append((path, path.read_bytes()))
    for name in (Path(__file__).name, 'inspect_vm_flow.py', 'audit_trace_wrappers.py',
                 'checksum.py', 'decode_trace_containers.py', 'validate_vm_buffers.py',
                 'al5_segment.py', 'inspect_vm_objects.py'):
        path = Path(__file__).with_name(name); snapshots.append((path, path.read_bytes()))
    flow = analyze_buffers(raw['code'], raw['data'], struct.unpack_from('<8H', raw['code']))
    saved_flow = json.loads(raw['listing'])
    if flow['structural_instructions'] != saved_flow.get('structural_instructions'):
        raise ValueError('Saved structural listing differs from reconstructed buffers')
    nodes = flow['structural_instructions']
    selected = []
    ranges = ((0x102, 0x144), (0x2CE, 0x31A), (0x172A, 0x1748),
              (0x1770, 0x1782), (0x1836, 0x183C), (0x27C8, 0x282A), (0x2A1C, 0x2A30))
    for node in nodes:
        if any(start <= node['offset'] < end for start, end in ranges):
            out = dict(node); literals = []
            for arg in node['operands']:
                if arg['tag'] == 0xB0:
                    literals.append({'descriptor_offset': arg['offset'],
                                     'payload_hex': raw['data'][arg['offset'] + 6:arg['offset'] + 6 + arg['payload_bytes']].hex()})
            if literals: out['inline_literals'] = literals
            selected.append(out)
    initial = []
    for offset in (0x2112, 0x2164, 0x21B6, 0x24AE, 0x24B2, 0x2484, 0x2488):
        desc, end = descriptor(raw['code'], offset)
        initial.append({**desc, 'raw_hex': raw['code'][offset:end].hex(), 'runtime_value_proven': False})
    pes = {name: pefile.PE(data=raw[name]) for name in ('vm', 'hapi')}

    def span(name, start, length):
        pe = pes[name]; rva = start - pe.OPTIONAL_HEADER.ImageBase
        for section in pe.sections:
            relative = rva - section.VirtualAddress
            if 0 <= relative and relative + length <= section.SizeOfRawData:
                offset = section.PointerToRawData + relative
                return {'source': name, 'va': hex(start), 'file_offset': offset,
                        'bytes': length, 'sha256': sha256(raw[name][offset:offset + length])}
        raise ValueError('Native evidence is not wholly file-backed')

    windows = []
    for name, role, start, end in WINDOWS:
        source = span(name, start, end - start)
        lookahead = span(name, start, end - start + 16)
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
    imports = [{'dll': imp.dll.decode('ascii'), 'name': item.name.decode('ascii'), 'iat_va': hex(item.address)}
               for imp in pes['vm'].DIRECTORY_ENTRY_IMPORT for item in imp.imports
               if item.name and item.address == 0x446260]
    if imports != [{'dll': 'KERNEL32.DLL', 'name': 'Sleep', 'iat_va': '0x446260'}]:
        raise ValueError('Expected Sleep import binding differs')
    cells = []
    for name, address, expected_value in (('hapi', 0xA543D7 + (10 - 3) * 4, 0xA5488C),):
        cell = span(name, address, 4)
        value = int.from_bytes(raw[name][cell['file_offset']:cell['file_offset'] + 4], 'little')
        if value != expected_value:
            raise ValueError('Expected selector dispatch cell differs')
        cells.append({**cell, 'target_va': hex(value), 'callback_selector': 10})
    event_rows = selected_trace_events(list(records(decode(raw['trace']))))
    for path, snapshot in snapshots:
        if path.read_bytes() != snapshot:
            raise ValueError('Input or implementation changed during collection')
    return {
        'schema': 'autocal-e54-speed-vm-static-v1',
        'scope': 'Exact reconstructed E54_R structure, native host handling and saved read12 observations; no VM or callbacks executed',
        'sources': [{'path': str(path.resolve()), 'bytes': len(value), 'sha256': sha256(value)} for path, value in snapshots],
        'structural_instruction_count': len(nodes), 'selected_structural_nodes': selected,
        'initial_code_descriptors': initial, 'native_windows': windows,
        'import_bindings': imports, 'dispatch_table_cells': cells, 'saved_trace_events': event_rows,
        'observations': [
            'The only literal opcode60 A0 and A1 sends are at data offsets2F2 and304 inside helper2CE.',
            'Caller172A first calls broadcast2800 helper28E, then tests initial code descriptor2164 against1; non-equality skips helper2CE.',
            'Helper2CE copiesFF18, ANDs initial code descriptor21B6=0x10, compares the result to that mask and branches to318 on non-equality.',
            'FF18 maps native descriptor42764E; its word427650 is populated from the caller-provided word pointer at vmStep argument4 before each step and written back afterward.',
            'The positive gate path sendsA0, calls102, sendsA1, requests Sleep(1000), requests opcode64 selector0A, and returns. It has no explicit resend branch or A1 receive/acknowledgement check.',
            'Helper102 copies initial counter24AE=20 to24B2 and calls opcode61 with receive destination10CC, output length2472 and initial timeout2484=250.',
            'Helper102 exits on receive flag0x80 before decrement, otherwise subtracts1 and repeats while arithmetic flag0x20 is clear. It then restores247E from2488=250, requests selector0A and clearsflags0x81. No E0AA byte comparison appears in this helper.',
            'Opcode80 reaches KERNEL32!Sleep through4188F0/IAT446260 for a positive signed operand word. This is a requested delay, not measured elapsed bus time.',
            'Opcode64 invokes common callbackselector0A with argument4=100. HAPI selector0A reachesA5488C thenA16BD8; the available backend2 path requests FT_Purge(mask3). Existing FTDI binding evidence identifies mask3 as RX|TX.',
            'Read12 records118=A0,119=E0AA,120=RX Looping,121=Timed Out,122=A1,123=mode34. No intervening binary TX exists between122 and123. The shown8A00 TX caller metadata remains0x10.',
            'Cleanup nodes27DC,27EE,2800 request zero8604 then8B01 payload00010000 then01010000. Their saved forms occur at1183,1186,1188; subsequent helper364 again requests zero8604 and3C55. Firmware effects of these messages are not established.'
        ],
        'derivations': [
            'For the initial literal descriptors and supplied flags, the A0 receive loop is bounded to20 receive calls and accepts no particular acknowledgement payload; a transport-error flag exits the drain and is subsequently cleared.',
            'The script does not condition A1 on a positively validated E0AA acknowledgement. SendingA1 also has no local retry guard in helper2CE.',
            'The operation immediately following the one-second requested delay is a host queue-purge request, not an additional speed-setting payload in this script helper.'
        ],
        'inferences': [
            'The A0/A1 messages are candidates for the observed speed-transition boundary, consistent with prior read captures. This report does not identify the adapter firmware mechanism that changes timing.'
        ],
        'unknowns': [
            'Host runtime choices for every vmStep input word, indirect writes to code descriptors and complete VM reachability are not modeled.',
            'Script flags, callback return values, empty adapter replies and successful host sends do not establish physical4x operation or successful controller acknowledgement.',
            'Whether adapter firmware recognizesA1 automatically, which setup fields affect VPW timing, and how physical return-to1x occurs remain unresolved.',
            'FTDI purge is conditional and its success is not established here; it does not prove bus silence or absence of unintended pulses.',
            'The existing cleanup8B01 and8604 forms cannot yet be labeled a proven1x-reset or interrupted-flash recovery sequence.',
            'The bounded flag projection assumes initial descriptor values and normal return from the purge callback. It uses supplied outcomes only and excludes callback exceptions, host redirects, indirect writes, opaque receive framing rules, USB timing, controller responses and scheduling.'
        ],
        'modeled_gate_cases': [gate_from_supplied_values(word, enable) for word, enable in ((0, 1), (0x10, 1), (0x10, 0), (0x20, 1))],
        'modeled_drain_cases': [drain_from_supplied_receive_flags(values) for values in ([], [0], [0, 0x80], [1] * 20, [0] * 20)],
        'adapter_opened': False, 'target_executed': False, 'physical_speed_proven': False,
        'return_to_1x_proven': False, 'live_write_enabled': False, 'ready_to_flash': False, 'would_send': False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ('code', 'data', 'listing', 'trace', 'vm', 'hapi', 'dumpbin', 'docs', 'output'):
        parser.add_argument('--' + argument, required=True)
    args = parser.parse_args(argv)
    output = Path(args.output)
    if output.exists():
        raise FileExistsError('Preserve existing output or evidence: ' + str(output))
    report = inspect(args.code, args.data, args.listing, args.trace, args.vm, args.hapi, args.dumpbin, args.docs)
    with output.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'report': str(output.resolve()), 'native_windows': len(report['native_windows']),
                      'selected_nodes': len(report['selected_structural_nodes']), 'live_write_enabled': False}))


if __name__ == '__main__':
    main()
