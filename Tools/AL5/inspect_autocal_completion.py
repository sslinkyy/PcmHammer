"""File-only HAPI FTDI completion evidence and bounded count-path experiments.

The count experiment supplies synthetic successful driver returns. It does not
execute the target, emulate FTDI/firmware, or authorize any adapter operation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

import pefile
from inspect_autocal_transport import HAPI_SHA256


WINDOWS = (
    ('ftdi_status_raise', 0x6ECCF0, 0x6ECD00),
    ('fixed_driver_timeout_initialization', 0x6EDBB8, 0x6EDC0B),
    ('driver_timeout_api_call', 0x6ECFC6, 0x6ED007),
    ('read_count_initialization', 0x6EDD33, 0x6EDD56),
    ('read_logical_attempt_budget', 0x6EDD87, 0x6EDE13),
    ('read_count_update_and_final_guard', 0x6EDE54, 0x6EDF57),
    ('write_count_initialization', 0x6EE0DB, 0x6EE106),
    ('write_logical_attempt_budget', 0x6EE137, 0x6EE197),
    ('write_count_update_and_final_guard', 0x6EE1D8, 0x6EE2D7),
    ('hapi_send_caller_no_length_check', 0xA16F7E, 0xA16FCF),
    ('hapi_send_outer_attempt_setup', 0xA16F12, 0xA16F49),
    ('hapi_send_outer_exception_retry_tail', 0xA1700F, 0xA1703E),
    ('hapi_receive_prefix_scan', 0xA173CA, 0xA1742B),
    ('hapi_receive_header_calls', 0xA174C4, 0xA1751A),
    ('hapi_receive_other_command_drain', 0xA175F5, 0xA176AA),
    ('hapi_receive_candidate_limit', 0xA176F7, 0xA17748),
    ('hapi_receive_payload_and_trailer_calls', 0xA177CF, 0xA17880),
    ('hapi_receive_payload_return', 0xA17A02, 0xA17A41),
)
PRIOR = (
    ('AUTOCAL_TRANSPORT_STATIC.json', 'fe791a6bd42a61ffc80fec8f77d2eebe7fdcd074ac1e37e466a4b1b114a647b7'),
    ('AUTOCAL_VPW_TRANSPORT_STATIC.json', 'd2551b0df3e646469abde42324872b3b3b17a8fe162cccc99bc95db78d738f74'),
    ('VM_RETRY_HELPERS_STATIC.json', 'de0179fb250a497b1e1beaaabbc36295b62ce50d3e8fcc705864488a95228d18'),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def count_path(requested, timeout_ms, direction, returned_counts):
    """Synthetic zero-status FTDI counts, with no reconnect or actual I/O."""
    if type(requested) is not int or not 1 <= requested <= 65550:
        raise ValueError('Experiment requires a positive bounded host-envelope byte count')
    if type(timeout_ms) is not int or not 1 <= timeout_ms <= 65535:
        raise ValueError('Experiment requires a positive timeout at most65535')
    if direction not in ('read', 'write'):
        raise ValueError('Explicit read or write required')
    quantum = 250 if direction == 'read' else 1000
    attempts = (timeout_ms - 1) // quantum + 1
    if not isinstance(returned_counts, list) or not 1 <= len(returned_counts) <= attempts:
        raise ValueError('Count samples must fit the native attempt budget')
    remaining, total, steps = requested, 0, []
    for count in returned_counts:
        if remaining == 0:
            raise ValueError('Native loop would already have stopped')
        if type(count) is not int or not 0 <= count <= remaining:
            raise ValueError('Driver sample count must fit the outstanding request')
        remaining -= count
        total += count
        steps.append({'returned_count': count, 'cumulative_count': total, 'remaining_count': remaining})
    if remaining and len(returned_counts) != attempts:
        raise ValueError('Missing synthetic outcomes before the native loop exits')
    return {'requested_count': requested, 'logical_timeout_ms': timeout_ms,
            'direction': direction, 'maximum_driver_calls': attempts,
            'steps': steps, 'native_final_count_guard_passes': remaining <= total,
            'all_requested_bytes_accounted_for': remaining == 0,
            'synthetic_driver_status_for_every_call': 0,
            'physical_transfer_observed': False}


def inspect(hapi, dumpbin, docs):
    hapi, dumpbin, docs = map(Path, (hapi, dumpbin, docs))
    source, disassembler, generator = hapi.read_bytes(), dumpbin.read_bytes(), Path(__file__).read_bytes()
    if digest(source) != HAPI_SHA256:
        raise ValueError('HAPI hash differs; static addresses cannot be reused')
    prior = {name: (docs / name).read_bytes() for name, _ in PRIOR}
    for name, expected in PRIOR:
        if digest(prior[name]) != expected:
            raise ValueError('Prior evidence hash differs: ' + name)
    pe = pefile.PE(data=source, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase

    def span(start, length):
        rva = start - base
        for section in pe.sections:
            relative = rva - section.VirtualAddress
            if relative >= 0 and relative + length <= section.SizeOfRawData:
                offset = section.PointerToRawData + relative
                raw = source[offset:offset + length]
                if len(raw) != length:
                    raise ValueError('Truncated source span')
                return {'va': hex(start), 'rva': hex(rva), 'file_offset': offset,
                        'bytes': length, 'sha256': digest(raw)}
        raise ValueError('Range is not wholly file-backed')

    windows = []
    for role, start, end in WINDOWS:
        declared, lookahead = span(start, end - start), span(start, end - start + 16)
        command = [str(dumpbin), '/disasm:nobytes', f'/range:{hex(start)},{hex(end + 15)}', str(hapi)]
        output = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30).stdout
        lines = []
        for line in output.splitlines():
            match = re.match(r'\s+([0-9A-F]{8}):', line)
            if match and start <= int(match[1], 16) < end:
                lines.append(line.strip())
        if not lines or not lines[0].startswith(f'{start:08X}:'):
            raise ValueError('Disassembler did not start at requested boundary')
        windows.append({'role': role, 'source': declared, 'end_exclusive_va': hex(end),
                        'lookahead_source': lookahead, 'command': command, 'instructions': lines})
    if hapi.read_bytes() != source or dumpbin.read_bytes() != disassembler or Path(__file__).read_bytes() != generator:
        raise ValueError('Source, disassembler or generator changed during collection')
    if any((docs / name).read_bytes() != data for name, data in prior.items()):
        raise ValueError('Prior evidence changed during collection')
    return {
        'schema': 'autocal-host-completion-static-v1',
        'scope': 'File-only exact-HAPI FTDI count, timeout and host-envelope receive analysis; no target execution',
        'source': {'path': str(hapi.resolve()), 'bytes': len(source), 'sha256': digest(source)},
        'generator_sha256': digest(generator),
        'disassembler': {'path': str(dumpbin.resolve()), 'sha256': digest(disassembler)},
        'prior_evidence': [{'path': 'Docs/AL5/' + name, 'sha256': expected} for name, expected in PRIOR],
        'input_stability': 'Inputs, generator and prior reports compared before and after; transient replacement is not prevented by locking',
        'windows': windows,
        'observations': [
            {'addresses': ['0x6EDD3C', '0x6EDDF9', '0x6EDE6E', '0x6EDE7C', '0x6EDEDE'],
             'fact': 'FTDI read helper initializes ESI from requested count, zeros caller cumulative count, advances cumulative count and buffer offset by each returned count, and subtracts it from ESI. Final count check compares remaining ESI against cumulative count, not original requested count.'},
            {'addresses': ['0x6EE0E4', '0x6EE178', '0x6EE1F0', '0x6EE1FE', '0x6EE260'],
             'fact': 'FTDI write helper has the equivalent remaining/cumulative update and final comparison. Zero remaining ends the loop early, but the final guard also passes any nonzero remaining value no greater than cumulative count.'},
            {'addresses': ['0x6ECCF0', '0x6EDED4', '0x6EE256'],
             'fact': 'Driver status is checked separately: nonzero status reaches the exception helper. Status values1..4 first take helper6EDB54; that reconnect/recovery helper is not modeled by the synthetic zero-status count cases.'},
            {'addresses': ['0xA16F89', '0xA16F9E', '0xA16FBD'],
             'fact': 'HAPI passes local[-14] as write count output, then clears host state without inspecting that count. This send path has no receive call or controller acknowledgement check.'},
            {'addresses': ['0xA17400', '0xA17415', '0xA174C8', '0xA174DD', '0xA174F8', '0xA1750D', '0xA177CF', '0xA17814'],
             'fact': 'The inspected HAPI receive call sites supply local[-18] as count output but do not compare it before continuing header/payload/trailer processing. Final return length is the declared payload length copied into local[-12], not accumulated driver bytes.'},
            {'addresses': ['0x6EDDD7', '0x6EE156', '0x6EDBF3', '0x6EDBFF', '0x6ECFDF'],
             'fact': 'Logical read timeout field+78 yields floor(max(timeout-1,0)/250)+1 driver calls; write field+7C yields divisor1000. Initialization requests driver timeout arguments250 and1000 through6ECF58. No monotonic deadline or cancellation test appears in the inspected transfer loops.'},
            {'addresses': ['0xA173DD', '0xA17422', '0xA174E5', '0xA176F7', '0xA1773E'],
             'fact': 'FTDI receive scans up to50 candidates for prefix01/52 and eligible header; exhaustion with rejection flag still set raises0x26. This is bounded skipping, not automatic lossless resynchronization.'},
            {'addresses': ['0xA175F5', '0xA17611', '0xA1761C', '0xA1765E', '0xA176A5'],
             'fact': 'For a non-metadata command mismatch, positive declared payload lengths at mostC000 are drained plus three trailing bytes before trying another candidate. Zero or oversized lengths skip that drain. Command8A00 normally uses metadata interpretation instead of command equality.'},
            {'addresses': ['0xA16F12', '0xA16F20', '0xA16F39', '0xA1700F', '0xA17024'],
             'fact': 'Outer send attempt count derives from host+3C plus one; caught failure can callA13678 before retry. A successful FTDI helper return exits that outer loop. This is host transport retry, not controller programming retry or bus acknowledgement.'},
        ],
        'conditional_count_path_conclusion': 'Under synthetic zero-status partial returns, the native final count guard can pass with bytes still outstanding. This is a static conditional path, not an observed FTDI or firmware failure. A PcmHammer transport must require its own exact transfer accounting.',
        'synthetic_count_examples': [count_path(10, 250, 'read', [4]), count_path(10, 250, 'read', [5]),
                                     count_path(10, 250, 'read', [10]), count_path(14, 1000, 'write', [7]),
                                     count_path(14, 2000, 'write', [5, 9])],
        'metadata_consumer_from_prior_vm_report': {
            'evidence': 'Docs/AL5/VM_RETRY_HELPERS_STATIC.json',
            'addresses': ['0x407087', '0x40708A', '0x4070EE', '0x4070FD', '0x407103', '0x40710C', '0x407127'],
            'fact': 'VM stores returned metadata at42765A. A conditional validation-selection path extracts bits16..23 and compares them withEF to choose selector2 or3; ordinary path chooses1. No low-bit0x10 ACK/success meaning is established by this consumer.'},
        'unknowns': ['Actual driver call timing, scheduling, device completion and bus delivery remain unobserved here.',
                     'No complete cancellation, reconnect, retry safety, or firmware queue model is established.',
                     'Linear disassembly windows preserve exact bytes but do not prove all paths reachable.',
                     'Candidate skipping can consume unrelated bytes; no lossless stream parser is implemented.',
                     'Logical timeouts and driver call budgets do not constitute a single end-to-end deadline.',
                     'Individual RX metadata flags, especially0x10, remain unresolved.'],
        'target_executed': False, 'adapter_opened': False, 'vehicle_transmissions_enabled': False,
        'live_write_enabled': False, 'ready_to_flash': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hapi', type=Path, required=True)
    parser.add_argument('--dumpbin', type=Path, required=True)
    parser.add_argument('--docs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.hapi, args.dumpbin, args.docs)
    with args.output.open('x', encoding='utf8', newline='\n') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'windows': len(WINDOWS), 'adapter_opened': False, 'output': str(args.output.resolve())}))


if __name__ == '__main__':
    main()
