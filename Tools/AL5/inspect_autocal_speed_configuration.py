"""Inspect native setup callers and distinguish polling from VPW speed.

File-only: pinned HAPI/Scan images, bounded dumpbin disassembly, exact byte
searches and a pure payload projection. No target, IPC or device is opened.
The logging setup producer is separate from the VM setup callback even when
both use the same receiver object. None of these fields proves firmware speed.
"""
import argparse
import json
from pathlib import Path
import re
import struct
import subprocess

import pefile

import inspect_autocal_setup_responses as boundary

SOURCE_HASHES = boundary.SOURCE_HASHES
DEPENDENCY_SHA = '7538dda0648a6585693daca53d93308609da63e1f6b33d6863273b180c881001'
PRIOR = {
    'AUTOCAL_SETUP_CALLBACK_STATIC.json': '244511cb52211c2424614f42f6a0d320b846229b6be7c69409b00e5e7bba15b0',
    'AUTOCAL_SETUP_NATIVE_STATIC.json': '973c72a8f72069abde76bf538fbb3c9319a73c732f1410fd858e8779cdb01088',
    'AUTOCAL_SETUP_RESPONSES_STATIC.json': '70e6aca5bd5397c94b2e2ec1129cb2c4ecf73aeb7ea96f3698c25a60da07d3fd',
    'AUTOCAL_SPEED_VM_STATIC.json': '707007048f3b47ed25c153892ad71e4adb7b62ae4181c860ea83a63b81fee680',
    'EFILIVE_HOST_IPC.json': '2d7846ea73bf723dccd0318cfa0ad440c1fbf814a07d6785549c013af466e4ae',
}
WINDOWS = (
    ('poll_setup_arguments_and_signed_division', 0xBB497C, 0xBB49DB),
    ('poll_setup_interval_bytes_and_8603', 0xBB49DB, 0xBB4A9B),
    ('poll_setup_mode_flags_and_8604', 0xBB4A9B, 0xBB4B78),
    ('poll_setup_return', 0xBB4BBD, 0xBB4BC6),
    ('zero_metadata_ipc_wrapper', 0xBBC380, 0xBBC3B3),
    ('conditional_poll_or_mode6_caller', 0x12A87F7, 0x12A886A),
    ('cleanup_zero_and_mode6_callers', 0x12ACAEE, 0x12ACB12),
    ('poll_start_caller', 0x12AF79F, 0x12AF7C2),
    ('vm_abort_calls_zero_setup', 0xED84E8, 0xED8506),
    ('properties_constructor_and_global_binding', 0x14A757A, 0x14A7596),
    ('logging_poll_time_setter', 0xBCB794, 0xBCB7AE),
)


def logging_setup_payloads(mode, poll_time, option, flags):
    """Project BB497C bytes only, preserving its native narrowing behavior.

    poll_time is signed Int32. Other native arguments are supplied as UInt32;
    mode and option are narrowed to a byte. Positive poll_time is split into
    quotient/remainder by1000 with both narrowed to UInt16. This producer has
    no quotient-range check, unlike the separately traced BB0A14 VM callback.
    Values here are analysis inputs, never a proposed adapter setup recipe.
    """
    for name, value in (('mode', mode), ('option', option), ('flags', flags)):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError(f'{name} must be UInt32')
    if type(poll_time) is not int or not -0x80000000 <= poll_time <= 0x7FFFFFFF:
        raise ValueError('poll_time must be Int32')
    result = []
    if poll_time > 0:
        quotient, remainder = divmod(poll_time, 1000)
        result.append({'command': '0x8603', 'payload_hex':
                       struct.pack('<HH', quotient & 0xFFFF, remainder & 0xFFFF).hex(),
                       'host_call_argument4': 100})
    result.append({'command': '0x8604', 'payload_hex':
                   struct.pack('<BBI', mode & 0xFF, option & 0xFF, flags).hex(),
                   'host_call_argument4': 1500})
    return result


def immediate_candidates(pe, raw, word):
    """Search enumerated x86 immediate forms, not all possible producers."""
    patterns = [bytes((0x66, op)) + word.to_bytes(2, 'little') for op in range(0xB8, 0xC0)]
    patterns += [bytes((op,)) + word.to_bytes(4, 'little') for op in (*range(0xB8, 0xC0), 0x68)]
    found = []
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        data = raw[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
        for pattern in patterns:
            cursor = 0
            while (cursor := data.find(pattern, cursor)) >= 0:
                va = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + cursor
                found.append({'va': hex(va), 'pattern_hex': pattern.hex(),
                              'file_offset': section.PointerToRawData + cursor})
                cursor += len(pattern)
    return {'command': hex(word), 'patterns_hex': [p.hex() for p in patterns],
            'matches': sorted(found, key=lambda item: int(item['va'], 16)),
            'instruction_boundaries_verified_by_search': False}


def direct_call_candidates(pe, raw, targets):
    result = {target: [] for target in targets}
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        data = raw[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
        base = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
        cursor = 0
        while (cursor := data.find(b'\xE8', cursor)) >= 0:
            if cursor + 5 <= len(data):
                target = base + cursor + 5 + struct.unpack_from('<i', data, cursor + 1)[0]
                if target in result:
                    result[target].append(hex(base + cursor))
            cursor += 1
    return [{'target': hex(target), 'candidate_call_sites': sites,
             'scope': 'E8 rel32 byte candidates across executable sections; verified callsites have separate disassembly windows. Indirect references are not included.'}
            for target, sites in result.items()]


def inspect(hapi_path, scan_path, dumpbin_path, docs_path):
    paths = {'hapi': Path(hapi_path), 'scan': Path(scan_path)}
    dumpbin_path, docs_path = Path(dumpbin_path), Path(docs_path)
    dependency = Path(boundary.__file__)
    snapshots = {p: p.read_bytes() for p in (*paths.values(), dumpbin_path, Path(__file__), dependency,
                 *(docs_path / name for name in PRIOR))}
    if boundary.digest(snapshots[dependency]) != DEPENDENCY_SHA:
        raise ValueError('Shared collector dependency identity differs')
    for key, path in paths.items():
        if boundary.digest(snapshots[path]) != SOURCE_HASHES[key]:
            raise ValueError(f'{key} identity differs; addresses cannot be reused')
    for name, expected in PRIOR.items():
        if boundary.digest(snapshots[docs_path / name]) != expected:
            raise ValueError(f'Prior evidence identity differs: {name}')
        json.loads(snapshots[docs_path / name])
    images = {key: pefile.PE(data=snapshots[path], fast_load=True) for key, path in paths.items()}
    pe, raw = images['scan'], snapshots[paths['scan']]
    windows = []
    for role, start, end in WINDOWS:
        where = boundary.file_range(pe, raw, start, end - start)
        lookahead = boundary.file_range(pe, raw, start, end - start + 16)
        command = [str(dumpbin_path), '/disasm:nobytes', f'/range:{hex(start)},{hex(end + 15)}', str(paths['scan'])]
        output = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
        lines = []
        for line in output.stdout.splitlines():
            match = re.match(r'\s+([0-9A-F]{8}):', line)
            if match and start <= int(match[1], 16) < end:
                lines.append(line.strip())
        if not lines or not lines[0].startswith(f'{start:08X}:'):
            raise ValueError('Disassembler did not start at requested boundary')
        windows.append({'role': role, 'source': where, 'end_exclusive_va': hex(end),
                        'lookahead_source': lookahead, 'command': command, 'instructions': lines})

    def bytes_at(va, size):
        span = boundary.file_range(pe, raw, va, size)
        return span, raw[span['file_offset']:span['file_offset'] + size]

    rtti = []
    # The property record is the Delphi32 TPropInfo layout: six DWORD values,
    # WORD NameIndex, then a length-prefixed ANSI name. The field entry and
    # setter provide independent source corroboration of its direct read offset.
    property_span, prop = bytes_at(0xBC33EB, 43)
    values = struct.unpack_from('<6IH', prop)
    if prop[26] != 16 or prop[27:] != b'Logging_PollTime' or values[:3] != (0x40109C, 0xFF0001E8, 0xBCB794):
        raise ValueError('Logging_PollTime property record differs')
    rtti.append({'role': 'logging_poll_time_property', 'source': property_span, 'raw_hex': prop.hex(),
                 'name': 'Logging_PollTime', 'type_pointer': hex(values[0]),
                 'getproc_raw': hex(values[1]), 'direct_field_offset': '0x1E8',
                 'setter_va': hex(values[2]), 'storedproc_raw': hex(values[3]),
                 'index_raw': hex(values[4]), 'default_raw': hex(values[5]), 'name_index': values[6]})
    for role, va, size in (
        ('properties_class_pointer_and_typeinfo', 0xBBDD18, 24),
        ('properties_typeinfo_name', 0xBC0628, 17),
        ('properties_global_pointer_cell', 0x1551F2C, 4),
        ('logging_poll_time_named_field_entry', 0xBBFC46, 29),
        ('vpw4x_separate_named_field', 0xBBED52, 41),
        ('todo_vpw_speed_separate_record_field', 0xBBD04E, 27),
    ):
        span, data = bytes_at(va, size)
        rtti.append({'role': role, 'source': span, 'raw_hex': data.hex()})
    searches = {key: [immediate_candidates(images[key], snapshots[path], word)
                      for word in (0x8603, 0x8604, 0x8B01)] for key, path in paths.items()}
    callers = direct_call_candidates(pe, raw, (0xBB497C, 0xBB0A14, 0xBC3744))
    for path, data in snapshots.items():
        if path.read_bytes() != data:
            raise ValueError(f'Source changed during collection: {path}')
    return {
        'schema': 'autocal-speed-configuration-static-v1',
        'scope': 'Native setup producer callers and host configuration names; no firmware behavior or physical speed qualification',
        'sources': {key: {'path': str(path.resolve()), 'sha256': boundary.digest(snapshots[path]), 'bytes': len(snapshots[path])}
                    for key, path in paths.items()},
        'generator_sha256': boundary.digest(snapshots[Path(__file__)]),
        'dependency': {'path': str(dependency.resolve()), 'sha256': DEPENDENCY_SHA},
        'disassembler': {'path': str(dumpbin_path.resolve()), 'sha256': boundary.digest(snapshots[dumpbin_path])},
        'prior_evidence': [{'path': str((docs_path / name).resolve()), 'sha256': digest} for name, digest in PRIOR.items()],
        'input_stability': 'All targets, generator, dependency, prior reports and disassembler compared before and after; transient replacement is not prevented by locking',
        'disassembly_windows': windows, 'rtti_and_pointer_evidence': rtti,
        'bounded_immediate_form_searches': searches, 'direct_call_candidates': callers,
        'observations': [
            {'classification': 'observation', 'finding': 'A second Scan producer at BB497C emits optional8603 and six-byte8604. It is distinct from the VM callback BB0A14.',
             'evidence': ['poll_setup_arguments_and_signed_division', 'poll_setup_interval_bytes_and_8603', 'poll_setup_mode_flags_and_8604']},
            {'classification': 'derived', 'finding': 'BB497C argument2 is signed Int32. When positive, it splits by1000 into quotient and remainder, narrows both to UInt16 and sends8603. Unlike BB0A14, it has no quotient range guard in the straight-line construction.',
             'evidence': ['poll_setup_arguments_and_signed_division', 'poll_setup_interval_bytes_and_8603']},
            {'classification': 'derived', 'finding': 'BB497C always constructs8604 as BYTE(arg1), BYTE(arg3), LE32(arg4); its host call argument4 is1500. BB0A14 instead selects1000 or2000 for that host parameter. These are host-call differences, not evidence of baud rate.',
             'evidence': ['poll_setup_mode_flags_and_8604', 'AUTOCAL_SETUP_CALLBACK_STATIC.json:setup_fourth_argument_dword_and_8604_call']},
            {'classification': 'derived', 'finding': 'Callsites12A883F and12AF7BD pass (1, TProperties.Logging_PollTime, 0, 0). The class is loaded throughBBDD18 at14A7584, constructed byBC3744 and stored through1551F2C. Its named property and setter both identify field1E8.',
             'evidence': ['conditional_poll_or_mode6_caller', 'poll_start_caller', 'properties_constructor_and_global_binding', 'logging_poll_time_property', 'logging_poll_time_setter']},
            {'classification': 'observation', 'finding': 'Other direct calls pass (6,0,0,0) at12A884E and12ACB0D, and (0,0,0,0) at12ACB00. ED8501 calls the VM callbackBB0A14 with all zeros after the caller observes its+DD byte and stores status0508.',
             'evidence': ['conditional_poll_or_mode6_caller', 'cleanup_zero_and_mode6_callers', 'vm_abort_calls_zero_setup']},
            {'classification': 'derived', 'finding': 'BB497C calls BBC380 using receiver slot155BA00; BBC380 supplies initial metadata0 and forwards toBBC3B4. This is a different slot from VM155B988, but the prior IPC evidence binds VM155B988 to that same main receiver during VM setup. It does not establish a separate adapter.',
             'evidence': ['poll_setup_interval_bytes_and_8603', 'poll_setup_mode_flags_and_8604', 'zero_metadata_ipc_wrapper', 'EFILIVE_HOST_IPC.json:pointer_chain']},
            {'classification': 'bounded_negative_observation', 'finding': 'The enumerated immediate forms find only HAPI one-byte8604 initialization calls, Scan BB0A14 andBB497C setup producers, and no HAPI/Scan8B01 producer. The existing8B01 producer is in the separate VM artifact. Computed commands, data tables, indirect producers and other encodings remain outside the search.',
             'evidence': ['bounded_immediate_form_searches', 'AUTOCAL_SETUP_NATIVE_STATIC.json', 'AUTOCAL_SETUP_RESPONSES_STATIC.json']},
        ],
        'speed_conclusion': {
            'supported_host_meaning': 'The second producer receives the named Logging_PollTime setting as its8603 split input. That is not an explicit host baud-rate selector.',
            'separate_names': 'FTune_ReadFlash_Default_Vpw4x is a separate TProperties byte fieldB3. todo_vpwSpeed appears in a different record at offset56. Their names alone do not bind either to8604 bytes.',
            'native_caller_variation': 'Observed native logging calls use8604 flag DWORD0; the saved E54 VM setup example uses flag DWORD0x10. Different caller context prevents interpreting this difference as1x versus4x.',
            'existing_speed_path': 'Prior AUTOCAL_SPEED_VM_STATIC.json resolves the E54 A0/A1 path followed by Sleep1000 and local FTDI queue purge; no8603/8604/8B01 command occurs between those two traced bus requests.',
            'unresolved': 'No explicit1x/4x firmware selector or autonomous speed-following behavior is proved by these native callers.',
        },
        'modeled_examples': [{'native_arguments': list(values), 'commands': logging_setup_payloads(*values)} for values in
                             ((1, 1500, 0, 0), (6, 0, 0, 0), (0, 0, 0, 0), (1, 65536000, 0, 0))],
        'unknowns': [
            'Firmware meanings of8604 mode/option/flag fields, including mode1 versus6 and flag0x10.',
            'Firmware timing units, timer behavior and relevance of8603 to the bus rather than internal polling.',
            'Whether adapter firmware recognizes A0/A1 and follows speed autonomously.',
            'Physical1x/4x transitions, bus quietness, programming, verification and recovery.',
            'Execution of the new static callers in the particular saved read, and unenumerated computed/indirect producers.',
        ],
        'target_executed': False, 'adapter_opened': False, 'vehicle_transmissions_enabled': False,
        'live_write_enabled': False, 'ready_to_flash': False, 'would_send': [],
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
    print(json.dumps({'windows': len(WINDOWS), 'adapter_opened': False, 'live_write_enabled': False}))


if __name__ == '__main__':
    main()
