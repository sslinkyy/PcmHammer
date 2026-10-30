"""Collect the exact Scan VM setup callback producing commands8603/8604.

File-only disassembly and formulas; does not execute Scan, VM callbacks,
host IPC, adapter commands or a vehicle protocol.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

import pefile


SCAN_SHA256 = '9d3aad921df7ac8848b7d7cdb82fea0fd7695070f1c4d1f6bf9f68f0a0f34a3a'
WINDOWS = (
    ('vm_callback_table_setup_slot', 0xBB0250, 0xBB02A3),
    ('conditional_protocol_callback_and_host_state', 0xBB07F4, 0xBB08B9),
    ('setup_callback_arguments_and_interval_split', 0xBB0A14, 0xBB0A9D),
    ('setup_interval_words_and_8603_call', 0xBB0A9D, 0xBB0B87),
    ('setup_mode_and_third_argument_bytes', 0xBB0B87, 0xBB0BD4),
    ('setup_fourth_argument_dword_and_8604_call', 0xBB0BD4, 0xBB0CB9),
    ('setup_callback_cleanup_and_return', 0xBB0CB9, 0xBB0CE6),
    ('shared_callback_argument_roles', 0xBB0614, 0xBB06A8),
    ('shared_callback_optional_outputs', 0xBB06A8, 0xBB06E7),
    ('shared_callback_caught_error', 0xBB06F8, 0xBB0712),
    ('shared_callback_status_return', 0xBB0737, 0xBB0743),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def inspect(scan_path, dumpbin_path):
    scan_path, dumpbin_path = Path(scan_path), Path(dumpbin_path)
    snapshots = [(p, p.read_bytes()) for p in (scan_path, dumpbin_path, Path(__file__))]
    source, disassembler, generator = [raw for _, raw in snapshots]
    if digest(source) != SCAN_SHA256:
        raise ValueError('Scan identity differs; addresses cannot be reused')
    pe = pefile.PE(data=source, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase

    def location(va, count):
        rva = va - base
        for section in pe.sections:
            relative = rva - section.VirtualAddress
            if 0 <= relative and relative + count <= section.SizeOfRawData:
                offset = section.PointerToRawData + relative
                raw = source[offset:offset + count]
                if len(raw) != count:
                    raise ValueError('Truncated source range')
                return {'va': hex(va), 'rva': hex(rva), 'file_offset': offset,
                        'bytes': count, 'sha256': digest(raw),
                        'section': section.Name.rstrip(b'\0').decode('ascii')}
        raise ValueError('Window is not wholly file-backed')

    windows = []
    for role, start, end in WINDOWS:
        where = location(start, end - start)
        lookahead = location(start, end - start + 16)
        command = [str(dumpbin_path), '/disasm:nobytes', f'/range:{hex(start)},{hex(end + 15)}', str(scan_path)]
        output = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
        lines = []
        for line in output.stdout.splitlines():
            match = re.match(r'\s+([0-9A-F]{8}):', line)
            if match and start <= int(match[1], 16) < end:
                lines.append(line.strip())
        if not lines or not lines[0].startswith(f'{start:08X}:'):
            raise ValueError('Disassembler did not begin at requested instruction boundary')
        windows.append({'role': role, 'source': where, 'end_exclusive_va': hex(end),
                        'lookahead_source': lookahead, 'command': command, 'instructions': lines})
    for path, raw in snapshots:
        if path.read_bytes() != raw:
            raise ValueError(f'Source changed during collection: {path}')
    return {
        'schema': 'autocal-vm-setup-callback-static-v1',
        'scope': 'Exact Scan native callback BB0A14 setup payload construction and return handling; file-only',
        'source': {'path': str(scan_path.resolve()), 'sha256': digest(source), 'bytes': len(source)},
        'generator_sha256': digest(generator),
        'disassembler': {'path': str(dumpbin_path.resolve()), 'sha256': digest(disassembler)},
        'input_stability': 'Scan, dumpbin and generator bytes compared before and after collection; transient replacement is not prevented by locking',
        'disassembly_windows': windows,
        'derived_contract': {
            'entry': '0xBB0A14', 'calling_convention_observation': 'Four stack arguments; ret0x10',
            'registration': 'BB029C writes BB0A14 to callback table+2C; table+4 is the shared transport callback BB0614.',
            'separate_protocol_callback': {
                'table_slot': '0x1C', 'registration_address': '0xBB0280', 'entry': '0xBB07F4',
                'native_argument': 'DWORD at EBP+8',
                'guard': 'Scan receiver reached through155B988 must have word+7A equal3; meaning of this receiver field is not established here.',
                'initial_result': -1,
                'conditional_command': '0x8800', 'payload_formula': 'BYTE(argument) || 00',
                'callback_selector': '0x0C', 'callback_argument4': 750,
                'status_check': 'BB087E tests returned EAX; negative goes directly to cleanup.',
                'host_state_after_nonnegative_return': 'Store low word of argument toScan global155B9FC and return original argument.',
                'unknowns': 'Skipped or negative callback returns-1. Nonnegative host result and cached selection do not prove a physical VPW speed or firmware state. The separate VM opcode caller must be checked for whether it honors this return.',
            },
            'argument_1': {'stack_offset': 'EBP+8', 'native_consumption': 'low byte', 'firmware_meaning': None},
            'argument_2': {'stack_offset': 'EBP+0xC', 'native_consumption': 'signed DWORD', 'firmware_meaning': None},
            'argument_3': {'stack_offset': 'EBP+0x10', 'native_consumption': 'low byte', 'firmware_meaning': None},
            'argument_4': {'stack_offset': 'EBP+0x14', 'native_consumption': 'DWORD', 'firmware_meaning': None},
            'first_command': {
                'condition': 'argument_2 > 0 using signed comparison', 'command': '0x8603',
                'payload_bytes': 4,
                'payload_formula': 'LE16(argument_2 div1000) || LE16(argument_2 mod1000)',
                'division_derivation': 'Signed high multiply by0x10624DD3, arithmetic shift6, sign correction; positive input then remainder=input-quotient*1000',
                'range_checks': 'The quotient and remainder must each fit unsigned16; the native range-check helper is called otherwise. Maximum positive representable input is65535999.',
                'callback_address': '0xBB0614', 'callback_selector': '0x0C',
                'callback_argument_4': 100,
                'callback_metadata_pointer': None, 'callback_exception_status_pointer': None,
                'firmware_units_or_effect_verified': False,
            },
            'second_command': {
                'condition': 'Reached after optional8603 call; no returned-status comparison at callsite',
                'command': '0x8604', 'payload_bytes': 6,
                'payload_formula': 'BYTE(argument_1) || BYTE(argument_3) || LE32(argument_4)',
                'callback_address': '0xBB0614', 'callback_selector': '0x0C',
                'callback_argument_4': {'when_low_byte_argument_1_is_6': 2000, 'otherwise': 1000},
                'callback_metadata_pointer': None, 'callback_exception_status_pointer': None,
                'firmware_mode_speed_or_filter_verified': False,
            },
            'status_handling': {
                'shared_callback_error_handler': 'BB06F8 sets return local toFFFFFFFF and only writes exception details if final pointer is nonnull; BB0737 returns that local.',
                'setup_callsite': 'BB0A14 supplies null optional outputs, does not inspect the first call return, and enters cleanup immediately after the second call. It does not return an explicit structured programming or bus-setup result.',
                'implication': 'Constructed or logged setup commands do not prove successful firmware configuration; an independent implementation cannot infer success from this sequence alone.',
            },
        },
        'derived_examples': [
            {'arguments': [1, 1500, 0, 16], 'command_8603_payload_hex': '0100f401', 'command_8604_payload_hex': '010010000000'},
            {'arguments': [0, 0, 0, 0], 'command_8603_omitted': True, 'command_8604_payload_hex': '000000000000'},
        ],
        'unknowns': [
            'The Scan table+2C initializer is shown, but VM opcode-to-callback resolution and reconstructed operand values require the separate VM bridge evidence.',
            'The payload split is proven as arithmetic, not a firmware duration-unit or timeout definition.',
            'BB0614 argument4 values100/1000/2000 are retained as host-call parameters; their transport meaning follows through the separate IPC/HAPI path.',
            'Firmware effects, initial electrical bus state, speed transitions, masks, completion behavior and safe retries remain unqualified.',
            'Command8B01 is outside these callback windows and is not assigned a meaning.',
            'Bounded linear disassembly is not complete exception matching or runtime reachability evidence. No target code or device commands execute.',
        ],
        'target_executed': False, 'adapter_opened': False, 'vehicle_transmissions_enabled': False,
        'live_write_enabled': False, 'ready_to_flash': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scan', type=Path, required=True)
    parser.add_argument('--dumpbin', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.scan, args.dumpbin)
    with args.output.open('x', encoding='utf8', newline='\n') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'windows': len(WINDOWS), 'source_sha256': SCAN_SHA256, 'adapter_opened': False}))


if __name__ == '__main__':
    main()
