"""Reconstruct pinned DOC LCT tables in isolated memory; no host/vehicle I/O.

Requires optional Unicorn 2.1.4. Only four exact initializer ranges may execute;
writes are restricted to the table region and synthetic stack. No imports,
callbacks, DLL entry point, COM objects or adapter APIs are executed.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

from inspect_pccs_methods import executable_sections


SOURCE_SHA256 = '023185650cddbd015a16eef4a8d58b2d6e173519ff07dc6434cb1552a55389c8'
INITIALIZERS = ((0x10001064, 0x10001814), (0x10001823, 0x10002bc9),
                (0x10002bc9, 0x10002cc3), (0x10002cc3, 0x10004ac8))
STACK, EXIT = 0x20000000, 0x30000000
TABLE_START, TABLE_END = 0x10071018, 0x10076bf4
# Catalog and row counts derived from native function 0x10008ee6.
CATALOG = ((0, 0x10071120, 3), (1, 0x10071228, 68),
           (2, 0x10073220, 1), (3, 0x10072988, 1),
           (4, 0x10073278, 1), (5, 0x100729e0, 2),
           (6, 0x10072a90, 22), (7, 0x100732d0, 25),
           (8, 0x10073bc0, 2), (9, 0x10073b68, 1),
           (11, 0x10073c70, 6), (12, 0x100710c8, 1),
           (13, 0x10071018, 2))


def permitted_pc(address, start, end):
    return start <= address < end


def permitted_write(address, size):
    return size > 0 and (TABLE_START <= address and address+size <= TABLE_END
                         or STACK <= address and address+size <= STACK+0x10000)


def reconstruct(data):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('Pinned LctTransBusRules.dll hash differs; no emulation')
    executable_sections(data)  # Validate file-backed PE32 layout before mapping.
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    optional = pe+24
    base = struct.unpack_from('<I', data, optional+28)[0]
    image_size = struct.unpack_from('<I', data, optional+56)[0]
    section_count = struct.unpack_from('<H', data, pe+6)[0]
    table = optional+struct.unpack_from('<H', data, pe+20)[0]
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('This audit requires the validated Unicorn 2.1.4 runtime')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EFLAGS, UC_X86_REG_EIP
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(base, (image_size+4095) & ~4095)
    for i in range(section_count):
        _, rva, raw_size, raw_offset = struct.unpack_from('<IIII', data, table+i*40+8)
        if raw_size:
            uc.mem_write(base+rva, data[raw_offset:raw_offset+raw_size])
    uc.mem_map(STACK, 0x10000)
    uc.mem_map(EXIT, 0x1000)
    active = [0, 0]
    instructions = [0]

    def code(engine, address, size, user):
        if not permitted_pc(address, *active):
            raise ValueError(f'Unexpected execution {address:#x}')
        instructions[0] += 1

    def write(engine, access, address, size, value, user):
        if not permitted_write(address, size):
            raise ValueError(f'Unexpected emulated write {address:#x}+{size}')

    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    runs = []
    for start, end in INITIALIZERS:
        active[:] = [start, end]
        before = instructions[0]
        uc.reg_write(UC_X86_REG_ESP, STACK+0x8000)
        uc.reg_write(UC_X86_REG_EFLAGS, 2)
        uc.mem_write(STACK+0x8000, struct.pack('<I', EXIT))
        uc.emu_start(start, EXIT, count=20000)
        if uc.reg_read(UC_X86_REG_EIP) != EXIT:
            raise ValueError('Initializer exhausted instruction bound without returning')
        runs.append({'start': hex(start), 'exclusive_end': hex(end),
                     'code_sha256': hashlib.sha256(bytes(uc.mem_read(start, end-start))).hexdigest(),
                     'instruction_observations': instructions[0]-before,
                     'returned_to_synthetic_exit': True})
    return uc, runs


def descriptors(read, address, count):
    rows = []
    for index in range(count):
        raw = bytes(read(address+index*88, 88))
        if len(raw) != 88:
            raise ValueError('Incomplete descriptor read')
        length = raw[8]
        if length > 40:
            raise ValueError('Descriptor length exceeds its storage span')
        rows.append({'index': index, 'address': hex(address+index*88),
                     'raw_hex': raw.hex(),
                     'event_handle_initial_raw': hex(struct.unpack_from('<I', raw)[0]),
                     'timeout_parameter': struct.unpack_from('<I', raw, 4)[0],
                     'internal_request_hex': raw[9:9+length].hex(),
                     'opaque_remaining_storage_hex': raw[9+length:].hex()})
    return rows


def audit(data):
    uc, runs = reconstruct(data)
    tables = [{'selector': selector, 'base_address': hex(address),
               'rows': descriptors(uc.mem_read, address, count)}
              for selector, address, count in CATALOG]
    startup = next(t for t in tables if t['selector'] == 1)['rows']
    resets = next(t for t in tables if t['selector'] == 7)['rows']
    if startup[14]['internal_request_hex'] != '12ffffff':
        raise ValueError('Startup diagnostic-poll anchor differs')
    if resets[12]['internal_request_hex'] != 'ae01000020200000':
        raise ValueError('Adaptive reset anchor differs')
    services = Counter(r['internal_request_hex'][:2] for t in tables for r in t['rows']
                       if r['internal_request_hex'])
    return {'schema': 'lct-command-table-audit-v1', 'source_sha256': SOURCE_SHA256,
            'emulator': 'Unicorn 2.1.4',
            'initializers': runs, 'tables': tables,
            'internal_request_leading_byte_counts': dict(sorted(services.items())),
            'host_prefixes': {'j1939': bytes(uc.mem_read(0x10071000, 6)).hex(),
                              'j1850': bytes(uc.mem_read(0x10071008, 6)).hex(),
                              'alternate_j1850': bytes(uc.mem_read(0x10071010, 6)).hex()},
            'scope': 'Four source-pinned initializers in private Unicorn memory; not host execution',
            'limitations': ['Tables may be modified later; this is not a live-state snapshot.',
                            'Internal request and match fields are not qualified wire frames.',
                            'Only the selected initializers ran; later changes are not modeled.',
                            'No conclusion that programming services are absent from the whole application.'],
            'transport_used': False, 'windows_apis_executed': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dll', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Output exists; refusing overwrite')
    result = audit(args.dll.read_bytes())
    result['source_path'] = str(args.dll.resolve())
    with args.output.open('x', encoding='utf8') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print(json.dumps({'tables': len(result['tables']),
                      'rows': sum(len(t['rows']) for t in result['tables']),
                      'services': result['internal_request_leading_byte_counts'],
                      'ready_to_flash': False}))


if __name__ == '__main__':
    main()
