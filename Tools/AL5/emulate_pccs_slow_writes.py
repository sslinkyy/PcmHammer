"""Execute only pinned PCCS Slow Writes flag stores/toggle in private memory.

Config parsing and UI calls are excluded. The config snippet receives a
synthetic comparison result; the actual parser/string operands are preserved
as static evidence. No process, API, COM, dispatcher or transport executes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

FLAG, POINTER = 0x81d16c, 0x81ed28
STACK = 0x20000000
SLICES = {'config_store': (0x7d42c5, 0x7d42cd),
          'toggle': (0x7e1a1f, 0x7e1a33),
          'force_one_a': (0x7babdc, 0x7babe4),
          'force_one_b': (0x7bb106, 0x7bb10e)}


def permitted_pc(kind, address, size):
    if kind not in SLICES:
        return False
    start, stop = SLICES[kind]
    return size > 0 and start <= address and address+size <= stop


def permitted_write(address, size):
    return address == FLAG and size == 1


def run(data, *, kind='toggle', prior=1, comparison_equal=0):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if kind not in SLICES or any(type(v) is not int or v not in (0, 1)
                                 for v in (prior, comparison_equal)):
        raise ValueError('Invalid synthetic flag context')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EFLAGS
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+24+28)[0]
    size = struct.unpack_from('<I', data, pe+24+56)[0]
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(base, (size+0xfff)&~0xfff)
    for section in executable_sections(data):
        off = section['raw_offset']
        uc.mem_write(section['va'], data[off:off+section['raw_bytes']])
    # Source-bound indirection, synthetic flag state. No native pointer writer runs.
    uc.mem_write(POINTER, struct.pack('<I', FLAG))
    uc.mem_write(FLAG, bytes([prior]))
    uc.mem_map(STACK, 0x1000)
    uc.reg_write(UC_X86_REG_ESP, STACK+0x800)
    uc.reg_write(UC_X86_REG_EFLAGS, 2 | (0x40 if comparison_equal else 0))
    count = [0]

    def code(engine, address, length, _):
        if not permitted_pc(kind, address, length):
            raise ValueError(f'Unexpected Slow Writes PC {address:#x}+{length}')
        count[0] += 1

    def write(engine, access, address, length, value, _):
        if not permitted_write(address, length):
            raise ValueError(f'Unexpected Slow Writes write {address:#x}+{length}')

    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    start, stop = SLICES[kind]
    uc.emu_start(start, stop, count=100)
    if uc.reg_read(UC_X86_REG_EIP) != stop or uc.reg_read(UC_X86_REG_ESP) != STACK+0x800:
        raise ValueError('Slow Writes slice did not reach declared boundary')
    return {'context': {'kind': kind, 'prior': prior, 'comparison_equal': comparison_equal},
            'final_flag': uc.mem_read(FLAG, 1)[0], 'instruction_observations': count[0],
            'config_parser_executed': False, 'ui_executed': False, 'transport_used': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def audit(data):
    cases = [run(data, kind=kind, prior=prior, comparison_equal=equal)
             for kind in SLICES for prior in (0, 1)
             for equal in ((0, 1) if kind == 'config_store' else (0,))]
    ranges = []
    for name, (start, stop) in SLICES.items():
        section = next(s for s in executable_sections(data)
                       if s['va'] <= start and stop <= s['va']+s['raw_bytes'])
        offset = section['raw_offset']+start-section['va']
        ranges.append({'name': name, 'start': hex(start), 'exclusive_end': hex(stop),
                       'file_offset': offset,
                       'sha256': hashlib.sha256(data[offset:offset+stop-start]).hexdigest()})
    return {'schema': 'pccs-slow-writes-flag-native-slices-v1',
            'source_sha256': SOURCE_SHA256, 'source_ranges': ranges,
            'cases': cases, 'live_write_enabled': False, 'ready_to_flash': False, 'would_send': [],
            'limitations': ['Interior flag-store/toggle slices only; callers and parsers do not execute.',
                            'Prior state and comparison equality are synthetic.',
                            'Full selection, actual AL5 routing, programming and recovery remain unproven.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('exe', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Output exists; refusing overwrite')
    result = audit(args.exe.read_bytes())
    result['source_path'] = str(args.exe.resolve())
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print(json.dumps({'cases': len(result['cases']), 'ready_to_flash': False}))


if __name__ == '__main__':
    main()
