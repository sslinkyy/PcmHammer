"""Pinned PCCS identification route slice and native identity getter, offline only.

Runs interior selection instructions and the pure getter in isolated memory.
No dispatcher, COM, executable entry point, API, adapter or controller executes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

START, STOP = 0x5da7b1, 0x5dc04b
GETTER_START, GETTER_STOP = 0x5ae00c, 0x5ae049
THIS, STACK = 0x10000000, 0x20000000


def permitted_pc(address, size):
    return size > 0 and (START <= address and address+size <= 0x5da891
                         or GETTER_START <= address and address+size <= GETTER_STOP)


def permitted_write(address, size):
    return size > 0 and (STACK <= address and address+size <= STACK+0x10000
                         or address == THIS+0x68c60 and size == 1)


def run(data, *, index=3, version=0, family=1, identity=16, disabled=0, prior=0):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if (any(type(v) is not int or not 0 <= v <= 255 for v in (version, family))
            or type(index) is not int or not 0 <= index <= 3
            or type(identity) is not int or not 0 <= identity <= 0xffffff
            or any(type(v) is not int or v not in (0, 1) for v in (disabled, prior))):
        raise ValueError('Invalid synthetic route context')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+24+28)[0]
    image_size = struct.unpack_from('<I', data, pe+24+56)[0]
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(base, (image_size+0xfff)&~0xfff)
    for section in executable_sections(data):
        off = section['raw_offset']
        uc.mem_write(section['va'], data[off:off+section['raw_bytes']])
    uc.mem_map(THIS, 0x75000)
    uc.mem_map(STACK, 0x10000)
    uc.mem_write(THIS+index*0xa4+0x80, bytes([family]))
    uc.mem_write(THIS+index*0xa4+0xb6, bytes([version]))
    uc.mem_write(THIS+index*0xa4+0x50, identity.to_bytes(3, 'big'))
    uc.mem_write(THIS+0x68c60, bytes([prior]))
    uc.mem_write(0x81d16c, bytes([disabled]))
    bp, sp = STACK+0x8000, STACK+0x7000
    uc.mem_write(bp-0x108, struct.pack('<II', index, THIS))
    uc.reg_write(UC_X86_REG_EBP, bp)
    uc.reg_write(UC_X86_REG_ESP, sp)
    calls, count = [], [0]

    def code(engine, address, size, _):
        if not permitted_pc(address, size):
            raise ValueError(f'Unexpected route PC {address:#x}+{size}')
        count[0] += 1
        if address == GETTER_START:
            calls.append('native_identity_getter')

    def write(engine, access, address, size, value, _):
        if not permitted_write(address, size):
            raise ValueError(f'Unexpected route write {address:#x}+{size}')

    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, STOP, count=1000)
    if uc.reg_read(UC_X86_REG_EIP) != STOP or uc.reg_read(UC_X86_REG_ESP) != sp:
        raise ValueError('Route slice did not stop at declared boundary with balanced calls')
    return {'context': {'index': index, 'version': version, 'family': family,
                        'identity_bytes': identity.to_bytes(3, 'big').hex(),
                        'global_disabled': disabled, 'prior_route_flag': prior},
            'final_route_flag': uc.mem_read(THIS+0x68c60, 1)[0],
            'calls': calls, 'instruction_observations': count[0],
            'transport_used': False, 'windows_apis_executed': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def audit(data):
    contexts = [dict(index=i, version=v, disabled=d, prior=p)
                for i in (0, 3) for v in (0, 3, 6, 7, 8, 12, 13, 14)
                for d in (0, 1) for p in (0, 1)]
    contexts += [dict(identity=x, prior=p) for x in (0, 15, 16, 0xffffff) for p in (0, 1)]
    contexts += [dict(family=0, identity=x) for x in (0x100000, 0x0f0000, 0x3f0000, 0xff0000)]
    cases = [run(data, **context) for context in contexts]
    ranges = []
    for start, stop in ((START, 0x5da891), (GETTER_START, GETTER_STOP)):
        section = next(s for s in executable_sections(data)
                       if s['va'] <= start and stop <= s['va']+s['raw_bytes'])
        offset = section['raw_offset']+start-section['va']
        ranges.append({'start': hex(start), 'exclusive_end': hex(stop),
                       'file_offset': offset,
                       'sha256': hashlib.sha256(data[offset:offset+stop-start]).hexdigest()})
    return {'schema': 'pccs-quick-route-native-slice-v1', 'source_sha256': SOURCE_SHA256,
            'source_ranges': ranges,
            'cases': cases, 'live_write_enabled': False, 'ready_to_flash': False, 'would_send': [],
            'limitations': ['Interior identification route slice only; outer family/type dispatch is assumed.',
                            'Identity, global disable flag and prior state are synthetic.',
                            'A selected host route does not establish actual AL5 capability or wire behavior.',
                            'No QuickWriteData, dispatcher, API, COM, controller or recovery execution.']}


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
