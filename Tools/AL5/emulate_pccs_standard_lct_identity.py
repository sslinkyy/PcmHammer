"""Pinned standard-LCT identification slice; synthetic string assignment.

This interior slice sets family/version but does not run full identification,
transport or hardware. Logging is disabled. Prior routing state is synthetic.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

START, STOP = 0x5da68e, 0x5da6f2
THIS, STACK = 0x10000000, 0x20000000


def permitted_pc(address, size):
    return size > 0 and START <= address and address+size <= STOP


def permitted_write(address, size, index):
    return size > 0 and (STACK <= address and address+size <= STACK+0x1000
                         or size == 1 and address in (THIS+index*0xa4+0x80, THIS+index*0xa4+0xb6))


def run(data, *, prior_alternate=0, index=3):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if (type(prior_alternate) is not int or not 0 <= prior_alternate <= 255
            or type(index) is not int or not 0 <= index <= 6):
        raise ValueError('Invalid synthetic standard LCT context')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+24+28)[0]
    size = struct.unpack_from('<I', data, pe+24+56)[0]
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(base, (size+0xfff)&~0xfff)
    for section in executable_sections(data):
        off = section['raw_offset']
        uc.mem_write(section['va'], data[off:off+section['raw_bytes']])
    uc.mem_map(THIS, 0x75000)
    uc.mem_map(STACK, 0x1000)
    uc.mem_write(THIS+0x72d90, bytes([prior_alternate]))
    uc.mem_write(THIS+index*0xa4+0x80, b'\x99')
    uc.mem_write(THIS+index*0xa4+0xb6, b'\x99')
    uc.mem_write(0x81d138, b'\x00')
    bp, sp = STACK+0x800, STACK+0x400
    uc.mem_write(bp-0x108, struct.pack('<II', index, THIS))
    uc.reg_write(UC_X86_REG_EBP, bp)
    uc.reg_write(UC_X86_REG_ESP, sp)
    calls, count = [], [0]

    def code(engine, address, size, _):
        if address == 0x407208:
            current = engine.reg_read(UC_X86_REG_ESP)
            target = struct.unpack('<I', engine.mem_read(current, 4))[0]
            if (target != 0x5da6dd or calls
                    or engine.reg_read(UC_X86_REG_EAX) != THIS+index*0xa4+0x44
                    or engine.reg_read(UC_X86_REG_EDX) != 0x5dc168):
                raise ValueError('Unexpected synthetic standard-LCT string assignment')
            calls.append({'kind': 'synthetic_identity_assignment'})
            engine.reg_write(UC_X86_REG_ESP, current+4)
            engine.reg_write(UC_X86_REG_EIP, target)
            return
        if not permitted_pc(address, size):
            raise ValueError(f'Unexpected standard-LCT PC {address:#x}+{size}')
        count[0] += 1

    def write(engine, access, address, size, value, _):
        if not permitted_write(address, size, index):
            raise ValueError(f'Unexpected standard-LCT write {address:#x}+{size}')

    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, STOP, count=1000)
    if uc.reg_read(UC_X86_REG_EIP) != STOP or uc.reg_read(UC_X86_REG_ESP) != sp or len(calls) != 1:
        raise ValueError('Standard-LCT slice did not reach declared boundary with balanced calls')
    return {'context': {'prior_alternate': prior_alternate, 'index': index},
            'final_alternate': uc.mem_read(THIS+0x72d90, 1)[0],
            'final_family': uc.mem_read(THIS+index*0xa4+0x80, 1)[0],
            'final_version': uc.mem_read(THIS+index*0xa4+0xb6, 1)[0],
            'calls': calls, 'instruction_observations': count[0],
            'full_identification_executed': False, 'transport_used': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def audit(data):
    cases = [run(data, prior_alternate=value, index=index) for value in (0, 1, 255) for index in (0, 3)]
    section = next(s for s in executable_sections(data)
                   if s['va'] <= START and STOP <= s['va']+s['raw_bytes'])
    offset = section['raw_offset']+START-section['va']
    return {'schema': 'pccs-standard-lct-identity-interior-native-slice-v1',
            'source_sha256': SOURCE_SHA256,
            'source_range': {'start': hex(START), 'exclusive_end': hex(STOP), 'file_offset': offset,
                             'sha256': hashlib.sha256(data[offset:offset+STOP-START]).hexdigest()},
            'cases': cases,
            'limitations': ['Interior classification slice only; not complete identification or its route prerequisites.',
                            'Prior route and selected index are synthetic; string assignment is replaced and logging disabled.',
                            'A retained flag does not prove an actual standard-LCT session reaches this context.'],
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


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
