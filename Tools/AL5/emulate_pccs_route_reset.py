"""Pinned PCCS reset prefix and independent identification-selection composition.

No full initialization, identification I/O, dispatcher or transport executes.
Identity and Slow Writes are synthetic. Slice composition is explicitly not a
complete call-path emulation or proof of a connected controller's capability.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections
from emulate_pccs_quick_route import run as run_selection

START, STOP = 0x5dcb40, 0x5dcb89
THIS, STACK = 0x10000000, 0x20000000


def permitted_pc(address, size):
    return size > 0 and START <= address and address+size <= STOP


def permitted_write(address, size):
    if size <= 0:
        return False
    if STACK <= address and address+size <= STACK+0x10000:
        return True
    if size != 1:
        return False
    offset = address-THIS
    return (offset == 0x68c60 or 0x72564 <= offset < 0x72d64
            or 0 <= offset-0xb4 < 2048*0xa4 and (offset-0xb4) % 0xa4 in (0, 1))


def run(data, *, prior=1):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if type(prior) is not int or prior not in (0, 1):
        raise ValueError('Requires synthetic Boolean route state')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ESP, UC_X86_REG_EIP
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+24+28)[0]
    size = struct.unpack_from('<I', data, pe+24+56)[0]
    uc.mem_map(base, (size+0xfff)&~0xfff)
    for section in executable_sections(data):
        off = section['raw_offset']
        uc.mem_write(section['va'], data[off:off+section['raw_bytes']])
    uc.mem_map(THIS, 0x75000)
    uc.mem_map(STACK, 0x10000)
    uc.mem_write(THIS+0x68c60, bytes([prior]))
    for i in range(2048):
        uc.mem_write(THIS+i*0xa4+0xb4, b'\xa5\xa5')
    uc.mem_write(THIS+0x72564, b'\xa5'*2048)
    sp = STACK+0x8000
    uc.reg_write(UC_X86_REG_EAX, THIS)
    uc.reg_write(UC_X86_REG_ESP, sp)
    instructions, writes = [0], [0]
    def code(engine, pc, size, _):
        if not permitted_pc(pc, size):
            raise ValueError(f'Unexpected reset PC {pc:#x}+{size}')
        instructions[0] += 1
    def write(engine, access, addr, size, value, _):
        if not permitted_write(addr, size):
            raise ValueError(f'Unexpected reset write {addr:#x}+{size}')
        if not STACK <= addr < STACK+0x10000:
            writes[0] += 1
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, STOP, count=40000)
    if uc.reg_read(UC_X86_REG_EIP) != STOP or uc.reg_read(UC_X86_REG_ESP) != sp-24:
        raise ValueError('Reset prefix did not reach boundary with expected stack frame')
    return {'prior_route_flag': prior,
            'final_route_flag': uc.mem_read(THIS+0x68c60, 1)[0],
            'indexed_marker_pairs_zero': all(bytes(uc.mem_read(THIS+i*0xa4+0xb4, 2)) == b'\0\0'
                                             for i in range(2048)),
            'auxiliary_bytes_zero': bytes(uc.mem_read(THIS+0x72564, 2048)) == bytes(2048),
            'object_write_observations': writes[0], 'instruction_observations': instructions[0],
            'identification_executed': False, 'transport_used': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def audit(data):
    resets = [run(data, prior=p) for p in (0, 1)]
    contexts = [dict(index=i, version=0, family=1, identity=x, disabled=d)
                for i in (0, 3) for x in (15, 16) for d in (0, 1)]
    reset_flag = resets[1]['final_route_flag']
    cases = [{'context': c,
              'selection_without_reset': run_selection(data, prior=1, **c),
              'selection_after_reset': run_selection(data, prior=reset_flag, **c)}
             for c in contexts]
    section = next(s for s in executable_sections(data)
                   if s['va'] <= START and STOP <= s['va']+s['raw_bytes'])
    off = section['raw_offset']+START-section['va']
    return {'schema': 'pccs-route-reset-selection-composition-v1',
            'source_sha256': SOURCE_SHA256,
            'source_range': {'start': hex(START), 'exclusive_end': hex(STOP), 'file_offset': off,
                             'sha256': hashlib.sha256(data[off:off+STOP-START]).hexdigest()},
            'reset_cases': resets, 'selection_compositions': cases,
            'limitations': ['Reset prefix only; full reset routine and identification do not execute.',
                            'Identification selection runs as a separate existing native slice.',
                            'Identity bytes, version, family, index and Slow Writes are synthetic.',
                            'Composition does not prove the caller reaches reset or selection.',
                            'No controller I/O, programming, acceptance or recovery proof.'],
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
    print(json.dumps({'reset_cases': len(result['reset_cases']),
                      'selection_compositions': len(result['selection_compositions']),
                      'ready_to_flash': False}))


if __name__ == '__main__':
    main()
