"""Pinned post-CAN-helper fallback gate; no calls, transport or controller.

The supplied helper state and host status are synthetic. This interior gate
alone cannot prove that a real helper/AL5 produces the supplied combination.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

START, STOP = 0x5d91a1, 0x5d91cf
THIS, STACK = 0x10000000, 0x20000000
BOUNDARIES = {0x5d9ba9: 'ordinary_fallback', 0x5dc085: 'identified_or_other_exit'}


def permitted_pc(address, size):
    return size > 0 and START <= address and address+size <= STOP


def permitted_write(address, size):
    return False


def run(data, *, helper_flag=0, identification_word=0, host_status=9, alternate=1):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if (any(type(v) is not int or not 0 <= v <= 255 for v in (helper_flag, host_status, alternate))
            or type(identification_word) is not int or not 0 <= identification_word <= 0xffff):
        raise ValueError('Invalid synthetic post-helper context')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP
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
    uc.mem_write(THIS+3*0xa4+0x84, struct.pack('<H', identification_word))
    uc.mem_write(THIS+0x528a4, bytes([host_status]))
    uc.mem_write(THIS+0x72d90, bytes([alternate]))
    uc.mem_write(0x81d118, bytes([helper_flag]))
    bp, sp = STACK+0x800, STACK+0x400
    uc.mem_write(bp-0x108, struct.pack('<II', 3, THIS))
    uc.reg_write(UC_X86_REG_EBP, bp)
    uc.reg_write(UC_X86_REG_ESP, sp)
    stops, count = [], [0]

    def code(engine, address, size, _):
        if address in BOUNDARIES:
            stops.append(BOUNDARIES[address])
            engine.emu_stop()
            return
        if not permitted_pc(address, size):
            raise ValueError(f'Unexpected post-helper PC {address:#x}+{size}')
        count[0] += 1

    def write(engine, access, address, size, value, _):
        if not permitted_write(address, size):
            raise ValueError(f'Unexpected post-helper write {address:#x}+{size}')

    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, 0, count=100)
    if (uc.reg_read(UC_X86_REG_EIP) not in BOUNDARIES or len(stops) != 1
            or uc.reg_read(UC_X86_REG_ESP) != sp):
        raise ValueError('Post-helper gate did not reach declared boundary')
    return {'context': {'helper_flag': helper_flag, 'identification_word': identification_word,
                        'host_status': host_status, 'alternate': alternate, 'index': 3},
            'boundary': stops[0], 'final_host_status': uc.mem_read(THIS+0x528a4, 1)[0],
            'final_alternate': uc.mem_read(THIS+0x72d90, 1)[0],
            'instruction_observations': count[0], 'helper_executed': False,
            'full_identification_executed': False, 'transport_used': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}



def run_identifier_producer(data, *, response_byte=0, index=3):
    """Actual three-instruction E2 reply-byte copy, not reply acceptance."""
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if any(type(v) is not int or not 0 <= v <= 255 for v in (response_byte, index)):
        raise ValueError('Invalid synthetic identifier producer context')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_ESI, UC_X86_REG_EIP
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+24+28)[0]
    size = struct.unpack_from('<I', data, pe+24+56)[0]
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(base, (size+0xfff)&~0xfff)
    for section in executable_sections(data):
        off = section['raw_offset']
        uc.mem_write(section['va'], data[off:off+section['raw_bytes']])
    uc.mem_map(THIS, 0x75000)
    uc.mem_write(THIS+0x528b9, bytes([response_byte]))
    uc.mem_write(0x81d0f4, struct.pack('<I', index))
    destination = THIS+index*0xa4+0x84
    uc.mem_write(destination, b'\xff\xff')
    uc.reg_write(UC_X86_REG_ESI, THIS)
    count = [0]

    def code(engine, address, size, _):
        if not (size > 0 and 0x5bba73 <= address and address+size <= 0x5bba89):
            raise ValueError('Unexpected identifier producer PC')
        count[0] += 1

    def write(engine, access, address, size, value, _):
        if address != destination or size != 2:
            raise ValueError('Unexpected identifier producer write')

    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(0x5bba73, 0x5bba89, count=10)
    if uc.reg_read(UC_X86_REG_EIP) != 0x5bba89 or count[0] != 3:
        raise ValueError('Identifier producer did not reach declared boundary')
    section = next(s for s in executable_sections(data)
                   if s['va'] <= 0x5bba73 and 0x5bba89 <= s['va']+s['raw_bytes'])
    offset = section['raw_offset']+0x5bba73-section['va']
    return {'context': {'response_byte': response_byte, 'index': index},
            'identification_word': struct.unpack('<H', uc.mem_read(destination, 2))[0],
            'source_range': {'start': '0x5bba73', 'exclusive_end': '0x5bba89',
                             'file_offset': offset,
                             'sha256': hashlib.sha256(data[offset:offset+0x16]).hexdigest()},
            'instruction_observations': count[0], 'full_probe_executed': False,
            'reply_acceptance_proven': False, 'transport_used': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def audit(data):
    cases = [run(data, helper_flag=flag, identification_word=word, host_status=status)
             for flag in (0, 1) for word in (0, 1, 0xffff) for status in (0, 9)]
    section = next(s for s in executable_sections(data)
                   if s['va'] <= START and STOP <= s['va']+s['raw_bytes'])
    offset = section['raw_offset']+START-section['va']
    return {'schema': 'pccs-can-post-helper-native-gate-v1', 'source_sha256': SOURCE_SHA256,
            'source_range': {'start': hex(START), 'exclusive_end': hex(STOP), 'file_offset': offset,
                             'sha256': hashlib.sha256(data[offset:offset+STOP-START]).hexdigest()},
            'cases': cases,
            'identifier_producer_cases': [run_identifier_producer(data, response_byte=value) for value in (0, 1, 255)],
            'limitations': ['Interior post-helper gate only; helper outputs are synthetic.',
                            'No helper, ordinary dispatcher, full identification or actual AL5 reply executes.',
                            'A matching host path does not prove controller compatibility or recovery.'],
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
