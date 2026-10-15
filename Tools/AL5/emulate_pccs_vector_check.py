"""Pinned PCCS vector comparison/failure slice with synthetic host callbacks.

Begins after ReadData: the read buffer, status, file blocks and prior flags are
synthetic. No read, programming, UI, Windows API or transport executes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

START, SUCCESS, FAILURE = 0x7baaa5, 0x7bac36, 0x7bbb31
GETTER, GETTER_END = 0x5b0af0, 0x5b0af8
THIS, STACK, FILES, LENGTHS, BLOCKS, UI = (0x10000000, 0x20000000, 0x30000000,
                                         0x30001000, 0x30002000, 0x40000000)
FLAG, POINTER = 0x81d16c, 0x81ed28
CALLBACKS = {0x5d3310: ('host_helper', b'\xc3'),
             0x415a88: ('format_coordinate', b'\xc3'),
             0x408a98: ('concat_log_text', bytes.fromhex('c20c00')),
             0x7b0c90: ('log_vector_failure', b'\xc3'),
             0x53456c: ('disable_control', b'\xc3'),
             0x521d84: ('update_fast_write_ui', b'\xc3')}


def permitted_pc(address, size):
    return size > 0 and (START <= address and address+size <= SUCCESS
                         or GETTER <= address and address+size <= GETTER_END
                         or address in CALLBACKS and size == len(CALLBACKS[address][1]))


def permitted_write(address, size):
    return size > 0 and (STACK <= address and address+size <= STACK+0x10000
                         or address == FLAG and size == 1)


def run(data, *, expected=bytes(0x500), observed=bytes(0x410),
        lengths=(256, 256, 256, 256, 16), status=0, prior_slow=0, prior_route=1):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if (not isinstance(expected, bytes) or len(expected) != 0x500
            or not isinstance(observed, bytes) or len(observed) != 0x410
            or not isinstance(lengths, tuple) or len(lengths) != 5
            or any(type(x) is not int or not 0 <= x <= 256 for x in lengths)
            or type(status) is not int or not 0 <= status <= 255
            or any(type(x) is not int or x not in (0, 1) for x in (prior_slow, prior_route))):
        raise ValueError('Invalid synthetic vector context')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX, UC_X86_REG_EDX
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+24+28)[0]
    size = struct.unpack_from('<I', data, pe+24+56)[0]
    uc.mem_map(base, (size+0xfff)&~0xfff)
    for section in executable_sections(data):
        off = section['raw_offset']
        uc.mem_write(section['va'], data[off:off+section['raw_bytes']])
    for addr, size in ((THIS, 0x75000), (STACK, 0x10000), (FILES, 0x4000), (UI, 0x1000)):
        uc.mem_map(addr, size)
    def put(addr, value):
        uc.mem_write(addr, struct.pack('<I', value))
    # Use a private reference slot; the native source dereferences it twice.
    put(0x81f328, FILES+0xff0)
    put(FILES+0xff0, THIS)
    put(0x81f12c, FILES)
    put(0x81ed44, LENGTHS)
    put(POINTER, FLAG)
    put(0x9d3158, UI)
    put(UI+0x3e8, UI)
    put(UI+0x420, UI)
    uc.mem_write(FLAG, bytes([prior_slow]))
    uc.mem_write(THIS+0x68c60, bytes([prior_route]))
    uc.mem_write(THIS+0x528a4, bytes([status]))
    uc.mem_write(0x9df398, observed)
    for i, length in enumerate(lengths):
        put(FILES+(0x200+i)*4, BLOCKS+i*256)
        put(LENGTHS+(0x200+i)*4, length)
    uc.mem_write(BLOCKS, expected)
    for addr, (_, replacement) in CALLBACKS.items():
        uc.mem_write(addr, replacement)
    bp, parent, sp = STACK+0x8000, STACK+0xc000, STACK+0x7000
    put(bp+8, parent)
    put(parent-0xf8, 0x410)
    uc.reg_write(UC_X86_REG_EBP, bp)
    uc.reg_write(UC_X86_REG_ESP, sp)
    calls, comparisons, instructions, mismatch = [], [], [0], []
    def integer(addr):
        return struct.unpack('<I', uc.mem_read(addr, 4))[0]
    def code(engine, pc, size, _):
        if pc in (SUCCESS, FAILURE):
            engine.emu_stop()
            return
        if not permitted_pc(pc, size):
            raise ValueError(f'Unexpected vector PC {pc:#x}+{size}')
        instructions[0] += 1
        if pc in CALLBACKS:
            eax, edx = engine.reg_read(UC_X86_REG_EAX), engine.reg_read(UC_X86_REG_EDX)
            if pc == 0x5d3310 and (eax, edx) != (THIS, 0):
                raise ValueError('Unexpected synthetic host-helper context')
            if pc == 0x415a88 and (eax, edx) not in (
                    (integer(parent-0xfc), 4), (integer(parent-0x100), 2)):
                raise ValueError('Unexpected synthetic coordinate format')
            if pc == 0x408a98 and edx != 3:
                raise ValueError('Unexpected synthetic string count')
            if pc == 0x7b0c90 and eax & 255 != 0xf8:
                raise ValueError('Unexpected synthetic failure log status')
            if pc in (0x53456c, 0x521d84) and (eax, edx) != (UI, 0):
                raise ValueError('Unexpected synthetic UI callback context')
            calls.append({'name': CALLBACKS[pc][0], 'synthetic': True})
        if pc == 0x7bab1d:
            comparisons.append(integer(parent-0x104))
        if pc == 0x7bab4a:
            mismatch.append({'segment': integer(parent-0xfc),
                             'byte_offset': integer(parent-0x100),
                             'read_offset': integer(parent-0x104)})
    def write(engine, access, addr, size, value, _):
        if not permitted_write(addr, size):
            raise ValueError(f'Unexpected vector write {addr:#x}+{size}')
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, 0, count=100000)
    stop = uc.reg_read(UC_X86_REG_EIP)
    if stop not in (SUCCESS, FAILURE) or uc.reg_read(UC_X86_REG_ESP) != sp:
        raise ValueError('Vector slice did not reach declared boundary with balanced calls')
    return {'context': {'lengths': list(lengths), 'read_status': status,
                        'prior_slow': prior_slow, 'prior_route': prior_route,
                        'expected_sha256': hashlib.sha256(expected).hexdigest(),
                        'observed_sha256': hashlib.sha256(observed).hexdigest()},
            'stop_address': hex(stop), 'vector_mismatch': mismatch,
            'comparison_offsets': comparisons, 'synthetic_callbacks': calls,
            'final_slow': uc.mem_read(FLAG, 1)[0],
            'final_route': uc.mem_read(THIS+0x68c60, 1)[0],
            'instruction_observations': instructions[0],
            'transport_used': False, 'read_executed': False, 'live_write_enabled': False,
            'ready_to_flash': False, 'would_send': []}


def audit(data):
    contexts = [{}, {'status': 9}, {'lengths': (0, 0, 0, 0, 16)},
                {'lengths': (1, 256, 256, 256, 16), 'observed': bytes(1)+b'X'+bytes(0x40e)}]
    for offset in (0, 255, 256, 1024, 1039):
        contexts.append({'observed': bytes(offset)+b'X'+bytes(0x40f-offset)})
    cases = [run(data, **c) for c in contexts]
    ranges = []
    for start, stop in ((START, SUCCESS), (GETTER, GETTER_END)):
        section = next(s for s in executable_sections(data)
                       if s['va'] <= start and stop <= s['va']+s['raw_bytes'])
        offset = section['raw_offset']+start-section['va']
        ranges.append({'start': hex(start), 'exclusive_end': hex(stop), 'file_offset': offset,
                       'sha256': hashlib.sha256(data[offset:offset+stop-start]).hexdigest()})
    return {'schema': 'pccs-vector-check-native-slice-v1', 'source_sha256': SOURCE_SHA256,
            'source_ranges': ranges, 'cases': cases, 'live_write_enabled': False, 'ready_to_flash': False,
            'would_send': [], 'limitations': [
                'Interior slice after ReadData; outer gate and successful I/O are not executed.',
                'Expected blocks, read buffer, status and prior flags are synthetic.',
                'Formatting, log, host helper and UI are synthetic callbacks.',
                'Stops at success continuation or failure cleanup; no outer retry executes.',
                'Absent/short blocks skip failure recognition; file pointer validity is assumed.',
                'No programming, controller acceptance, full-image verification or recovery proof.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('exe', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Output exists; refusing overwrite')
    data = args.exe.read_bytes()
    result = audit(data)
    result['source_path'] = str(args.exe.resolve())
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print(json.dumps({'cases': len(result['cases']), 'ready_to_flash': False}))


if __name__ == '__main__':
    main()
