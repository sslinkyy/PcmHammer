"""Pinned PCCS WriteData native helper with synthetic dispatch/copy callbacks.

Internal buffers and host statuses are observed offline. No transport is run.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

THIS, STACK, INPUT, VTABLE, EXIT = 0x10000000, 0x20000000, 0x30000000, 0x40000000, 0x50000000
SEND, COPY = VTABLE+0x100, 0x404820
QUICK = VTABLE+0x200
START, END = 0x5b487c, 0x5b4d1c
GETTER, GETTER_END = 0x5b0af0, 0x5b0af8


def permitted_pc(address, size):
    return size > 0 and (START <= address and address+size <= END or
                        GETTER <= address and address+size <= GETTER_END or
                        address == COPY and size == 1 or address in (SEND, QUICK) and size == 3)


def permitted_write(address, size):
    return size > 0 and (STACK <= address and address+size <= STACK+0x10000 or
                        THIS+0x52250 <= address and address+size <= THIS+0x52258 or
                        address in (THIS+0x52894, THIS+0x5289c, THIS+0x528a0) and size == 4 or
                        address == THIS+0x528a4 and size == 1)


def run(data, *, payload=bytes(range(11)), address=0x123456, ccp=False,
        statuses=None, responses=None, quick=False, caller_flag=0):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= 256 or type(ccp) is not bool:
        raise ValueError('Requires 1..256 synthetic payload bytes and a Boolean CCP context')
    if type(quick) is not bool or type(caller_flag) is not int or not 0 <= caller_flag <= 255:
        raise ValueError('Requires Boolean QuickWrite flag and byte caller flag')
    if type(address) is not int or not 0 <= address <= (0xffffffff if ccp else 0xffffff)-len(payload):
        raise ValueError('Address escapes modeled 32-bit CCP / 24-bit ordinary context')
    for values in (statuses, responses):
        if values is not None and (not isinstance(values, tuple) or not values or
                                   any(type(x) is not int or not 0 <= x <= 255 for x in values)):
            raise ValueError('Synthetic responses must be nonempty byte tuples')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ECX, UC_X86_REG_ESP, UC_X86_REG_EIP
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    sections = executable_sections(data)
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+24+28)[0]
    size = struct.unpack_from('<I', data, pe+24+56)[0]
    uc.mem_map(base, (size+0xfff)&~0xfff)
    for section in sections:
        off = section['raw_offset']
        uc.mem_write(section['va'], data[off:off+section['raw_bytes']])
    for start, size in ((THIS, 0x75000), (STACK, 0x10000), (INPUT, 0x1000), (VTABLE, 0x1000), (EXIT, 0x1000)):
        uc.mem_map(start, size)
    def put(addr, value):
        uc.mem_write(addr, struct.pack('<I', value))
    put(THIS, VTABLE)
    put(VTABLE, SEND)
    put(VTABLE+0x18, QUICK)
    uc.mem_write(QUICK, bytes.fromhex('c20800'))
    uc.mem_write(THIS+0x68c60, bytes([int(quick)]))
    uc.mem_write(SEND, bytes.fromhex('c20800'))
    uc.mem_write(COPY, b'\xc3')
    uc.mem_write(INPUT, payload)
    uc.mem_write(0x81d108, bytes([int(ccp)]))
    for global_address in (0x81d148, 0x81d154, 0x81d190, 0x81d118):
        uc.mem_write(global_address, b'\x00')
    uc.mem_write(THIS+0xa4+0x80, b'\x01')  # Synthetic target index 1, LCT enum.
    uc.mem_write(THIS+0x74884, b'\x7a')  # Synthetic CCP field; no live value inferred.
    sp = STACK+0x8000
    uc.mem_write(sp, struct.pack('<IIIII', EXIT, caller_flag, 0, 1, len(payload)))
    uc.reg_write(UC_X86_REG_EAX, THIS)
    uc.reg_write(UC_X86_REG_EDX, INPUT)
    uc.reg_write(UC_X86_REG_ECX, address)
    uc.reg_write(UC_X86_REG_ESP, sp)
    dispatches, quick_calls = [], []
    instructions = [0]
    def code(engine, pc, size, _):
        if not permitted_pc(pc, size):
            raise ValueError(f'Unexpected native execution {pc:#x}+{size}')
        instructions[0] += 1
        eax, edx, ecx = (engine.reg_read(r) for r in (UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ECX))
        if pc == COPY:
            if not INPUT <= eax < INPUT+len(payload) or eax+ecx > INPUT+len(payload) or not 1 <= ecx <= (5 if ccp else 4):
                raise ValueError('Synthetic copy escaped input bounds')
            if edx != THIS+0x52250+(3 if ccp else 4) or not permitted_write(edx, ecx):
                raise ValueError('Synthetic copy escaped request buffer')
            engine.mem_write(edx, bytes(engine.mem_read(eax, ecx)))
        elif pc == QUICK:
            args = struct.unpack('<II', engine.mem_read(engine.reg_read(UC_X86_REG_ESP)+4, 8))
            if (eax, edx, ecx, args) != (THIS, INPUT, address, (1, len(payload))):
                raise ValueError('Unexpected synthetic QuickWrite arguments')
            quick_calls.append({'target_index': args[0], 'length': args[1],
                                'address': ecx, 'payload_hex': payload.hex(),
                                'body_executed': False})
        elif pc == SEND:
            if eax != THIS or edx != (3 if ccp else 5) or ecx != 500:
                raise ValueError('Unexpected synthetic dispatch identity/class/timeout')
            stack_args = struct.unpack('<II', engine.mem_read(engine.reg_read(UC_X86_REG_ESP)+4, 8))
            if stack_args != ((3, 0) if ccp else (1, 0)):
                raise ValueError('Unexpected synthetic dispatch stack arguments')
            length = struct.unpack('<I', engine.mem_read(THIS+0x52894, 4))[0]
            if not 1 <= length <= 8:
                raise ValueError('Synthetic dispatch length escaped request buffer')
            ordinal = len(dispatches)
            if statuses is not None and ordinal >= len(statuses) or responses is not None and ordinal >= len(responses):
                raise ValueError('Synthetic dispatch responses exhausted')
            status = 0 if statuses is None else statuses[ordinal]
            response = 0 if responses is None else responses[ordinal]
            dispatches.append({'request_class': edx, 'timeout': ecx, 'stack_arguments': list(stack_args),
                               'internal_buffer_hex': bytes(engine.mem_read(THIS+0x52250, length)).hex(),
                               'synthetic_host_status': status, 'synthetic_response_byte': response})
            engine.mem_write(THIS+0x528a4, bytes([status]))
            engine.mem_write(THIS+(0x52679 if ccp else 0x5267c), bytes([response]))
    def write(engine, access, addr, size, value, _):
        if not permitted_write(addr, size):
            raise ValueError(f'Unexpected native write {addr:#x}+{size}')
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, EXIT, count=100000)
    if uc.reg_read(UC_X86_REG_EIP) != EXIT or uc.reg_read(UC_X86_REG_ESP) != sp+20:
        raise ValueError('Native helper did not return with its RET16 stack balance')
    return {'context': {'payload_hex': payload.hex(), 'address': address, 'use_ccp_messages': ccp,
                        'synthetic_target_index': 1, 'synthetic_target_enum': 1,
                        'quick_route_flag': quick, 'caller_flag': caller_flag},
            'dispatches': dispatches, 'quick_calls': quick_calls, 'final_host_status': uc.mem_read(THIS+0x528a4, 1)[0],
            'instruction_observations': instructions[0], 'transport_used': False,
            'windows_apis_executed': False, 'live_write_enabled': False,
            'ready_to_flash': False, 'would_send': []}


def audit(data):
    contexts = ({}, {'ccp': True}, {'payload': bytes(4)}, {'payload': bytes(5), 'ccp': True},
                {'statuses': (9,)}, {'ccp': True, 'statuses': (9,)},
                {'ccp': True, 'responses': (1,)}, {'ccp': True, 'responses': (0, 1)},
                *({'responses': (response,)} for response in (1, 2, 4, 3)))
    cases = [run(data, **context) for context in contexts]
    source_ranges = []
    for start, end in ((START, END), (GETTER, GETTER_END)):
        section = next(s for s in executable_sections(data) if s['va'] <= start and end <= s['va']+s['raw_bytes'])
        offset = section['raw_offset']+start-section['va']
        source_ranges.append({'start': hex(start), 'exclusive_end': hex(end), 'file_offset': offset,
                              'sha256': hashlib.sha256(data[offset:offset+end-start]).hexdigest()})
    return {'schema': 'pccs-write-data-native-emulation-v1', 'source_sha256': SOURCE_SHA256,
            'source_ranges': source_ranges, 'cases': cases,
            'selection_cases': [run(data, quick=q, caller_flag=f, ccp=c)
                                for q in (False, True) for f in (0, 1, 255) for c in (False, True)],
            'limitations': ['Dispatch and copy are synthetic replacements; no real transport executes.',
                            'Use CCP Messages is synthetic configuration, not an LCT identity test.',
                            'Alternate FIL/bulk branches are disabled by synthetic zero state.',
                            'QuickWrite selection is observed at a synthetic VMT callback; its body is not executed here.',
                            'Internal request buffers and mapped host statuses do not prove AL5 compatibility.',
                            '256-byte payload cap is a synthetic harness resource bound, not a protocol limit.'],
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
