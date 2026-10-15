"""Pinned ordinary PCCS boot-request slice; synthetic dispatch, no transport.

Security prerequisites, identification polling and the complete preparation
method do not execute. A zero status here is not programming readiness.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

START, STOP, ERROR_STOP = 0x5b8ed6, 0x5b8fee, 0x5b8fcf
THIS, STACK, STUB = 0x10000000, 0x20000000, 0x30000000


def permitted_pc(address, size):
    return size > 0 and (START <= address and address+size <= STOP
                         or address == STUB+0x100 and size == 3)


def permitted_write(address, size):
    return size > 0 and (STACK <= address and address+size <= STACK+0x10000
                         or THIS+0x52250 <= address and address+size <= THIS+0x52255
                         or address in (THIS+0x52894, THIS+0x5289c, THIS+0x528a0) and size == 4
                         or address == THIS+0x528a4 and size == 1)


def run(data, *, version=0, selector=0, host_status=0, response_byte=0):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if any(type(v) is not int or not 0 <= v <= 255
           for v in (version, selector, host_status, response_byte)):
        raise ValueError('Synthetic version, selector, status and response must be bytes')
    sections = executable_sections(data)
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ECX, UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+24+28)[0]
    size = struct.unpack_from('<I', data, pe+24+56)[0]
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(base, (size+0xfff)&~0xfff)
    for section in sections:
        off = section['raw_offset']
        uc.mem_write(section['va'], data[off:off+section['raw_bytes']])
    uc.mem_map(THIS, 0x75000)
    uc.mem_map(STACK, 0x10000)
    uc.mem_map(STUB, 0x1000)
    uc.mem_write(THIS, struct.pack('<I', STUB))
    uc.mem_write(STUB, struct.pack('<I', STUB+0x100))
    uc.mem_write(STUB+0x100, bytes.fromhex('c20800'))
    uc.mem_write(THIS+0xa4+0x80, b'\x01')
    uc.mem_write(THIS+0xa4+0xb6, bytes([version]))
    uc.mem_write(THIS+0x72d64, bytes([selector]))
    uc.mem_write(0x81d138, b'\x00')
    uc.reg_write(UC_X86_REG_ESI, THIS)
    uc.reg_write(UC_X86_REG_EBX, 1)
    uc.reg_write(UC_X86_REG_EBP, STACK+0x8000)
    sp = STACK+0x7f00
    uc.reg_write(UC_X86_REG_ESP, sp)
    calls, stop = [], []
    count = [0]

    def code(engine, address, size, _):
        if address == ERROR_STOP:
            stop.append('error_status_before_string_formatting')
            engine.emu_stop()
            return
        if not permitted_pc(address, size):
            raise ValueError(f'Unexpected preparation PC {address:#x}+{size}')
        count[0] += 1
        if address == STUB+0x100:
            args = struct.unpack('<II', engine.mem_read(engine.reg_read(UC_X86_REG_ESP)+4, 8))
            if engine.reg_read(UC_X86_REG_EAX) != THIS or engine.reg_read(UC_X86_REG_EDX) != 1 or engine.reg_read(UC_X86_REG_ECX) != 1000 or args != (1, 0):
                raise ValueError('Unexpected synthetic preparation dispatch')
            length = struct.unpack('<I', engine.mem_read(THIS+0x52894, 4))[0]
            if length not in (4, 5) or calls:
                raise ValueError('Unexpected preparation buffer length or repeated dispatch')
            calls.append({'internal_buffer_hex': bytes(engine.mem_read(THIS+0x52250, length)).hex(),
                          'timeout_parameter': 1000, 'request_class': 1,
                          'stack_arguments': list(args)})
            engine.mem_write(THIS+0x528a4, bytes([host_status]))
            engine.mem_write(THIS+0x52679, bytes([response_byte]))

    def write(engine, access, address, size, value, _):
        if not permitted_write(address, size):
            raise ValueError(f'Unexpected preparation write {address:#x}+{size}')

    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, STOP, count=2000)
    if uc.reg_read(UC_X86_REG_EIP) not in (STOP, ERROR_STOP) or uc.reg_read(UC_X86_REG_ESP) != sp or len(calls) != 1:
        raise ValueError('Preparation slice did not reach a declared boundary with balanced calls')
    return {'context': {'synthetic_family': 1, 'version': version, 'selector': selector,
                        'host_status': host_status, 'response_byte': response_byte},
            'dispatches': calls, 'final_host_status': uc.mem_read(THIS+0x528a4, 1)[0],
            'stop': stop[0] if stop else 'before_identification_poll',
            'instruction_observations': count[0], 'transport_used': False,
            'windows_apis_executed': False, 'live_write_enabled': False,
            'ready_to_flash': False, 'would_send': []}


def audit(data):
    contexts = ({}, {'response_byte': 1}, {'host_status': 1, 'response_byte': 1},
                {'host_status': 9}, *({'version': 5, 'selector': i} for i in (0, 1, 2)))
    cases = [run(data, **context) for context in contexts]
    section = next(s for s in executable_sections(data) if s['va'] <= START and STOP <= s['va']+s['raw_bytes'])
    offset = section['raw_offset']+START-section['va']
    return {'schema': 'pccs-prepare-request-native-slice-v1', 'source_sha256': SOURCE_SHA256,
            'source_range': {'start': hex(START), 'exclusive_end': hex(STOP),
                             'file_offset': offset, 'sha256': hashlib.sha256(data[offset:offset+STOP-START]).hexdigest()},
            'cases': cases,
            'limitations': ['Interior ordinary boot-request slice only; not the complete preparation helper.',
                            'Security prerequisites, error text formatting and identification polling do not execute.',
                            'Dispatcher status/response bytes are synthetic; zero status does not prove a positive acknowledgement.',
                            'Controller routing, transport, programming and recovery are not qualified.'],
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
