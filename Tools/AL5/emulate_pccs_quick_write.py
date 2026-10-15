"""Pinned PCCS QuickWriteData ordinary branch with synthetic callbacks only.

No dispatcher, transport, Windows API, or controller code executes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

THIS, STACK, INPUT, EXIT = 0x10000000, 0x20000000, 0x30000000, 0x50000000
START, END = 0x5b4f80, 0x5b538c
COPY, PREFIX, SEND, SLEEP, CLEAN, ARRAY_CLEAN = 0x404820, 0x5a8c58, 0x5a9658, 0x40e3e4, 0x4084c8, 0x40a3cc
STUBS = {COPY: b'\xc3', PREFIX: b'\xc3', SEND: b'\xc3', SLEEP: bytes.fromhex('c20400'), CLEAN: b'\xc3', ARRAY_CLEAN: b'\xc3'}


def permitted_pc(address, size):
    return size > 0 and (START <= address and address+size <= END or
                        address in STUBS and size == len(STUBS[address]))


def permitted_write(address, size):
    return size > 0 and (STACK <= address and address+size <= STACK+0x10000 or
                        address == 0 and size == 4 or
                        THIS+0x52250 <= address and address+size <= THIS+0x52258 or
                        address in (THIS+0x52894, THIS+0x5289c, THIS+0x528a0) and size == 4 or
                        address == THIS+0x528a4 and size == 1 or
                        address == THIS+0x52898 and size == 2)


def run(data, *, payload=bytes(range(11)), address=0x123456, statuses=None, initial_host_status=0):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= 256:
        raise ValueError('Requires 1..256 synthetic payload bytes')
    if type(address) is not int or not 0 <= address <= 0xffffff-len(payload):
        raise ValueError('Address escapes modeled 24-bit ordinary context')
    if type(initial_host_status) is not int or not 0 <= initial_host_status <= 255:
        raise ValueError('Initial host status must be a byte')
    if statuses is not None and (not isinstance(statuses, tuple) or not statuses or
                                any(type(x) is not int or not 0 <= x <= 65535 for x in statuses)):
        raise ValueError('Synthetic statuses must be a nonempty word tuple')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ECX, UC_X86_REG_ESP, UC_X86_REG_EIP
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+24+28)[0]
    image_size = struct.unpack_from('<I', data, pe+24+56)[0]
    uc.mem_map(base, (image_size+0xfff)&~0xfff)
    for section in executable_sections(data):
        off = section['raw_offset']
        uc.mem_write(section['va'], data[off:off+section['raw_bytes']])
    for start, size in ((0, 0x1000), (THIS, 0x75000), (STACK, 0x10000), (INPUT, 0x1000), (EXIT, 0x1000)):
        uc.mem_map(start, size)
    for stub, code in STUBS.items():
        uc.mem_write(stub, code)
    uc.mem_write(INPUT, payload)
    uc.mem_write(THIS+0x528a4, bytes([initial_host_status]))
    sp = STACK+0x8000
    uc.mem_write(sp, struct.pack('<III', EXIT, 1, len(payload)))
    uc.reg_write(UC_X86_REG_EAX, THIS)
    uc.reg_write(UC_X86_REG_EDX, INPUT)
    uc.reg_write(UC_X86_REG_ECX, address)
    uc.reg_write(UC_X86_REG_ESP, sp)
    dispatches, prefixes, sleeps = [], [], []
    def code(engine, pc, size, _):
        if not permitted_pc(pc, size):
            raise ValueError(f'Unexpected native execution {pc:#x}+{size}')
        eax, edx, ecx = (engine.reg_read(r) for r in (UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ECX))
        if pc == COPY:
            if not INPUT <= eax < INPUT+len(payload) or eax+ecx > INPUT+len(payload) or not 1 <= ecx <= 4:
                raise ValueError('Synthetic copy escaped input bounds')
            if edx != THIS+0x52254 or not permitted_write(edx, ecx):
                raise ValueError('Synthetic copy escaped request buffer')
            engine.mem_write(edx, bytes(engine.mem_read(eax, ecx)))
        elif pc == PREFIX:
            if eax != THIS or edx != 1:
                raise ValueError('Unexpected prefix object/target index')
            prefixes.append({'synthetic_target_index': edx})
        elif pc == SEND:
            length = struct.unpack('<I', engine.mem_read(THIS+0x52894, 4))[0]
            if eax != THIS or edx != length or not 5 <= length <= 8:
                raise ValueError('Unexpected synthetic dispatch identity/length')
            ordinal = len(dispatches)
            if statuses is not None and ordinal >= len(statuses):
                raise ValueError('Synthetic dispatch statuses exhausted')
            status = 0 if statuses is None else statuses[ordinal]
            dispatches.append({'internal_buffer_hex': bytes(engine.mem_read(THIS+0x52250, length)).hex(),
                               'synthetic_transport_word': status})
            engine.reg_write(UC_X86_REG_EAX, status)
        elif pc == SLEEP:
            wait = struct.unpack('<I', engine.mem_read(engine.reg_read(UC_X86_REG_ESP)+4, 4))[0]
            if wait not in (10, 50):
                raise ValueError('Unexpected synthetic wait')
            sleeps.append(wait)
        elif pc == CLEAN:
            if not STACK <= eax < STACK+0x10000 or edx != 6:
                raise ValueError('Unexpected string cleanup context')
        elif pc == ARRAY_CLEAN:
            if not STACK <= eax < STACK+0x10000:
                raise ValueError('Unexpected array cleanup context')
    def write(engine, access, addr, size, value, _):
        if not permitted_write(addr, size):
            raise ValueError(f'Unexpected native write {addr:#x}+{size}')
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, EXIT, count=100000)
    if uc.reg_read(UC_X86_REG_EIP) != EXIT or uc.reg_read(UC_X86_REG_ESP) != sp+12:
        raise ValueError('Native helper did not return with its RET8 stack balance')
    return {'context': {'payload_hex': payload.hex(), 'address': address, 'driver_batch_flag': False,
                        'initial_host_status': initial_host_status, 'synthetic_target_index': 1},
            'dispatches': dispatches, 'prefix_calls': prefixes, 'synthetic_wait_milliseconds': sleeps,
            'final_host_status': uc.mem_read(THIS+0x528a4, 1)[0],
            'final_transport_word': struct.unpack('<H', uc.mem_read(THIS+0x52898, 2))[0],
            'transport_used': False, 'windows_apis_executed': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def audit(data):
    contexts = ({}, {'payload': bytes(1)}, {'payload': bytes(4)}, {'payload': bytes(5)},
                {'initial_host_status': 9}, {'payload': bytes(4), 'statuses': (11, 137, 0)},
                {'statuses': (126,)}, {'statuses': (9,)},
                {'statuses': (11,)*41}, {'statuses': (137,)*41}, {'payload': bytes(range(256))})
    cases = [run(data, **context) for context in contexts]
    section = next(s for s in executable_sections(data) if s['va'] <= START and END <= s['va']+s['raw_bytes'])
    offset = section['raw_offset']+START-section['va']
    return {'schema': 'pccs-quick-write-native-emulation-v1', 'source_sha256': SOURCE_SHA256,
            'source_range': {'start': hex(START), 'exclusive_end': hex(END), 'file_offset': offset,
                             'sha256': hashlib.sha256(data[offset:offset+END-START]).hexdigest()},
            'cases': cases, 'limitations': [
                'Only the ordinary non-batch branch executes; the driver-batch flag is synthetic zero.',
                'Copy, prefix selection, transport, waits, and cleanup are synthetic replacements.',
                'No real dispatcher, transport, Windows API, controller, checksum, or readback executes.',
                '256-byte payload cap is a harness resource bound, not a protocol limit.',
                'Internal request buffers do not establish AL5 routing or controller acceptance.'],
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
