"""Pinned PCCS EndWrite with synthetic readiness responses; no transport or time waits.

This models host finalization and boot-state checks, not checksum verification,
programming success, controller compatibility, or interrupted-flash recovery.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

START, END = 0x5b93e4, 0x5b96ca
THIS, STACK, EXIT = 0x10000000, 0x20000000, 0x30000000
PREFIX, SEND, SLEEP, INIT, BOOT, CLEAN = 0x5a8c58, 0x5a924c, 0x40e3e4, 0x5d8ec8, 0x5adc54, 0x4084c8
STUBS = {PREFIX: b'\xc3', SEND: b'\xc3', SLEEP: b'\xc2\x04\x00',
         INIT: b'\xc2\x04\x00', BOOT: b'\xc3', CLEAN: b'\xc3'}


def permitted_pc(address, size):
    return size > 0 and (START <= address and address+size <= END or
                        address in STUBS and size == len(STUBS[address]))


def permitted_write(address, size):
    return size > 0 and (STACK <= address and address+size <= STACK+0x10000 or
                        address == 0 and size == 4 or
                        THIS+0x52250 <= address and address+size <= THIS+0x52254 or
                        address == THIS+0x52894 and size == 4 or
                        address == THIS+0x528a4 and size == 1 or
                        address in (0x81d104, 0x81d174) and size == 1)


def run(data, *, check=True, statuses=(0,), boots=(False, False), version=0):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if type(check) is not bool or type(version) is not int or version not in (0, 7):
        raise ValueError('requires Boolean check and modeled version 0 or 7')
    if (not isinstance(statuses, tuple) or not statuses or
            any(type(v) is not int or not 0 <= v <= 255 for v in statuses) or
            not isinstance(boots, tuple) or any(type(v) is not bool for v in boots)):
        raise ValueError('requires explicit synthetic response tuples')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ECX, UC_X86_REG_ESP, UC_X86_REG_EIP
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    sections = executable_sections(data)
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+52)[0]
    image_size = struct.unpack_from('<I', data, pe+80)[0]
    uc.mem_map(base, (image_size+0xfff)&~0xfff)
    for section in sections:
        off = section['raw_offset']
        uc.mem_write(section['va'], data[off:off+section['raw_bytes']])
    for address, size in ((0, 0x1000), (THIS, 0x75000), (STACK, 0x10000), (EXIT, 0x1000)):
        uc.mem_map(address, size)
    def put(address, value):
        uc.mem_write(address, struct.pack('<I', value))
    for address, stub in STUBS.items():
        uc.mem_write(address, stub)
    put(0x81d0f4, 1)
    uc.mem_write(THIS+0xa4+0x80, b'\x01')
    uc.mem_write(THIS+0xa4+0xb6, bytes([version]))
    uc.mem_write(0x81d138, b'\x00')
    uc.mem_write(0x81d104, b'\x35')
    uc.mem_write(0x81d174, b'\x67')
    sp = STACK+0x8000
    put(sp, EXIT)
    uc.reg_write(UC_X86_REG_EAX, THIS)
    uc.reg_write(UC_X86_REG_EDX, 1)
    uc.reg_write(UC_X86_REG_ECX, int(check))
    uc.reg_write(UC_X86_REG_ESP, sp)
    sends, prefixes, delays, init_calls, boot_calls = [], [], [], [], []
    count = [0]
    def code(engine, pc, size, _):
        if not permitted_pc(pc, size):
            raise ValueError(f'unexpected native execution {pc:#x}+{size}')
        count[0] += 1
        eax, edx, ecx, esp = (engine.reg_read(r) for r in
                              (UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ECX, UC_X86_REG_ESP))
        if pc in (PREFIX, SEND, INIT, BOOT) and eax != THIS:
            raise ValueError('synthetic callback object changed')
        if pc == PREFIX:
            prefixes.append(edx)
        elif pc == SEND:
            if edx not in (1, 4):
                raise ValueError('unexpected EndWrite request length')
            sends.append(bytes(engine.mem_read(THIS+0x52250, edx)).hex())
            engine.reg_write(UC_X86_REG_EAX, 0)  # Send result not promoted to controller evidence.
        elif pc == SLEEP:
            delays.append(struct.unpack('<I', engine.mem_read(esp+4, 4))[0])
        elif pc == INIT:
            index = len(init_calls)
            if index >= len(statuses):
                raise ValueError('synthetic initialization responses exhausted')
            arg = struct.unpack('<I', engine.mem_read(esp+4, 4))[0]
            if edx != 1 or ecx != 0 or arg != 0:
                raise ValueError('initialization callback context changed')
            init_calls.append(statuses[index])
            engine.mem_write(THIS+0x528a4, bytes([statuses[index]]))
        elif pc == BOOT:
            index = len(boot_calls)
            if index >= len(boots):
                raise ValueError('synthetic boot responses exhausted')
            boot_calls.append(boots[index])
            engine.reg_write(UC_X86_REG_EAX, int(boots[index]))
    def write(engine, access, address, size, value, _):
        if not permitted_write(address, size):
            raise ValueError(f'unexpected native write {address:#x}+{size}')
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, EXIT, count=10000)
    if uc.reg_read(UC_X86_REG_EIP) != EXIT or uc.reg_read(UC_X86_REG_ESP) != sp+4:
        raise ValueError('native instruction budget or RET stack balance failed')
    restored = bytes(uc.mem_read(0x81d104, 1)+uc.mem_read(0x81d174, 1)).hex()
    if restored != '3567':
        raise ValueError('temporary communication globals not restored')
    return dict(check=check, version=version, internal_requests=sends, prefix_indices=prefixes,
                fake_sleep_arguments=delays, initialization_statuses=init_calls, in_boot_results=boot_calls,
                restored_globals_hex=restored, final_host_status=uc.mem_read(THIS+0x528a4, 1)[0],
                native_instruction_count=count[0], transport_used=False, windows_apis_executed=False, live_write_enabled=False,
                ready_to_flash=False, would_send=[])


def audit(data):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    contexts = [dict(), dict(check=False, boots=()), dict(statuses=(9, 0)),
                dict(statuses=(9, 9, 9), boots=()), dict(boots=(True, True, True, True), statuses=(0, 0, 0)),
                dict(boots=(True, False, False), statuses=(0, 0)),
                dict(statuses=(9, 9, 0)*3, boots=(True, True, True, True)), dict(version=7),
                dict(statuses=(12,), boots=())]
    section = next(s for s in executable_sections(data) if s['va'] <= START and END <= s['va']+s['raw_bytes'])
    offset = section['raw_offset']+START-section['va']
    return dict(schema='pccs-end-write-native-emulation-v1', source_sha256=SOURCE_SHA256,
                source_range={'start': hex(START), 'exclusive_end': hex(END), 'file_offset': offset,
                              'sha256': hashlib.sha256(data[offset:offset+END-START]).hexdigest()},
                cases=[run(data, **c) for c in contexts],
                evidence='isolated native emulation with synthetic host readiness responses',
                limitation='No checksum, readback integrity, controller compatibility or recovery qualified.',
                modeled_route='Ordinary route only; object+0x72d90 is zero. Prefix/send/init/boot/time/cleanup calls are synthetic.',
                live_write_enabled=False, ready_to_flash=False, would_send=[])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('exe', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output exists; refusing overwrite')
    result = audit(args.exe.read_bytes())
    result['source_path'] = str(args.exe.resolve())
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'cases': len(result['cases']), 'ready_to_flash': False}))


if __name__ == '__main__':
    main()
