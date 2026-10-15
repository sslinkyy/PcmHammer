"""Pinned, isolated LCT callback experiments; synthetic events, no host I/O.

This models two narrow callback bodies and caller-supplied synthetic payloads.
It does not run dispatch, transport, DOC, COM, or controller code.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from audit_lct_command_tables import SOURCE_SHA256, reconstruct

STACK, EXIT, STUB = 0x20000000, 0x30000000, 0x30000100
THIS, PAYLOAD = 0x40000000, 0x50000000
CALLBACKS = {'group0': (0x1000d029, 0x1000d08d),
             'group2': (0x1000a783, 0x1000a7a4)}
COPY_PAGES = (0x1000d000, 0x1000a000, 0x10071000, 0x10073000, 0x1005d000)
INITIAL_STATUS = 0xdeadbeef


def permitted_pc(address, size, start, end):
    return size > 0 and (start <= address and address+size <= end
                         or STUB <= address and address+size <= STUB+8)


def permitted_write(address, size):
    return size > 0 and (STACK <= address and address+size <= STACK+0x10000
                         or THIS+0xb4 <= address and address+size <= THIS+0xb8)


def emulate_case(source, callback, first_byte=0x31, second_byte=0, index=0):
    """Run only an allowlisted body in a fresh sandbox from reconstructed pages."""
    if callback not in CALLBACKS:
        raise ValueError('Unknown callback; no emulation')
    if not 0 <= first_byte <= 255 or not 0 <= second_byte <= 255:
        raise ValueError('Payload bytes must fit octets')
    if callback == 'group0' and index not in (0, 1, 2):
        raise ValueError('Group-0 synthetic descriptor index must be 0..2')
    if not 0 <= index <= 0xffff:
        raise ValueError('Synthetic index must fit a word')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires validated Unicorn 2.1.4 runtime')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import (UC_X86_REG_ESP, UC_X86_REG_ECX,
                                   UC_X86_REG_EFLAGS, UC_X86_REG_EIP)
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    for page in COPY_PAGES:
        uc.mem_map(page, 0x1000)
        uc.mem_write(page, bytes(source.mem_read(page, 0x1000)))
    for page, length in ((STACK, 0x10000), (EXIT, 0x1000),
                         (THIS, 0x1000), (PAYLOAD, 0x1000)):
        uc.mem_map(page, length)
    # The import points only to a local MOV EAX,1; RET 4 stub.
    uc.mem_write(STUB, bytes.fromhex('b801000000c20400'))
    uc.mem_write(0x1005d110, struct.pack('<I', STUB))
    for slot in range(3):
        uc.mem_write(0x10071120+slot*88, struct.pack('<I', 0xa000+slot))
    uc.mem_write(0x10073220, struct.pack('<I', 0xb000))
    uc.mem_write(THIS+0xb4, struct.pack('<I', INITIAL_STATUS))
    uc.mem_write(THIS+(0x1a4 if callback == 'group0' else 0x1ae), struct.pack('<H', index))
    uc.mem_write(PAYLOAD, bytes((first_byte, second_byte)))
    sp = STACK+0x8000
    uc.mem_write(sp, struct.pack('<III', EXIT, PAYLOAD, 2))
    uc.reg_write(UC_X86_REG_ESP, sp)
    uc.reg_write(UC_X86_REG_ECX, THIS)
    uc.reg_write(UC_X86_REG_EFLAGS, 2)
    start, end = CALLBACKS[callback]
    events, observations, writes = [], [0], []

    def code(engine, address, size, _):
        if address == EXIT:
            engine.emu_stop()
            return
        if not permitted_pc(address, size, start, end):
            raise ValueError(f'Unexpected emulated execution {address:#x}')
        observations[0] += 1
        if address == STUB:
            stack = engine.reg_read(UC_X86_REG_ESP)
            events.append(struct.unpack('<I', engine.mem_read(stack+4, 4))[0])

    def write(engine, access, address, size, value, _):
        if not permitted_write(address, size):
            raise ValueError(f'Unexpected emulated write {address:#x}+{size}')
        writes.append({'address': hex(address), 'size': size})

    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(start, EXIT, count=2000)
    if uc.reg_read(UC_X86_REG_EIP) != EXIT:
        raise ValueError('Callback exhausted instruction bound without returning')
    if uc.reg_read(UC_X86_REG_ESP) != sp+12:
        raise ValueError('Callback did not preserve synthetic RET 8 contract')
    return {'callback': callback, 'start': hex(start), 'exclusive_end': hex(end),
            'code_sha256': hashlib.sha256(bytes(source.mem_read(start, end-start))).hexdigest(),
            'provider_defined_function': callback == 'group0',
            'payload_hex': bytes((first_byte, second_byte)).hex(), 'synthetic_index': index,
            'initial_status': INITIAL_STATUS,
            'final_status': struct.unpack('<I', uc.mem_read(THIS+0xb4, 4))[0],
            'synthetic_events': events, 'instruction_observations': observations[0],
            'writes': writes, 'returned_to_synthetic_exit': True}


def audit(data):
    # Pin before importing optional execution dependencies or reconstructing tables.
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('Pinned LctTransBusRules.dll hash differs; no emulation')
    source, initializers = reconstruct(data)
    cases = [emulate_case(source, 'group0', first, second, index)
             for first in (0x31, 0x37) for second in (0, 0x31, 0x35, 0x37, 0xff)
             for index in (0, 1, 2)]
    cases += [emulate_case(source, 'group2', index=index) for index in (0, 1, 0xffff)]
    return {'schema': 'lct-session-callback-emulation-v1', 'source_sha256': SOURCE_SHA256,
            'emulator': 'Unicorn 2.1.4', 'initializers': initializers, 'cases': cases,
            'scope': 'Synthetic payload callbacks only; dispatcher and native send paths do not execute',
            'limitations': ['Caller-supplied payloads do not establish controller responses.',
                            'Synthetic event signals are not Windows API calls.',
                            'Group-2 body is raw-disassembly bounded; not a provider-defined function.',
                            'No programming, erase, transfer, verification or recovery is qualified.'],
            'transport_used': False, 'windows_apis_executed': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Output already exists; choose a new report path')
    result = audit(args.source.read_bytes())
    result['source_path'] = str(args.source.resolve())
    with args.output.open('x', encoding='utf-8') as output:
        output.write(json.dumps(result, indent=2)+'\n')
    print(f"Saved {len(result['cases'])} isolated callback cases to {args.output}")


if __name__ == '__main__':
    main()
