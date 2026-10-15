"""Emulate pinned LCT event creation with synthetic handles; no OS/transport calls."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from audit_lct_command_tables import CATALOG, SOURCE_SHA256, reconstruct

START, END = 0x1000796f, 0x10007aff
STACK, EXIT, THIS = 0x20000000, 0x30000000, 0x40000000
STUB = EXIT+0x100
OBJECT_SLOTS = tuple(THIS+x for x in (0x1c0, 0x1c4, 0x1c8, 0x1d0, 0x1d4))
TABLE_SLOTS = tuple(base+i*88 for _, base, count in CATALOG for i in range(count))
REQUEST_SLOTS = tuple(THIS+0xd4+i*4 for i in range(14))
DONE_SLOTS = tuple(THIS+0x10c+i*4 for i in range(14))
EVENT_SLOTS = frozenset(OBJECT_SLOTS+TABLE_SLOTS+REQUEST_SLOTS+DONE_SLOTS)


def permitted_write(address, size):
    return size > 0 and (STACK <= address and address+size <= STACK+0x10000
                         or size == 4 and address in EVENT_SLOTS)


def permitted_pc(address, size):
    return size > 0 and (START <= address and address+size <= END
                         or STUB <= address and address+size <= STUB+3)


def audit(data):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('Pinned LctTransBusRules.dll hash differs; no emulation')
    source, _ = reconstruct(data)
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_ECX, UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    for page in (0x10007000, 0x10071000, 0x10072000, 0x10073000, 0x1005d000):
        uc.mem_map(page, 0x1000)
        uc.mem_write(page, bytes(source.mem_read(page, 0x1000)))
    uc.mem_map(STACK, 0x10000)
    uc.mem_map(EXIT, 0x1000)
    uc.mem_map(THIS, 0x1000)
    uc.mem_write(STUB, bytes.fromhex('c21000'))  # RET 16; EAX set by synthetic hook.
    uc.mem_write(0x1005d02c, struct.pack('<I', STUB))
    uc.mem_write(STACK+0x8000, struct.pack('<I', EXIT))
    uc.reg_write(UC_X86_REG_ESP, STACK+0x8000)
    uc.reg_write(UC_X86_REG_ECX, THIS)
    calls, writes = [], []
    observations = [0]

    def code(engine, address, size, _):
        if not permitted_pc(address, size):
            raise ValueError(f'Execution outside event setup: {address:#x}')
        observations[0] += 1
        if address == STUB:
            sp = engine.reg_read(UC_X86_REG_ESP)
            args = struct.unpack('<IIII', engine.mem_read(sp+4, 16))
            if args != (0, 0, 0, 0):
                raise ValueError('Unexpected CreateEventA arguments')
            handle = 0xa000+len(calls)
            calls.append({'synthetic_handle': handle, 'arguments': list(args)})
            engine.reg_write(UC_X86_REG_EAX, handle)

    def write(engine, access, address, size, value, _):
        if not permitted_write(address, size):
            raise ValueError(f'Unexpected setup write {address:#x}+{size}')
        if address in EVENT_SLOTS:
            writes.append({'address': hex(address), 'synthetic_handle': value})

    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, EXIT, count=10000)
    if uc.reg_read(UC_X86_REG_EIP) != EXIT or uc.reg_read(UC_X86_REG_ESP) != STACK+0x8004:
        raise ValueError('Setup did not return with the expected stack')
    if len(calls) != len(EVENT_SLOTS) or {int(w['address'], 16) for w in writes} != EVENT_SLOTS:
        raise ValueError('Incomplete event-slot coverage')
    if sorted(w['synthetic_handle'] for w in writes) != sorted(c['synthetic_handle'] for c in calls):
        raise ValueError('Synthetic handle assignment is not one-to-one')
    for address in TABLE_SLOTS:
        if uc.mem_read(address+4, 84) != source.mem_read(address+4, 84):
            raise ValueError('Event creation modified request descriptor fields')
    groups = [{'selector': i,
               'request_slot': hex(REQUEST_SLOTS[i]),
               'request_handle': struct.unpack('<I', uc.mem_read(REQUEST_SLOTS[i], 4))[0],
               'done_slot': hex(DONE_SLOTS[i]),
               'done_handle': struct.unpack('<I', uc.mem_read(DONE_SLOTS[i], 4))[0]}
              for i in range(14)]
    return {'schema': 'lct-event-setup-emulation-v1', 'source_sha256': SOURCE_SHA256,
            'code_sha256': hashlib.sha256(bytes(source.mem_read(START, END-START))).hexdigest(),
            'procedure': hex(START), 'exclusive_end': hex(END),
            'instruction_observations': observations[0], 'synthetic_create_event_calls': calls,
            'event_slot_writes': writes, 'groups': groups,
            'request_descriptor_fields_preserved': True,
            'limitations': ['Successful synthetic handles only; OS allocation failures are not modeled.',
                            'Creation arguments establish requested initial state, not live event state.',
                            'No event activation, request worker or controller response is executed.'],
            'transport_used': False, 'windows_apis_executed': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Output exists; refusing overwrite')
    result = audit(args.source.read_bytes())
    result['source_path'] = str(args.source.resolve())
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print(f"Saved {len(result['event_slot_writes'])} synthetic event assignments")


if __name__ == '__main__':
    main()
