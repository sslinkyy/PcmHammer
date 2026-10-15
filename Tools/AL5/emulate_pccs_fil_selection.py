"""Pinned FIL interpreter selection-changing interior branch, offline only.

Synthetic instruction locals and globals do not establish that an LCT utility
executes this branch. Stops before subsequent interpreter work or any call.
"""
import argparse
import hashlib
from itertools import product
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

START, END = 0x75c44a, 0x75c4b2
STOPS = {END: 'selection_branch_complete', 0x75c5c0: 'other_action_or_version', 0x75c588: 'zero_subaction'}
THIS, STACK, AUX = 0x10000000, 0x20000000, 0x30000000
ALIAS_SOURCE_OFFSET = 0x41d6f0


def permitted_pc(address, size):
    return size > 0 and START <= address and address+size <= END


def run(data, *, action=1, interpreter_version=4, subaction=1, selection_lock=0, selected=3, requested=0x18):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if (any(type(v) is not int or not 0 <= v <= 255 for v in (action, subaction, selection_lock, selected, requested)) or
            type(interpreter_version) is not int or not 0 <= interpreter_version <= 65535):
        raise ValueError('Requires byte-valued context and unsigned word interpreter version')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EBP, UC_X86_REG_ESP
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+52)[0]
    size = struct.unpack_from('<I', data, pe+80)[0]
    uc.mem_map(base, (size+0xfff)&~0xfff)
    for s in executable_sections(data):
        uc.mem_write(s['va'], data[s['raw_offset']:s['raw_offset']+s['raw_bytes']])
    for address, size in ((THIS, 0x75000), (STACK, 0x10000), (AUX, 0x1000)):
        uc.mem_map(address, size)
    def put(a, v):
        uc.mem_write(a, struct.pack('<I', v))
    # The alias is in non-executable data, outside the copied code mappings.
    alias = data[ALIAS_SOURCE_OFFSET:ALIAS_SOURCE_OFFSET+4]
    if int.from_bytes(alias, 'little') != 0x81d0f4:
        raise ValueError('Shared selection alias changed')
    uc.mem_write(0x81eaf0, alias)
    put(0x81d0f4, selected)
    put(0x81f250, AUX)
    uc.mem_write(AUX, bytes([selection_lock]))
    put(0x81f328, AUX+0x100)
    put(AUX+0x100, THIS)
    uc.mem_write(0x9d2dee, struct.pack('<H', interpreter_version))
    bp, sp = STACK+0x9000, STACK+0x8000
    uc.mem_write(bp-0x3c, bytes([action, subaction, requested]))
    uc.reg_write(UC_X86_REG_EBP, bp)
    uc.reg_write(UC_X86_REG_ESP, sp)
    indices = sorted({selected, requested})
    for index in indices:
        uc.mem_write(THIS+index*0xa4+0x80, b'\x09')
        uc.mem_write(THIS+index*0xa4+0xb6, b'\x09')
    stopped, steps, writes = [], [], []
    active = action == 1 and interpreter_version >= 4 and subaction != 0
    effective = requested if active and selection_lock == 0 else selected
    def code(engine, pc, n, _):
        if pc in STOPS:
            stopped.append(pc)
            engine.emu_stop()
            return
        if not permitted_pc(pc, n):
            raise ValueError(f'Unexpected FIL selection PC {pc:#x}+{n}')
        steps.append(pc)
    def write(engine, access, address, n, value, _):
        allowed = {THIS+effective*0xa4+0x80: 1, THIS+effective*0xa4+0xb6: 1} if active else {}
        if active and selection_lock == 0:
            allowed[0x81d0f4] = 4
        if allowed.get(address) != n:
            raise ValueError('Unexpected FIL selection write')
        writes.append(dict(address=hex(address), size=n, value=value))
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, 0, count=40)
    if len(stopped) != 1 or uc.reg_read(UC_X86_REG_ESP) != sp:
        raise ValueError('FIL selection missed declared boundary')
    actual = int.from_bytes(uc.mem_read(0x81d0f4, 4), 'little')
    if actual != effective:
        raise ValueError('Unexpected FIL selected-controller result')
    fields = [dict(index=i, family=int.from_bytes(uc.mem_read(THIS+i*0xa4+0x80, 1), 'little'),
                   version=int.from_bytes(uc.mem_read(THIS+i*0xa4+0xb6, 1), 'little')) for i in indices]
    return dict(context=dict(action=action, interpreter_version=interpreter_version, subaction=subaction,
                             selection_lock=selection_lock, selected=selected, requested=requested),
                boundary=STOPS[stopped[0]], selected_after=actual, indexed_fields=fields,
                native_writes=writes, native_instructions=len(steps), synthetic_context=True,
                lct_utility_reachability_proven=False, j1850_map_translation_proven=False,
                full_interpreter_executed=False, subsequent_restore_proven=False,
                programming_bypass_proven=False, transport_used=False,
                live_write_enabled=False, ready_to_flash=False, would_send=[])


def audit(data):
    contexts = [dict(action=a, interpreter_version=v, subaction=s, selection_lock=lock, requested=r)
                for a, v, s, lock, r in product((0, 1, 2), (3, 4), (0, 1), (0, 1), (3, 0x18))]
    cases = [run(data, **context) for context in contexts]
    s = next(s for s in executable_sections(data) if s['va'] <= START and END <= s['va']+s['raw_bytes'])
    off = s['raw_offset']+START-s['va']
    return dict(schema='pccs-fil-selection-v1', source_sha256=SOURCE_SHA256,
                source_alias=dict(address='0x81eaf0', file_offset=ALIAS_SOURCE_OFFSET,
                                  bytes_hex=data[ALIAS_SOURCE_OFFSET:ALIAS_SOURCE_OFFSET+4].hex()),
                source_range=dict(start=hex(START), exclusive_end=hex(END), file_offset=off,
                                  sha256=hashlib.sha256(data[off:off+END-START]).hexdigest()),
                cases=cases, limitations=[
                    'Interior branch only, with synthetic FIL instruction locals and aliased globals.',
                    'A selection mutation is not proof of a J1850 map lookup or an LCT programming route.',
                    'No preceding interpretation, following restore, callable transport or recovery execution.'],
                live_write_enabled=False, ready_to_flash=False, would_send=[])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('exe', type=Path)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        p.error('Output exists; refusing overwrite')
    result = audit(args.exe.read_bytes())
    result['source_path'] = str(args.exe.resolve())
    with args.output.open('x', encoding='utf-8') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    print(json.dumps(dict(cases=len(result['cases']), ready_to_flash=False)))


if __name__ == '__main__':
    main()
