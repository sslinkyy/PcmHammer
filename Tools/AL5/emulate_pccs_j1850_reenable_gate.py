"""Native controller-selection UI refresh protocol gate, entirely offline.

Delphi string equality is synthetic; stops before any control setter.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

START, ENABLE, SKIP = 0x7e211e, 0x7e214c, 0x7e2202
STACK, AUX = 0x20000000, 0x30000000
LITERALS = {0x7e2314: 'J1850', 0x7e22d4: 'XCP_ETHERNET'}


def permitted_pc(address, size):
    return size > 0 and START <= address and address+size <= ENABLE


def run(data, *, protocol='J1850'):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if type(protocol) is not str or protocol not in ('J1850', 'XCP_ETHERNET', 'CAN', 'IESCAN'):
        raise ValueError('Invalid synthetic protocol context')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EFLAGS
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+52)[0]
    size = struct.unpack_from('<I', data, pe+80)[0]
    uc.mem_map(base, (size+0xfff)&~0xfff)
    sections = executable_sections(data)
    for s in sections:
        uc.mem_write(s['va'], data[s['raw_offset']:s['raw_offset']+s['raw_bytes']])
    uc.mem_map(STACK, 0x10000)
    uc.mem_map(AUX, 0x1000)
    uc.mem_write(0x81f45c, struct.pack('<I', AUX))
    uc.mem_write(AUX, struct.pack('<I', AUX+0x100))
    uc.mem_write(AUX+0x100, protocol.encode('utf-16le')+b'\0\0')
    for address, literal in LITERALS.items():
        encoded = literal.encode('utf-16le')+b'\0\0'
        if bytes(uc.mem_read(address, len(encoded))) != encoded:
            raise ValueError('Protocol literal binding changed')
    sp = STACK+0x8000
    uc.reg_write(UC_X86_REG_ESP, sp)
    calls, stops, steps = [], [], []
    def code(engine, pc, n, _):
        if pc in (ENABLE, SKIP):
            stops.append(pc)
            engine.emu_stop()
            return
        if pc == 0x408c58:
            current = engine.reg_read(UC_X86_REG_ESP)
            ret = int.from_bytes(engine.mem_read(current, 4), 'little')
            expected = ((0x7e212f, 0x7e2314), (0x7e2146, 0x7e22d4))
            index = len(calls)
            if (index >= len(expected) or current != sp-4 or
                    (ret, engine.reg_read(UC_X86_REG_EDX)) != expected[index] or
                    engine.reg_read(UC_X86_REG_EAX) != AUX+0x100):
                raise ValueError('Unexpected synthetic protocol equality callback')
            literal = LITERALS[expected[index][1]]
            equal = protocol == literal
            calls.append(dict(literal=literal, equal=equal, synthetic=True))
            flags = engine.reg_read(UC_X86_REG_EFLAGS)
            engine.reg_write(UC_X86_REG_EFLAGS, (flags&~0x40) | (0x40 if equal else 0))
            engine.reg_write(UC_X86_REG_ESP, sp)
            engine.reg_write(UC_X86_REG_EIP, ret)
            return
        if not permitted_pc(pc, n):
            raise ValueError(f'Unexpected re-enable gate PC {pc:#x}+{n}')
        steps.append(pc)
    def write(engine, access, address, n, value, _):
        if address != sp-4 or n != 4:
            raise ValueError('Unexpected re-enable gate write')
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, 0, count=40)
    if len(stops) != 1 or uc.reg_read(UC_X86_REG_ESP) != sp:
        raise ValueError('Re-enable gate did not reach its declared boundary')
    return dict(context=dict(protocol=protocol), stopped_before=hex(stops[0]),
                reaches_programming_enable_block=stops[0] == ENABLE,
                synthetic_comparisons=calls, native_instructions=len(steps),
                earlier_event_state_assumed=True, control_setters_executed=False,
                complete_event_executed=False, actual_ui_state_proven=False,
                transport_used=False, live_write_enabled=False, ready_to_flash=False, would_send=[])


def audit(data):
    cases = [run(data, protocol=p) for p in ('J1850', 'XCP_ETHERNET', 'CAN', 'IESCAN')]
    s = next(s for s in executable_sections(data) if s['va'] <= START and ENABLE <= s['va']+s['raw_bytes'])
    off = s['raw_offset']+START-s['va']
    return dict(schema='pccs-j1850-reenable-gate-v1', source_sha256=SOURCE_SHA256,
                source_range=dict(start=hex(START), exclusive_end=hex(ENABLE), file_offset=off,
                                  sha256=hashlib.sha256(data[off:off+ENABLE-START]).hexdigest()),
                cases=cases, limitations=[
                    'Interior ControllerRadioGroupClick gate only; preceding event state assumed.',
                    'Protocol equality is synthetic; original literal bytes are checked.',
                    'Stops before all setters; not a complete UI lifecycle or hardware qualification.'],
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
