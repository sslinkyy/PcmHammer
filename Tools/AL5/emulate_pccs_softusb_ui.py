"""Pinned native SoftUSB UI-apply normalization slice, offline, no UI or I/O.

Control getter and Delphi string operations are explicit synthetic callbacks.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

START, STOP, BYPASS = 0x5e88c0, 0x5e963b, 0x5e891c
STACK, THIS, AUX = 0x20000000, 0x10000000, 0x30000000
GETTER = AUX+0x100


def permitted_pc(address, size):
    return size > 0 and START <= address and address+size <= BYPASS


def run(data, *, checked=True, protocol='J1850'):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if type(checked) is not bool or type(protocol) is not str or protocol not in ('J1850', 'CAN', 'IESCAN', 'CAN:Baud=500'):
        raise ValueError('Invalid synthetic UI context')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EFLAGS
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+52)[0]
    size = struct.unpack_from('<I', data, pe+80)[0]
    uc.mem_map(base, (size+0xfff)&~0xfff)
    for s in executable_sections(data):
        uc.mem_write(s['va'], data[s['raw_offset']:s['raw_offset']+s['raw_bytes']])
    for a in (STACK, THIS, AUX):
        uc.mem_map(a, 0x10000)
    def put(a, v):
        uc.mem_write(a, struct.pack('<I', v))
    bp, sp = STACK+0x8000, STACK+0x7000
    put(bp-0xc, THIS)
    put(THIS+0x3a0, THIS+0x1000)
    put(THIS+0x1000, THIS+0x2000)
    put(THIS+0x2000+0xec, GETTER)
    put(0x828fe4, AUX+0x300)
    put(0x828fdc, AUX+0x400)
    uc.reg_write(UC_X86_REG_EBP, bp)
    uc.reg_write(UC_X86_REG_ESP, sp)
    state = dict(protocol=protocol, library='prior.dll')
    calls, stops, steps = [], [], []
    def code(engine, pc, n, _):
        if pc in (STOP, BYPASS):
            stops.append(pc)
            engine.emu_stop()
            return
        if pc in (GETTER, 0x4084d0, 0x408c58):
            current = engine.reg_read(UC_X86_REG_ESP)
            ret = int.from_bytes(engine.mem_read(current, 4), 'little')
            eax, edx = engine.reg_read(UC_X86_REG_EAX), engine.reg_read(UC_X86_REG_EDX)
            if pc == GETTER:
                if calls or eax != THIS+0x1000 or ret != 0x5e88d1:
                    raise ValueError('Unexpected synthetic control getter')
                calls.append('synthetic_checked_getter')
                engine.reg_write(UC_X86_REG_EAX, int(checked))
            elif pc == 0x408c58:
                if ret != 0x5e88f3 or edx != 0x5e9990 or eax != AUX+0x300:
                    raise ValueError('Unexpected synthetic protocol comparison')
                calls.append('synthetic_compare_IESCAN')
                flags = engine.reg_read(UC_X86_REG_EFLAGS)
                engine.reg_write(UC_X86_REG_EFLAGS, (flags & ~0x40) | (0x40 if protocol == 'IESCAN' else 0))
            else:
                if ret == 0x5e88e4 and (eax, edx) == (0x828fdc, 0x5e9e94):
                    state['library'] = 'SOFTUSB.DLL'
                elif ret == 0x5e8904 and (eax, edx) == (0x828fe4, 0x5e991c):
                    state['protocol'] = 'CAN'
                else:
                    raise ValueError('Unexpected synthetic string assignment')
                calls.append('synthetic_assign_'+state['library'] if ret == 0x5e88e4 else 'synthetic_assign_CAN')
            engine.reg_write(UC_X86_REG_ESP, current+4)
            engine.reg_write(UC_X86_REG_EIP, ret)
            return
        if not permitted_pc(pc, n):
            raise ValueError(f'Unexpected UI slice PC {pc:#x}+{n}')
        steps.append(pc)
    def write(engine, access, a, n, value, _):
        if not (a == sp-4 and n == 4 or a == 0x81d1d0 and n == 4 or a == 0x828fec and n == 2):
            raise ValueError(f'Unexpected UI slice write {a:#x}+{n}')
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, 0, count=100)
    if len(stops) != 1 or uc.reg_read(UC_X86_REG_ESP) != sp:
        raise ValueError('UI slice did not reach declared boundary')
    return dict(context=dict(checked=checked, protocol=protocol), effective=state,
                boundary=hex(stops[0]), synthetic_callbacks=calls, instruction_count=len(steps),
                device_word=int.from_bytes(uc.mem_read(0x828fec, 2), 'little'),
                timing_global=int.from_bytes(uc.mem_read(0x81d1d0, 4), 'little'),
                actual_ui_executed=False, actual_string_runtime_executed=False,
                transport_used=False, live_write_enabled=False, ready_to_flash=False, would_send=[])


def audit(data):
    contexts = [dict(protocol=p) for p in ('J1850', 'CAN', 'IESCAN', 'CAN:Baud=500')]+[dict(checked=False)]
    s = next(s for s in executable_sections(data) if s['va'] <= START < s['va']+s['raw_bytes'])
    off = s['raw_offset']+START-s['va']
    return dict(schema='pccs-softusb-ui-normalization-v1', source_sha256=SOURCE_SHA256,
                source_range=dict(start=hex(START), exclusive_end=hex(BYPASS), file_offset=off,
                                  sha256=hashlib.sha256(data[off:off+BYPASS-START]).hexdigest()),
                cases=[run(data, **c) for c in contexts],
                limitations=['Synthetic control getter/string helpers; native branching and scalar stores only.',
                             'Entry assumes the adapter check is reached; full dialog and later initialization excluded.',
                             'No observation of owner runtime configuration or actual bus protocol.'],
                live_write_enabled=False, ready_to_flash=False, would_send=[])


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
    print(json.dumps(dict(cases=len(result['cases']), ready_to_flash=False)))


if __name__ == '__main__':
    main()
