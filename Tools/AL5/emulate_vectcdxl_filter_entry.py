"""Offline pinned Vector RP1210 command stub and acceptance-reset request slices.

No DLL is loaded. The two Vector calls are guarded synthetic boundaries.
Selectors are retained numerically; actual driver/hardware acceptance is unknown.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from inspect_pccs_methods import executable_sections

SOURCE_SHA256 = '9068a4cadf75fd663f6c1f66d07938ebef153492c53fc9e46eb49d00571893f5'
COMMAND_START, COMMAND_STOP = 0x44d5fc, 0x44d605
RESET_START, RESET_STOP, RESET_FAIL = 0x44d056, 0x44d08a, 0x44d100
STACK, EXIT, RESET_CALLBACK = 0x20000000, 0x30000000, 0x44cb48


def permitted_pc(phase, address, size):
    start, stop = {'command': (COMMAND_START, COMMAND_STOP),
                   'reset': (RESET_START, RESET_STOP)}.get(phase, (0, 0))
    return size > 0 and start <= address and address+size <= stop


def run(data, *, phase='command', command=3, client=1, pointer=0xdead0000,
        length=0, reset_results=(0, 0)):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source DLL pin changed')
    if (type(phase) is not str or phase not in ('command', 'reset')
            or any(type(v) is not int or not 0 <= v <= 0xffffffff
                   for v in (command, client, pointer, length))
            or type(reset_results) is not tuple or len(reset_results) != 2
            or any(type(v) is not int or not 0 <= v <= 0xffffffff for v in reset_results)):
        raise ValueError('Invalid synthetic Vector context')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+24+28)[0]
    size = struct.unpack_from('<I', data, pe+24+56)[0]
    uc.mem_map(base, (size+0xfff)&~0xfff)
    for section in executable_sections(data):
        off = section['raw_offset']
        uc.mem_write(section['va'], data[off:off+section['raw_bytes']])
    uc.mem_map(STACK, 0x10000)
    uc.mem_map(EXIT, 0x1000)
    sp, bp = STACK+0x7000, STACK+0x8000
    def put(address, value):
        uc.mem_write(address, struct.pack('<I', value))
    uc.reg_write(UC_X86_REG_ESP, sp)
    uc.reg_write(UC_X86_REG_EBP, bp)
    if phase == 'command':
        uc.mem_write(sp, struct.pack('<5I', EXIT, command, client, pointer, length))
    else:
        put(bp-0xc, 0x1234)
        put(bp-0x18, 1)
        put(bp-0x14, 0)
    calls, stops, steps, reads = [], [], [], []
    def code(engine, pc, instruction_size, _):
        if pc in ((EXIT,) if phase == 'command' else (RESET_STOP, RESET_FAIL)):
            stops.append(pc)
            engine.emu_stop()
            return
        if phase == 'reset' and pc == RESET_CALLBACK:
            current = engine.reg_read(UC_X86_REG_ESP)
            args = struct.unpack('<5I', engine.mem_read(current, 20))
            ordinal = len(calls)
            expected = ((0x44d067, 0x1234, 1, 0, 1), (0x44d083, 0x1234, 1, 0, 2))
            if ordinal >= 2 or args != expected[ordinal]:
                raise ValueError('Unexpected synthetic xlCanResetAcceptance boundary')
            calls.append(dict(port=args[1], mask_low=args[2], mask_high=args[3],
                              selector=args[4], synthetic_result=reset_results[ordinal]))
            engine.reg_write(UC_X86_REG_EAX, reset_results[ordinal])
            engine.reg_write(UC_X86_REG_ESP, current+20)
            engine.reg_write(UC_X86_REG_EIP, args[0])
            return
        if not permitted_pc(phase, pc, instruction_size):
            raise ValueError(f'Unexpected Vector PC {pc:#x}+{instruction_size}')
        steps.append(pc)
    def write(engine, access, address, size, value, _):
        if not (size == 4 and (address == sp-4 if phase == 'command' else sp-20 <= address < sp)):
            raise ValueError(f'Unexpected Vector write {address:#x}+{size}')
    def read(engine, access, address, size, value, _):
        if phase == 'command' and not (size == 4 and address in (sp-4, sp)):
            raise ValueError(f'Command handler unexpectedly read argument/state {address:#x}+{size}')
        if phase == 'reset' and not (STACK <= address and address+size <= STACK+0x10000):
            raise ValueError(f'Unexpected Vector reset read {address:#x}+{size}')
        reads.append(dict(address=hex(address), size=size))
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.hook_add(UC_HOOK_MEM_READ, read)
    uc.emu_start(COMMAND_START if phase == 'command' else RESET_START, 0, count=100)
    if len(stops) != 1 or uc.reg_read(UC_X86_REG_ESP) != sp+(20 if phase == 'command' else 0):
        raise ValueError('Vector slice did not reach declared boundary')
    if phase == 'command' and (uc.reg_read(UC_X86_REG_EAX) != 0 or uc.reg_read(UC_X86_REG_EBP) != bp):
        raise ValueError('Unexpected native command result')
    return dict(context=dict(phase=phase, command=command, client=client, pointer=pointer,
                             length=length, reset_results=list(reset_results)),
                boundary=hex(stops[0]), result=uc.reg_read(UC_X86_REG_EAX),
                instruction_count=len(steps), native_reads=reads, reset_requests=calls,
                command_arguments_read=False if phase == 'command' else None,
                driver_calls_synthetic=True, loaded_driver_identity_proven=False,
                filter_installation_proven=False, transport_used=False,
                live_write_enabled=False, ready_to_flash=False, would_send=[])


def audit(data):
    contexts = [dict(command=c) for c in (3, 17, 5, 0xffffffff)]
    contexts += [dict(command=5, client=0xffffffff, length=0xffffffff, pointer=0)]
    contexts += [dict(phase='reset', reset_results=r) for r in ((0, 0), (9, 0), (0, 9), (0x10000, 0))]
    ranges = []
    for start, stop in ((COMMAND_START, COMMAND_STOP), (RESET_START, RESET_STOP)):
        section = next(s for s in executable_sections(data) if s['va'] <= start and stop <= s['va']+s['raw_bytes'])
        off = section['raw_offset']+start-section['va']
        raw = data[off:off+stop-start]
        ranges.append(dict(start=hex(start), exclusive_end=hex(stop), file_offset=off,
                           hex=raw.hex(), sha256=hashlib.sha256(raw).hexdigest()))
    return dict(schema='vectcdxl-command-reset-slices-v1', source_sha256=SOURCE_SHA256,
                source_ranges=ranges, cases=[run(data, **c) for c in contexts],
                limitations=['Bundled implementation only; runtime-loaded driver identity unknown.',
                             'Native command handler has no argument reads or filter-state writes.',
                             'Reset phase calls are synthetic; numeric selectors retain unknown API semantics.',
                             'No full ClientConnect, physical CAN admission, AL5 programming or recovery qualification.'],
                live_write_enabled=False, ready_to_flash=False, would_send=[])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dll', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Output exists; refusing overwrite')
    result = audit(args.dll.read_bytes())
    result['source_path'] = str(args.dll.resolve())
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print(json.dumps(dict(cases=len(result['cases']), ready_to_flash=False)))


if __name__ == '__main__':
    main()
