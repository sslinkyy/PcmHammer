"""Resolve three pinned WriteCal switches without executing their destinations.

Exhaustive byte inputs cover selectors only, not callees or a programming
session. No original process, DLL, callback, adapter or controller is used.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

SWITCHES = {
    'status_a': dict(start=0x7c4ea1, end=0x7c4eb4, table=0x7c4eb4, count=24, default=0x7c4fbd, mask=0x7f),
    'local_byte': dict(start=0x7c5920, end=0x7c5934, table=0x7c5934, count=10, default=0x7c59b7, mask=0xff),
    'status_c': dict(start=0x7c5b77, end=0x7c5b91, table=0x7c5ba8, count=7, default=0x7c5c53, mask=0x7f, remap=0x7c5b91, remap_count=23),
}
STACK = 0x20000000


def permitted_pc(phase, address, size):
    s = SWITCHES[phase]
    return size > 0 and s['start'] <= address and address+size <= s['end']


def inspect_switches(data):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    sections = executable_sections(data)
    def source(va, size):
        s = next(s for s in sections if s['va'] <= va and va+size <= s['va']+s['raw_bytes'])
        off = s['raw_offset']+va-s['va']
        raw = data[off:off+size]
        return dict(address=hex(va), file_offset=off, length=size, bytes_hex=raw.hex(), sha256=hashlib.sha256(raw).hexdigest())
    result = {}
    for phase, s in SWITCHES.items():
        table = source(s['table'], 4*s['count'])
        targets = list(struct.unpack('<'+'I'*s['count'], bytes.fromhex(table['bytes_hex'])))
        if any(not any(section['va'] <= t < section['va']+section['raw_bytes'] for section in sections) for t in targets+[s['default']]):
            raise ValueError('Switch destination is not source-backed executable memory')
        remap = source(s['remap'], s['remap_count']) if 'remap' in s else None
        indexes = list(bytes.fromhex(remap['bytes_hex'])) if remap else None
        if indexes is not None and any(index >= s['count'] for index in indexes):
            raise ValueError('Remap exceeds switch destination table')
        result[phase] = dict(code=source(s['start'], s['end']-s['start']), table=table,
                             targets=targets, remap=remap, remap_indexes=indexes,
                             default=s['default'], mask=s['mask'])
    return result


def run(data, *, phase='status_a', value=0):
    layouts = inspect_switches(data)
    if type(phase) is not str or phase not in SWITCHES or type(value) is not int or not 0 <= value <= 255:
        raise ValueError('Requires a known switch and byte-valued synthetic input')
    return _run(data, layouts, phase, value)


def _run(data, layouts, phase, value):
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_ESP
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+52)[0]
    size = struct.unpack_from('<I', data, pe+80)[0]
    uc.mem_map(base, (size+0xfff)&~0xfff)
    for s in executable_sections(data):
        uc.mem_write(s['va'], data[s['raw_offset']:s['raw_offset']+s['raw_bytes']])
    uc.mem_map(STACK, 0x10000)
    sp, bp = STACK+0x8000, STACK+0x9000
    uc.reg_write(UC_X86_REG_ESP, sp)
    uc.reg_write(UC_X86_REG_EBP, bp)
    uc.reg_write(UC_X86_REG_EAX, value)
    uc.mem_write(bp-0x5b, bytes([value]))
    layout = layouts[phase]
    stops = set(layout['targets']+[layout['default']])
    stopped, steps = [], []
    def code(engine, pc, n, _):
        if pc in stops:
            stopped.append(pc)
            engine.emu_stop()
            return
        if not permitted_pc(phase, pc, n):
            raise ValueError(f'Unexpected switch PC {pc:#x}+{n}')
        steps.append(pc)
    def write(*args):
        raise ValueError('Switch selector attempted a memory write')
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(SWITCHES[phase]['start'], 0, count=12)
    if len(stopped) != 1 or uc.reg_read(UC_X86_REG_ESP) != sp:
        raise ValueError('Switch failed to stop before a destination')
    masked = value & layout['mask']
    indexes = layout['remap_indexes']
    in_table = masked < (len(indexes) if indexes is not None else len(layout['targets']))
    index = (indexes[masked] if indexes is not None else masked) if in_table else None
    expected = layout['targets'][index] if in_table else layout['default']
    if stopped[0] != expected:
        raise ValueError('Native switch differs from original table decoding')
    return dict(context=dict(phase=phase, input=value), masked_value=masked,
                table_index=index, destination=hex(stopped[0]), native_instructions=len(steps),
                synthetic_input=True, destination_executed=False, callees_executed=False,
                complete_writecal_executed=False, address_conversion_proven=False,
                programming_bypass_proven=False, transport_used=False,
                live_write_enabled=False, ready_to_flash=False, would_send=[])


def audit(data):
    layouts = inspect_switches(data)
    cases = [_run(data, layouts, phase, value) for phase in SWITCHES for value in range(256)]
    return dict(schema='pccs-writecal-switches-v1', source_sha256=SOURCE_SHA256,
                layouts=layouts, cases=cases, selector_coverage=dict(inputs_per_switch=256, switches=3, cases=len(cases)),
                limitations=[
                    'All byte selector inputs only; not all whole-program states or paths.',
                    'Stops before destinations; no callees, switch effects or UI guards executed.',
                    'No programming reachability, controller-address conversion or recovery proof.'],
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
