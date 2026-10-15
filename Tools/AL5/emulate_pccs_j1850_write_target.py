"""Independent native PCCS write-target forwarding stages; no virtual call runs.

Inputs and inter-stage handoff are synthetic. This does not bypass the GUI
restriction, execute a writer, or establish a reachable programming session.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

RANGES = {'caller': (0x7c625f, 0x7c627d), 'forward': (0x5b4c70, 0x5b4ca8)}
STOPS = {'caller': (0x7c627d,), 'forward': (0x5b4c8c, 0x5b4ca6)}
THIS, STACK, SCRATCH, VMT = 0x10000000, 0x20000000, 0x30000000, 0x723ba0


def permitted_pc(phase, address, size):
    start, end = RANGES[phase]
    return size > 0 and start <= address and address+size <= end


def run(data, *, phase='caller', selected=3, wait_field=0):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if (type(phase) is not str or phase not in RANGES or
            any(type(v) is not int or not 0 <= v <= 0xffffffff for v in (selected, wait_field))):
        raise ValueError('Requires a known phase and unsigned dword context')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+52)[0]
    size = struct.unpack_from('<I', data, pe+80)[0]
    uc.mem_map(base, (size+0xfff)&~0xfff)
    for s in executable_sections(data):
        uc.mem_write(s['va'], data[s['raw_offset']:s['raw_offset']+s['raw_bytes']])
    uc.mem_map(THIS, 0x75000)
    uc.mem_map(STACK, 0x10000)
    uc.mem_map(SCRATCH, 0x1000)
    def put(a, v):
        uc.mem_write(a, struct.pack('<I', v))
    put(THIS, VMT)
    put(THIS+0x24, wait_field)
    bindings = tuple(int.from_bytes(uc.mem_read(VMT+offset, 4), 'little') for offset in (0, 0x10))
    if bindings != (0x724668, 0x5b487c):
        raise ValueError('TJ1850 dispatch/write bindings changed')
    bp, sp = STACK+0x9000, STACK+0x8000
    uc.reg_write(UC_X86_REG_EBP, bp)
    uc.reg_write(UC_X86_REG_ESP, sp)
    if phase == 'caller':
        put(0x81d0f4, selected)
        put(SCRATCH, THIS)
        put(0x81f12c, SCRATCH+0x100)
        put(SCRATCH+0x100, SCRATCH+0x300)
        put(bp-0x1c, 0)
        put(bp-0x4c, 0x8000)
        uc.reg_write(UC_X86_REG_EBX, SCRATCH)
        uc.reg_write(UC_X86_REG_ESI, 0x81d0f4)
        expected_args, expected_registers = (0, 0, selected, 256), (THIS, SCRATCH+0x300, 0x8000)
    else:
        put(bp-8, THIS)
        put(bp+0x10, selected)
        uc.reg_write(UC_X86_REG_EAX, THIS)
        expected_args, expected_registers = (selected&255, int(wait_field != 0)), (THIS, 5, 500)
    stopped, steps = [], []
    def code(engine, pc, n, _):
        if pc in STOPS[phase]:
            stopped.append(pc)
            engine.emu_stop()
            return
        if not permitted_pc(phase, pc, n):
            raise ValueError(f'Unexpected target-forwarding PC {pc:#x}+{n}')
        steps.append(pc)
    def write(engine, access, address, n, value, _):
        if not (n == 4 and sp-4*len(expected_args) <= address and address+n <= sp):
            raise ValueError('Unexpected target-forwarding write')
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(RANGES[phase][0], 0, count=100)
    actual_sp = uc.reg_read(UC_X86_REG_ESP)
    if actual_sp != sp-4*len(expected_args) or len(stopped) != 1:
        raise ValueError('Target-forwarding stage missed its call boundary')
    args = struct.unpack('<'+'I'*len(expected_args), uc.mem_read(actual_sp, 4*len(expected_args)))
    registers = tuple(uc.reg_read(r) for r in (UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ECX))
    if args != expected_args or registers != expected_registers or uc.reg_read(UC_X86_REG_EDI) != VMT:
        raise ValueError('Unexpected pending virtual-call context')
    return dict(context=dict(phase=phase, selected=selected, wait_field=wait_field),
                stopped_before=hex(stopped[0]), pending_arguments=list(args),
                pending_registers=dict(eax=registers[0], edx=registers[1], ecx=registers[2]),
                source_bound_virtual_target=hex(bindings[1 if phase == 'caller' else 0]),
                native_instructions=len(steps), caller_state_synthetic=True,
                full_writer_executed=False, virtual_call_executed=False,
                mapping_before_slice_proven=False, programming_reachability_proven=False,
                transport_used=False, live_write_enabled=False, ready_to_flash=False, would_send=[])


def audit(data):
    from emulate_pccs_j1850_envelope import run as envelope
    # Independent stages: explicit synthetic handoff, never a continuous writer.
    cases = []
    for selected in (0, 3, 0x18, 255, 0x103):
        caller = run(data, selected=selected)
        forwards = [run(data, phase='forward', selected=selected, wait_field=w) for w in (0, 1, 0xffffffff)]
        target = forwards[0]['pending_arguments'][0]
        formatted = envelope(data, target=target, payload=b'\x10\x10')
        cases.append(dict(selected=selected, caller=caller, forwards=forwards,
                          synthetic_envelope_handoff=formatted, continuous_execution=False))
    ranges = {}
    for phase, (start, end) in RANGES.items():
        s = next(s for s in executable_sections(data) if s['va'] <= start and end <= s['va']+s['raw_bytes'])
        off = s['raw_offset']+start-s['va']
        ranges[phase] = dict(start=hex(start), exclusive_end=hex(end), file_offset=off,
                             sha256=hashlib.sha256(data[off:off+end-start]).hexdigest())
    return dict(schema='pccs-j1850-write-target-v1', source_sha256=SOURCE_SHA256, source_ranges=ranges,
                cases=cases, limitations=[
                    'Interior stages use synthetic caller state and handoffs; no virtual calls execute.',
                    'Envelope payload 10 10 is synthetic and is not a reconstructed WriteData request.',
                    'No pre-slice remapping, GUI reachability, controller authorization or recovery proof.'],
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
