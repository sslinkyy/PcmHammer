"""Pinned boot interface-selection gates with a synthetic hardware-read result.

Starts after the physical read at 0xCC0; no hardware register is accessed.
The real compare/store and initializer-call guard execute in emulator RAM.
"""
import argparse
import json
from pathlib import Path
from al5_segment import sha256
from emulate_boot_session import EXPECTED_LOW

RAM, STACK = 0xff8000, 0x208000
RANGES = ((0xcc6, 0xcd4), (0xab4, 0xac2), (0xe68, 0xe80))


def permitted_pc(pc, size):
    return size > 0 and any(a <= pc and pc+size <= b for a, b in RANGES)


def experiment(low, *, hardware_word=0):
    if len(low) != 0x20000 or sha256(low) != EXPECTED_LOW:
        raise ValueError('unexpected pinned LOW evidence')
    if type(hardware_word) is not int or not 0 <= hardware_word <= 65535:
        raise ValueError('synthetic hardware word must be unsigned 16-bit')
    from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_EXEC, __version__
    from unicorn.m68k_const import UC_CPU_M68K_M68020, UC_M68K_REG_D0, UC_M68K_REG_A7, UC_M68K_REG_PC, UC_M68K_REG_SR
    if __version__ != '2.1.4':
        raise ValueError('requires Unicorn 2.1.4')
    uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
    uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    uc.mem_map(0, 0x1000)
    for a, b in RANGES:
        uc.mem_write(a, low[a:b])
    uc.mem_protect(0, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_map(RAM, 0x1000)
    uc.mem_map(0x200000, 0x10000)
    uc.reg_write(UC_M68K_REG_SR, 0x2700)
    uc.reg_write(UC_M68K_REG_A7, STACK)
    uc.reg_write(UC_M68K_REG_D0, hardware_word)
    uc.mem_write(RAM+0x10, b'\xa5')
    stops, writes = [], []
    def code(machine, pc, size, _):
        if pc in (0xcd4, 0xabc, 0xac2, 0xe80):
            stops.append(pc)
            machine.emu_stop()
            return
        if not permitted_pc(pc, size):
            raise RuntimeError(f'escaped boot interface gate at {pc:#x}+{size}')
    def write(machine, access, address, size, value, _):
        if size in (2, 4) and STACK-10 <= address and address+size <= STACK:
            return
        if address != RAM+0x10 or size != 1 or writes:
            raise RuntimeError('unexpected interface-gate write')
        writes.append(value)
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(0xcc6, 0, count=20)
    if stops != [0xcd4] or uc.reg_read(UC_M68K_REG_A7) != STACK or len(writes) != 1:
        raise RuntimeError('interface producer missed its boundary')
    flag = int.from_bytes(uc.mem_read(RAM+0x10, 1), 'big')
    # Same synthetic RAM; omitted C20 epilogue and intermediate startup calls
    # are explicitly not presumed to preserve this flag in a physical startup.
    stops.clear()
    uc.emu_start(0xab4, 0, count=10)
    if len(stops) != 1 or uc.reg_read(UC_M68K_REG_A7) != STACK:
        raise RuntimeError('initializer call guard missed its boundary')
    initializer_boundary = stops[0]
    stops.clear()
    uc.emu_start(0xe68, 0, count=20)
    if stops != [0xe80] or uc.reg_read(UC_M68K_REG_A7) != STACK-8:
        raise RuntimeError('boot idle mask sequence missed its boundary')
    return dict(context=dict(synthetic_hardware_word=hardware_word), interface_flag=flag,
                reaches_initializer_call=initializer_boundary == 0xabc, stop_before=hex(initializer_boundary),
                idle_interrupt_mask=(uc.reg_read(UC_M68K_REG_SR)>>8)&7,
                idle_stop_before='0xe80', idle_stack_delta=-8, actual_interrupt_delivered=False,
                physical_read_executed=False, initializer_executed=False,
                full_startup_executed=False, intervening_effects_omitted=True,
                hardware_register_meaning_verified=False, vpw_reentry_verified=False,
                transport_used=False, live_write_enabled=False, ready_to_flash=False, would_send=[])


def audit(low):
    values = list(range(256))+[0x1200, 0x1214, 0x1215, 0xff14, 0xffff]
    cases = [experiment(low, hardware_word=value) for value in values]
    return dict(mode='offline_boot_interface_gate', low_sha256=EXPECTED_LOW,
                generator_sha256=sha256(Path(__file__).read_bytes()),
                source_ranges=[dict(start=hex(a), exclusive_end=hex(b), sha256=sha256(low[a:b])) for a, b in RANGES],
                cases=cases, limits='The hardware word is synthetic; physical register read, preceding peripheral readiness loop and full startup/IRQ are unverified.',
                physical_recovery_verified=False, live_write_enabled=False, ready_to_flash=False, would_send=[])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--low', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        p.error('output must be a new report path')
    result = audit(args.low.read_bytes())
    with args.output.open('x', encoding='utf-8', newline='\n') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    print(json.dumps(dict(cases=len(result['cases']), ready_to_flash=False)))


if __name__ == '__main__':
    main()
