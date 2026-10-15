"""Bounded cold ROM copy through the initial calibration-check call boundary.

Actual instructions prepare the VBR write and preserve copied flag/CRC state. Timer
MMIO instructions are suppressed before execution; reported effects are synthetic.
"""
import argparse
import json
from pathlib import Path
from al5_segment import START, LENGTH, sha256
from emulate_calibration_marker import validate_source, marker_case, reset_marker_branch
from emulate_calibration_startup import executable_span as copy_executable_span
from emulate_calibration_startup import writable_span as copy_writable_span
from emulate_calibration_startup import ROM_START, PREFIX_START, PREFIX_END, FLAG, SEED, COPY_ENTRY, COPY_STOP

BASE, CHECK_CALL = 0xFF8000, 0x994F8
RANGES = ((0x994D0, 0x994FE), (0xC5B54, 0xC5B68), (0xC5A88, 0xC5A9C),
          (0xBEBA0, 0xBEC1E), (0xBEB74, 0xBEB96), (0x21CE0, 0x21D08), (0x21D1E, 0x21D2E))
SUPPRESSED_MMIO = {0xBEB7E: (0xBEB86, 0xFFFA24), 0xBEB86: (0xBEB8E, 0xFFFA22)}
COPY_WATCHDOG = {0xBE49A: 0xBE4A2, 0xBE4A2: 0xBE4AA, 0xBE4D8: 0xBE4E0, 0xBE4E0: 0xBE4E8}


def initializer_executable_span(pc, size):
    return size > 0 and any(a <= pc and pc + size <= b for a, b in RANGES)


def initializer_writable_span(address, size):
    return size > 0 and any(a <= address and address + size <= b for a, b in (
        (0x200000, 0x210000), (BASE, BASE + 2), (BASE + 0x20BA, BASE + 0x20BB),
        (BASE + 0x1DCA, BASE + 0x1DCC), (BASE + 0x12C, BASE + 0x138)))


def pre_marker_initializers(low, high, *, synthetic_timer_control=0):
    validate_source(low, high)
    if type(synthetic_timer_control) is not int or not 0 <= synthetic_timer_control <= 0xFFFF:
        raise ValueError('synthetic timer control must be a word, not Boolean')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('requires the pinned Unicorn 2.1.4 runtime')
    from emulate_startup_context import Startup
    from emulate_storage_recovery import begin
    from unicorn.m68k_const import UC_M68K_REG_PC, UC_M68K_REG_SR, UC_M68K_REG_A0, UC_M68K_REG_D0
    data = low + high

    class Initializers(Startup):
        def __init__(self):
            self.stage = 'copy'
            self.owned_stop = None
            self.suppressed_mmio = []
            self.native_initializer_writes = []
            self.executed_entries = []
            self.vector_base_write_source = None
            self.suppressed_copy_watchdog_count = 0
            super().__init__(low, high, fill=0xA5)
            for a, b in RANGES:
                self.uc.mem_write(a, data[a:b])
            self.uc.mem_write(0xC5A40, data[0xC5A40:0xC5A44])

        def hook(self, machine, pc, size, user_data):
            if self.stage == 'copy':
                if not copy_executable_span(pc, size):
                    raise RuntimeError(f'escaped startup copy at {pc:#x}')
                if pc == COPY_STOP:
                    self.owned_stop = pc
                    machine.emu_stop()
                elif pc in COPY_WATCHDOG:
                    self.suppressed_copy_watchdog_count += 1
                    machine.reg_write(UC_M68K_REG_PC, COPY_WATCHDOG[pc])
                return
            if not initializer_executable_span(pc, size):
                raise RuntimeError(f'escaped pre-marker initializer ranges at {pc:#x}')
            if pc == CHECK_CALL:
                self.owned_stop = pc
                machine.emu_stop()  # BEFORE entering marker/CRC checker.
            elif pc == 0x21D26:
                # The instruction executes normally. Unicorn 2.1.4's exposed
                # CR_VBR read API is undefined, so retain its real source value
                # without inventing a verified architectural readback.
                self.vector_base_write_source = machine.reg_read(UC_M68K_REG_D0)
            elif pc in SUPPRESSED_MMIO:
                next_pc, target = SUPPRESSED_MMIO[pc]
                if pc == 0xBEB7E:
                    a0 = machine.reg_read(UC_M68K_REG_A0)
                    if a0 != BASE + 0x134:
                        raise RuntimeError('unexpected timer reload source')
                    value = int.from_bytes(machine.mem_read(a0 + 2, 2), 'big')
                    origin = 'actual computed RAM reload word'
                else:
                    value = synthetic_timer_control | 0x600
                    origin = 'explicit synthetic control word OR 0x0600'
                self.suppressed_mmio.append({'pc': hex(pc), 'source_hex': data[pc:next_pc].hex(),
                    'target': hex(target), 'would_write_word': hex(value), 'provenance': origin,
                    'instruction_executed': False, 'physical_effect_verified': False})
                machine.reg_write(UC_M68K_REG_PC, next_pc)
            elif pc in (0x994D0, 0xC5B54, 0x21D1E, 0xC5A88, 0xBEBA0, 0xBEB74, 0x21CE0):
                self.executed_entries.append(hex(pc))

        def write_hook(self, machine, access, address, size, value, user_data):
            if self.stage == 'copy':
                if address == 0xFFFA27 or not copy_writable_span(address, size):
                    raise RuntimeError('unexpected startup-copy write')
            elif not initializer_writable_span(address, size):
                raise RuntimeError(f'forbidden initializer native write at {address:#x} size {size}')
            elif not 0x200000 <= address < 0x210000:
                self.native_initializer_writes.append({'address': hex(address), 'size': size, 'value': hex(value)})

    session = Initializers()
    begin(session, COPY_ENTRY)
    if session.owned_stop != COPY_STOP:
        raise RuntimeError('copy did not stop at first initializer')
    copied_flag = session.uc.mem_read(FLAG, 1)[0]
    copied_seed = int.from_bytes(session.uc.mem_read(SEED, 2), 'big')
    prefix = bytes(session.uc.mem_read(PREFIX_START, PREFIX_END - PREFIX_START))
    if prefix != data[ROM_START:ROM_START + len(prefix)]:
        raise RuntimeError('cold copied prefix disagrees with pinned ROM')
    # Resume the same native session and stack at its actual pending JSR target.
    session.stage = 'initializers'
    session.owned_stop = None
    session.uc.emu_start(COPY_STOP, 0, timeout=2_000_000, count=10000)
    if session.owned_stop != CHECK_CALL or session.uc.reg_read(UC_M68K_REG_PC) != CHECK_CALL:
        raise RuntimeError('initializers did not stop before marker check')
    flag = session.uc.mem_read(FLAG, 1)[0]
    seed = int.from_bytes(session.uc.mem_read(SEED, 2), 'big')
    vbr_source = session.vector_base_write_source
    if flag != copied_flag or seed != copied_seed or vbr_source != 0x20410:
        raise RuntimeError('unexpected initializer flag/seed/VBR result')
    if len(session.suppressed_mmio) != 2:
        raise RuntimeError('unexpected timer MMIO path')
    return {'stop_pc': hex(CHECK_CALL), 'copied_initial_check_flag': copied_flag, 'copied_crc_seed': copied_seed,
        'copy_and_initializers_same_native_session': True, 'pre_marker_initializers_executed': True,
        'initial_check_flag_after_initializers': flag, 'crc_seed_after_initializers': seed,
        'flag_seed_preserved': True, 'vector_base_write_source': hex(vbr_source),
        'application_ram_marker_before_check': hex(int.from_bytes(session.uc.mem_read(BASE, 2), 'big')),
        'movec_instruction_executed': True, 'vector_base_register_readback_verified': False,
        'interrupt_mask_after_actual_helper': (session.uc.reg_read(UC_M68K_REG_SR) >> 8) & 7,
        'dynamic_initializer_pointer': hex(int.from_bytes(data[0xC5A40:0xC5A44], 'big')),
        'executed_entries': session.executed_entries,
        'native_ram_writes': session.native_initializer_writes,
        'synthetic_timer_control_input': hex(synthetic_timer_control),
        'suppressed_startup_watchdog_instruction_count': session.suppressed_copy_watchdog_count,
        'suppressed_timer_mmio_instructions': session.suppressed_mmio,
        'hidden_instruction_substitutions': [], 'complete_hardware_startup_verified': False,
        'physical_recovery_verified': False, 'ready_to_flash': False, 'live_write_enabled': False}


def audit(low, high):
    validate_source(low, high)
    contexts = [pre_marker_initializers(low, high, synthetic_timer_control=v) for v in (0, 0x8000, 0xFFFF)]
    first = contexts[0]
    stock = low[START:START + LENGTH]
    bad = bytearray(stock)
    bad[0x200] ^= 1
    linked = []
    for name, marker, calibration, expected in (
            ('saved_calibration', 0x4AFC, stock, 'returned'),
            ('erased_marker', 0xFFFF, stock, 'completion_marker_rejected'),
            ('payload_fault', 0x4AFC, bytes(bad), 'calibration_crc_rejected')):
        observed = marker_case(low, high, marker=marker, calibration=calibration,
            initial_check=first['initial_check_flag_after_initializers'] != 0,
            crc_seed=first['crc_seed_after_initializers'],
            initial_ram_marker=int(first['application_ram_marker_before_check'], 0))
        if observed['stop'] != expected or observed['marker_reads'] != 1:
            raise RuntimeError('unexpected post-initializer marker behavior')
        branch = reset_marker_branch(low, int(observed['reset_marker'], 0)) if observed['stop'] != 'returned' else None
        linked.append({'name': name, 'observed_marker_check': observed, 'separate_selected_reset_branch': branch,
            'flag_seed_from_copy_and_executed_initializers': True,
            'initial_ram_marker_from_executed_initializers': True})
    data = low + high
    sources = list(RANGES) + [(0xC5A40, 0xC5A44), (ROM_START, ROM_START + PREFIX_END - PREFIX_START)]
    return {'mode': 'offline_pre_marker_initializers_with_timer_mmio_suppressed',
        'low_sha256': sha256(low), 'high_sha256': sha256(high), 'unicorn_version': '2.1.4',
        'generator_sha256': sha256(Path(__file__).read_bytes()),
        'dependency_sha256': {name: sha256(Path(__file__).with_name(name).read_bytes()) for name in (
            'emulate_calibration_startup.py', 'emulate_calibration_marker.py',
            'emulate_startup_context.py', 'emulate_storage_recovery.py')},
        'source_ranges': [{'start': hex(a), 'exclusive_end': hex(b), 'sha256': sha256(data[a:b])} for a, b in sources],
        'initializer_cases': contexts, 'linked_cases': linked, 'all_pass': True,
        'pre_marker_initializers_executed': True,
        'limitations': ['Actual ROM copy and pre-marker initializer instructions run in one native session; timer MMIO instructions are suppressed before execution.',
            'The real source register for MOVEC VBR is observed; Unicorn 2.1.4 does not provide a defined CR_VBR readback through its register API.',
            'CPU instructions and SR changes do not establish that physical hardware accepted configuration or delivered interrupts.',
            'Separate marker cases transfer flag/seed/RAM marker into fresh synthetic memory; they do not preserve every startup RAM field or CPU register.',
            'Reset/boot startup before application entry and actual power-loss VPW recovery remain unverified.'],
        'complete_hardware_startup_verified': False, 'physical_recovery_verified': False,
        'ready_to_flash': False, 'live_write_enabled': False, 'would_send': []}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('low', 'high', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error('output must be a new report path')
    report = audit(args.low.read_bytes(), args.high.read_bytes())
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'initializer_cases': len(report['initializer_cases']), 'linked_cases': len(report['linked_cases']),
        'all_pass': True, 'ready_to_flash': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
