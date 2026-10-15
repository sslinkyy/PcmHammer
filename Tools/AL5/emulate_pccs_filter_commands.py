"""Pinned PCCS filter-command buffer construction; synthetic callback only.

Identification target gate and filter emitter are independent phases. The
emitter assumes driver-name eligibility. No RP1210 command, API or I/O runs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

THIS, STACK, STUB = 0x10000000, 0x20000000, 0x30000000
GATE_START, GATE_STOP = 0x5d9c9a, 0x5d9caa
EMITTERS = {'identification': (0x5d9e23, 0x5d9f04), 'enter_write': (0x5b88e2, 0x5b8959)}
RETURNS = {'identification': (0x5d9e42, 0x5d9ea0, 0x5d9f04),
           'enter_write': (0x5b88f2, 0x5b8926, 0x5b8959)}


def permitted_pc(mode, phase, address, size):
    if size <= 0 or mode not in EMITTERS:
        return False
    if phase == 'gate':
        return GATE_START <= address and address+size <= GATE_STOP
    if phase != 'emitter':
        return False
    start, stop = EMITTERS[mode]
    return start <= address and address+size <= stop


def permitted_write(address, size):
    return size > 0 and STACK <= address and address+size <= STACK+0x10000


def run(data, *, mode='identification', target=3, command_result=0):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if (type(mode) is not str or mode not in EMITTERS
            or type(target) is not int or not 0 <= target <= 255
            or type(command_result) is not int or not 0 <= command_result <= 0xffff):
        raise ValueError('Invalid synthetic filter context')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+24+28)[0]
    size = struct.unpack_from('<I', data, pe+24+56)[0]
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(base, (size+0xfff)&~0xfff)
    for section in executable_sections(data):
        off = section['raw_offset']
        uc.mem_write(section['va'], data[off:off+section['raw_bytes']])
    uc.mem_map(THIS, 0x75000)
    uc.mem_map(STACK, 0x10000)
    uc.mem_map(STUB, 0x1000)
    uc.mem_write(THIS+0x10, struct.pack('<I', STUB+0x100))
    uc.mem_write(THIS+0x2c, struct.pack('<H', 0x3456))
    uc.mem_write(THIS+0x528a4, b'\x00')
    uc.mem_write(0x81d0f4, struct.pack('<I', target))
    bp, sp = STACK+0x8000, STACK+0x7000
    uc.mem_write(bp-0x104, struct.pack('<I', THIS))
    uc.reg_write(UC_X86_REG_EBP, bp)
    uc.reg_write(UC_X86_REG_ESP, sp)
    uc.reg_write(UC_X86_REG_ESI, THIS)
    uc.reg_write(UC_X86_REG_EBX, target)
    phase, boundaries, commands, count = ['gate'], [], [], [0]

    def code(engine, address, size, _):
        if phase[0] == 'gate' and address in (GATE_STOP, 0x5d9f04):
            boundaries.append(address)
            engine.emu_stop()
            return
        if phase[0] == 'emitter' and address == EMITTERS[mode][1]:
            boundaries.append(address)
            engine.emu_stop()
            return
        if phase[0] == 'emitter' and address == STUB+0x100:
            current = engine.reg_read(UC_X86_REG_ESP)
            target_pc, command, connection, buffer, length = struct.unpack('<IIIII', engine.mem_read(current, 20))
            slot = len(commands)
            if (slot >= 3 or target_pc != RETURNS[mode][slot]
                    or command != (17 if slot == 0 else 5) or connection != 0x3456
                    or length != (0 if slot == 0 else 9)
                    or not STACK <= buffer <= STACK+0x10000-length):
                raise ValueError('Unexpected synthetic filter callback context')
            payload = bytes(engine.mem_read(buffer, length)) if length else b''
            commands.append({'command': command, 'connection': connection, 'length': length,
                             'payload_hex': payload.hex(), 'synthetic_result': command_result})
            engine.reg_write(UC_X86_REG_EAX, command_result)
            engine.reg_write(UC_X86_REG_ESP, current+20)
            engine.reg_write(UC_X86_REG_EIP, target_pc)
            return
        if not permitted_pc(mode, phase[0], address, size):
            raise ValueError(f'Unexpected filter PC {address:#x}+{size}')
        count[0] += 1

    def write(engine, access, address, size, value, _):
        if not permitted_write(address, size):
            raise ValueError(f'Unexpected filter write {address:#x}+{size}')

    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    gate_result = None
    if mode == 'identification':
        uc.emu_start(GATE_START, 0, count=100)
        if len(boundaries) != 1 or uc.reg_read(UC_X86_REG_ESP) != sp:
            raise ValueError('Identification filter gate did not stop at declared boundary')
        gate_result = 'driver_name_check' if boundaries[0] == GATE_STOP else 'bypass_filter_block'
    emit = mode == 'enter_write' or gate_result == 'driver_name_check'
    if emit:
        phase[0] = 'emitter'
        boundaries.clear()
        uc.emu_start(EMITTERS[mode][0], 0, count=2000)
        if (boundaries != [EMITTERS[mode][1]] or len(commands) != 3
                or uc.reg_read(UC_X86_REG_ESP) != sp):
            raise ValueError('Filter emitter did not finish with balanced synthetic callbacks')
    return {'context': {'mode': mode, 'target': target, 'command_result': command_result},
            'identification_gate': gate_result, 'emitter_phase_handoff': emit,
            'driver_name_eligibility_assumed': emit,
            'commands': commands, 'final_host_status': uc.mem_read(THIS+0x528a4, 1)[0],
            'instruction_observations': count[0], 'rp1210_callback_executed': False,
            'filter_installed': False, 'transport_used': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def audit(data):
    contexts = [dict(target=target, command_result=result) for target in (3, 0xf3) for result in (0, 9)]
    contexts += [dict(mode='enter_write', target=3, command_result=result) for result in (0, 9)]
    contexts.append(dict(mode='enter_write', target=0xf3))
    cases = [run(data, **context) for context in contexts]
    ranges = []
    for name, (start, stop) in [('target_gate', (GATE_START, GATE_STOP)), *EMITTERS.items()]:
        section = next(s for s in executable_sections(data)
                       if s['va'] <= start and stop <= s['va']+s['raw_bytes'])
        offset = section['raw_offset']+start-section['va']
        ranges.append({'name': name, 'start': hex(start), 'exclusive_end': hex(stop), 'file_offset': offset,
                       'sha256': hashlib.sha256(data[offset:offset+stop-start]).hexdigest()})
    return {'schema': 'pccs-filter-target-gate-and-emitter-native-v1', 'source_sha256': SOURCE_SHA256,
            'source_ranges': ranges, 'cases': cases,
            'limitations': ['Identification target gate and emitter use an explicit independent phase handoff.',
                            'Driver-name eligibility is assumed; no complete identification or EnterWrite.',
                            'Numeric command callbacks are synthetic; filter installation/driver behavior unproven.',
                            'Payload mask interpretation/additive admission semantics require separate evidence.'],
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


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
    print(json.dumps({'cases': len(result['cases']), 'ready_to_flash': False}))


if __name__ == '__main__':
    main()
