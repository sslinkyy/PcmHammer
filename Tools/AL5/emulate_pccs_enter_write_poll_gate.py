"""Pinned EnterWrite post-status polling loop, with synthetic helpers.

Security, request dispatch and previous EnterWrite phases are excluded.
No Windows API, virtual identification body, transport or controller executes.
Identity polling does not prove reset effects or complete EnterWrite behavior.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

START, IDENTIFY_RETURN, STOP = 0x5b8fee, 0x5b90b5, 0x5b9154
THIS, STACK, VIRTUAL = 0x10000000, 0x20000000, 0x30000000
DELAY = 0x40e3e4
BOUNDARIES = {0x5b9144: 'prior_host_status_error', STOP: 'poll_or_alternate_exit'}


def permitted_pc(address, size):
    return size > 0 and (START <= address and address+size <= STOP
                         or 0x5b0af0 <= address and address+size <= 0x5b0af8)


def permitted_write(address, size):
    return size > 0 and (STACK <= address and address+size <= STACK+0x10000
                         or address in (0x81d104, THIS+0x528a4) and size == 1)


def run(data, *, status=0, alternate=0, version=0, prior_d104=1,
        identify_statuses=(0,)*12, boot_states=(True,)*12):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if (any(type(v) is not int or not 0 <= v <= 255 for v in (status, version))
            or any(type(v) is not int or v not in (0, 1) for v in (alternate, prior_d104))
            or not isinstance(identify_statuses, tuple) or not identify_statuses or any(type(v) is not int or not 0 <= v <= 255 for v in identify_statuses)
            or not isinstance(boot_states, tuple) or not boot_states or any(type(v) is not bool for v in boot_states)):
        raise ValueError('Invalid synthetic EnterWrite gate context')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ECX, UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP
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
    uc.mem_map(VIRTUAL, 0x1000)
    uc.mem_write(THIS, struct.pack('<I', VIRTUAL))
    uc.mem_write(VIRTUAL+0x70, struct.pack('<I', VIRTUAL+0x100))
    uc.mem_write(THIS+3*0xa4+0x80, b'\x01')
    uc.mem_write(THIS+3*0xa4+0xb6, bytes([version]))
    uc.mem_write(THIS+0x528a4, bytes([status]))
    uc.mem_write(THIS+0x72d90, bytes([alternate]))
    uc.mem_write(0x81d0f4, struct.pack('<I', 3))
    uc.mem_write(0x81d138, b'\x00')
    uc.mem_write(0x81d104, bytes([prior_d104]))
    sp = STACK+0x7f00
    uc.reg_write(UC_X86_REG_ESI, THIS)
    uc.reg_write(UC_X86_REG_EBX, 3)
    uc.reg_write(UC_X86_REG_EBP, STACK+0x8000)
    uc.reg_write(UC_X86_REG_ESP, sp)
    calls, stops, count, global_writes = [], [], [0], []
    identification_count, boot_count = [0], [0]

    def code(engine, address, size, _):
        if address in BOUNDARIES:
            stops.append(BOUNDARIES[address])
            engine.emu_stop()
            return
        if address == DELAY:
            current = engine.reg_read(UC_X86_REG_ESP)
            target, milliseconds = struct.unpack('<II', engine.mem_read(current, 8))
            if target not in (0x5b904b, 0x5b9057, 0x5b90f6) or milliseconds not in (500, 2000, 3000):
                raise ValueError('Unexpected synthetic delay context')
            calls.append({'kind': 'synthetic_delay', 'milliseconds': milliseconds})
            engine.reg_write(UC_X86_REG_ESP, current+8)
            engine.reg_write(UC_X86_REG_EIP, target)
            return
        if address == VIRTUAL+0x100:
            current = engine.reg_read(UC_X86_REG_ESP)
            target = struct.unpack('<I', engine.mem_read(current, 4))[0]
            if (target != IDENTIFY_RETURN or current != sp-4
                    or engine.reg_read(UC_X86_REG_EAX) != THIS
                    or engine.reg_read(UC_X86_REG_EDX) != 0
                    or engine.reg_read(UC_X86_REG_ECX) != 0):
                raise ValueError('Unexpected synthetic identification context')
            if identification_count[0] >= len(identify_statuses):
                raise ValueError('Exhausted synthetic identification statuses')
            reply = identify_statuses[identification_count[0]]
            identification_count[0] += 1
            engine.mem_write(THIS+0x528a4, bytes([reply]))
            calls.append({'kind': 'synthetic_identification', 'vmt_offset': 0x70, 'host_status': reply})
            engine.reg_write(UC_X86_REG_ESP, current+4)
            engine.reg_write(UC_X86_REG_EIP, target)
            return
        if address == 0x5adc54:
            current = engine.reg_read(UC_X86_REG_ESP)
            target = struct.unpack('<I', engine.mem_read(current, 4))[0]
            if (target != 0x5b90d9 or engine.reg_read(UC_X86_REG_EAX) != THIS
                    or engine.reg_read(UC_X86_REG_EDX) != 3 or boot_count[0] >= len(boot_states)):
                raise ValueError('Unexpected or exhausted synthetic boot predicate context')
            value = boot_states[boot_count[0]]
            boot_count[0] += 1
            calls.append({'kind': 'synthetic_boot_predicate', 'result': value})
            engine.reg_write(UC_X86_REG_EAX, int(value))
            engine.reg_write(UC_X86_REG_ESP, current+4)
            engine.reg_write(UC_X86_REG_EIP, target)
            return
        if address == 0x407208:
            current = engine.reg_read(UC_X86_REG_ESP)
            target = struct.unpack('<I', engine.mem_read(current, 4))[0]
            if (target != 0x5b9019 or engine.reg_read(UC_X86_REG_EAX) != THIS+3*0xa4+0x44
                    or engine.reg_read(UC_X86_REG_EDX) != 0x5b9324):
                raise ValueError('Unexpected synthetic alternate identity assignment')
            calls.append({'kind': 'synthetic_alternate_identity_assignment'})
            engine.reg_write(UC_X86_REG_ESP, current+4)
            engine.reg_write(UC_X86_REG_EIP, target)
            return
        if not permitted_pc(address, size):
            raise ValueError(f'Unexpected EnterWrite gate PC {address:#x}+{size}')
        count[0] += 1

    def write(engine, access, address, size, value, _):
        if address == 0x81d104 and size == 1:
            global_writes.append(value & 255)
        if not permitted_write(address, size):
            raise ValueError(f'Unexpected EnterWrite gate write {address:#x}+{size}')

    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, 0, count=5000)
    if (uc.reg_read(UC_X86_REG_EIP) not in BOUNDARIES or len(stops) != 1
            or uc.reg_read(UC_X86_REG_ESP) != sp):
        raise ValueError('EnterWrite gate did not reach declared boundary with balanced calls')
    return {'context': {'host_status': status, 'alternate_route': alternate, 'version': version,
                        'family': 1, 'selected_index': 3, 'prior_d104': prior_d104,
                        'identify_statuses': list(identify_statuses), 'boot_states': list(boot_states)},
            'boundary': stops[0], 'calls': calls, 'instruction_observations': count[0],
            'identification_count': identification_count[0], 'boot_predicate_count': boot_count[0],
            'final_host_status': uc.mem_read(THIS+0x528a4, 1)[0],
            'final_d104': uc.mem_read(0x81d104, 1)[0], 'native_d104_writes': global_writes,
            'full_enter_write_executed': False, 'identification_body_executed': False,
            'transport_used': False, 'windows_api_executed': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def audit(data):
    cases = [run(data, status=s, alternate=a) for s in (0, 1, 12) for a in (0, 1)]
    cases.append(run(data, version=3))
    cases.append(run(data, boot_states=(False, True)))
    cases.append(run(data, boot_states=(False,)*12))
    cases.append(run(data, identify_statuses=(9,)*12))
    section = next(s for s in executable_sections(data)
                   if s['va'] <= START and STOP <= s['va']+s['raw_bytes'])
    offset = section['raw_offset']+START-section['va']
    return {'schema': 'pccs-enter-write-post-status-native-poll-v1', 'source_sha256': SOURCE_SHA256,
            'source_range': {'start': hex(START), 'exclusive_end': hex(STOP),
                             'file_offset': offset,
                             'sha256': hashlib.sha256(data[offset:offset+STOP-START]).hexdigest()},
            'cases': cases,
            'limitations': ['Interior post-status polling only; preparation, security and request dispatch excluded.',
                            'Host status, selected identity and alternate routing are synthetic.',
                            'Delay, boot predicate, alternate assignment and virtual identification are replacements; no actual reset/identification executes.',
                            'Logs are disabled; controller, programming and recovery are unqualified.'],
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
