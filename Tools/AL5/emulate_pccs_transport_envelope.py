"""Pinned PCCS CAN-envelope formatting and ordinary packet assembly offline.

Initial E2 context runs its header formatter only. Ordinary contexts use an
explicit native phase handoff to packet assembly and stop before the driver
callback. Byte copies are guarded replacements; no send/API/device executes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

THIS, STACK, EXIT = 0x10000000, 0x20000000, 0x30000000
HEADER_RANGES = {'initial': (0x5a8bb8, 0x5a8c17), 'ordinary': (0x5a8c58, 0x5a8d1d)}
SWAP_START, SWAP_STOP = 0x5adbfc, 0x5adc28
PACK_START, PACK_STOP = 0x5a927e, 0x5a92e7
DRIVER_BOUNDARIES = (0x5a92b1, 0x5a92e2)


def permitted_pc(mode, phase, address, size):
    if size <= 0 or mode not in HEADER_RANGES:
        return False
    if phase == 'packet':
        return PACK_START <= address and address+size <= PACK_STOP
    if phase != 'header':
        return False
    start, stop = HEADER_RANGES[mode]
    return start <= address and address+size <= stop or SWAP_START <= address and address+size <= SWAP_STOP


def permitted_write(phase, address, size):
    return phase in ('header', 'packet') and size > 0 and (STACK <= address and address+size <= STACK+0x10000
                         or phase == 'header' and address == THIS+0x528b0 and size == 1)


def run(data, *, mode='ordinary', ccp_control=0, target=3, source=0xf9,
        initial_id=0x7e0, ccp_id=0x7e0, alternate=1):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if (type(mode) is not str or mode not in HEADER_RANGES
            or any(type(v) is not int or not 0 <= v <= 255 for v in (ccp_control, target, source, alternate))
            or type(initial_id) is not int or not 0 <= initial_id <= 0xffff
            or type(ccp_id) is not int or not 0 <= ccp_id <= 0xffffffff):
        raise ValueError('Invalid synthetic formatter context')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ECX, UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP
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
    uc.mem_map(EXIT, 0x1000)
    uc.mem_write(THIS+0x74888, struct.pack('<I', initial_id))
    uc.mem_write(THIS+0x74890, struct.pack('<I', ccp_id))
    uc.mem_write(THIS+0x72d90, bytes([alternate, 1, 1, 1]))
    uc.mem_write(THIS+0x2c, struct.pack('<H', 0x3456))
    uc.mem_write(THIS+0x52250, b'\x35')
    uc.mem_write(0x81d108, bytes([ccp_control]))
    uc.mem_write(0x81d0fc, bytes([source]))
    sp, bp = STACK+0x7000, STACK+0x8000
    uc.mem_write(sp, struct.pack('<I', EXIT))
    uc.reg_write(UC_X86_REG_EAX, THIS)
    uc.reg_write(UC_X86_REG_EDX, 0 if mode == 'initial' else target)
    uc.reg_write(UC_X86_REG_EBP, bp)
    uc.reg_write(UC_X86_REG_ESP, sp)
    phase, copies, stops, count = ['header'], [], [], [0]

    def code(engine, address, size, _):
        if phase[0] == 'packet' and address in DRIVER_BOUNDARIES:
            stops.append(address)
            engine.emu_stop()
            return
        if address == 0x404820:
            current = engine.reg_read(UC_X86_REG_ESP)
            target_pc = struct.unpack('<I', engine.mem_read(current, 4))[0]
            src, dst, length = (engine.reg_read(reg) for reg in (UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ECX))
            if phase[0] == 'header':
                expected_lengths = {0x5a8c14: 2, 0x5a8c9b: 4, 0x5a8cd4: 2, 0x5a8d0f: 4}
                allowed = (target_pc in expected_lengths and length == expected_lengths[target_pc]
                           and dst == THIS+0x528b1 and STACK <= src and src+length <= STACK+0x10000)
            else:
                destinations = {0x5a929a: THIS+0x528b5, 0x5a92cb: THIS+0x528b3}
                allowed = (target_pc in destinations and dst == destinations[target_pc]
                           and src == THIS+0x52250 and length == 1)
            if not allowed:
                raise ValueError('Unexpected synthetic envelope copy context')
            engine.mem_write(dst, bytes(engine.mem_read(src, length)))
            copies.append({'phase': phase[0], 'length': length, 'destination_offset': dst-THIS})
            engine.reg_write(UC_X86_REG_ESP, current+4)
            engine.reg_write(UC_X86_REG_EIP, target_pc)
            return
        if not permitted_pc(mode, phase[0], address, size):
            raise ValueError(f'Unexpected formatter PC {address:#x}+{size}')
        count[0] += 1

    def write(engine, access, address, size, value, _):
        if not permitted_write(phase[0], address, size):
            raise ValueError(f'Unexpected formatter write {address:#x}+{size}')

    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(HEADER_RANGES[mode][0], EXIT, count=2000)
    if (uc.reg_read(UC_X86_REG_EIP) != EXIT or uc.reg_read(UC_X86_REG_ESP) != sp+4
            or uc.reg_read(UC_X86_REG_EBP) != bp):
        raise ValueError('Formatter did not return through declared boundary with balanced calls')
    frame_format = uc.mem_read(THIS+0x528b0, 1)[0]
    header_length = 5 if frame_format == 1 else 3
    header = bytes(uc.mem_read(THIS+0x528b0, header_length))
    packet = None
    if mode == 'ordinary':
        phase[0] = 'packet'
        uc.reg_write(UC_X86_REG_EBX, THIS)
        uc.reg_write(UC_X86_REG_EDI, 1)
        uc.reg_write(UC_X86_REG_ESP, sp)
        uc.emu_start(PACK_START, 0, count=1000)
        if len(stops) != 1 or uc.reg_read(UC_X86_REG_ESP) != sp-20:
            raise ValueError('Packet builder did not stop at driver boundary with five pending arguments')
        args = struct.unpack('<IIIII', uc.mem_read(sp-20, 20))
        if args != (0x3456, THIS+0x528b0, header_length+1, 0, 0):
            raise ValueError('Unexpected pending driver arguments')
        packet = {'hex': bytes(uc.mem_read(THIS+0x528b0, header_length+1)).hex(),
                  'length': header_length+1, 'connection_argument': args[0],
                  'callback_object_offset': 8, 'driver_call_boundary': hex(stops[0]),
                  'driver_callback_executed': False, 'independent_phase_handoff': True}
    return {'context': {'mode': mode, 'ccp_control': ccp_control, 'target': target, 'source': source,
                        'initial_id': initial_id, 'ccp_id': ccp_id, 'alternate': alternate},
            'format': frame_format, 'header_hex': header.hex(), 'ordinary_packet': packet,
            'final_alternate_bytes': bytes(uc.mem_read(THIS+0x72d90, 4)).hex(),
            'copies': copies, 'instruction_observations': count[0],
            'full_dispatcher_executed': False, 'initial_packet_builder_executed': False,
            'transport_used': False, 'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def audit(data):
    contexts = [{'mode': 'initial'}, {}, {'source': 0xf8, 'target': 4},
                {'ccp_control': 1}, {'ccp_control': 1, 'ccp_id': 0x18da03f9}, {'alternate': 0}]
    cases = [run(data, **context) for context in contexts]
    ranges = []
    for name, (start, stop) in [*HEADER_RANGES.items(), ('byte_order', (SWAP_START, SWAP_STOP)),
                               ('packet_prefix', (PACK_START, PACK_STOP))]:
        section = next(s for s in executable_sections(data)
                       if s['va'] <= start and stop <= s['va']+s['raw_bytes'])
        offset = section['raw_offset']+start-section['va']
        ranges.append({'name': name, 'start': hex(start), 'exclusive_end': hex(stop), 'file_offset': offset,
                       'sha256': hashlib.sha256(data[offset:offset+stop-start]).hexdigest()})
    return {'schema': 'pccs-formatters-ordinary-driver-boundary-native-v1', 'source_sha256': SOURCE_SHA256,
            'source_ranges': ranges, 'cases': cases,
            'limitations': ['Independent initial/ordinary formatting phases; no full invocation or complete dispatcher.',
                            'Ordinary packet assembly stops before driver callback; copies are synthetic.',
                            'Initial E2 packet padding and sending do not execute.',
                            'No actual AL5 mixed-format support, protocol transition, programming or recovery proof.'],
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
