"""Pinned SoftUSB outgoing CAN conversion; stops before CANPC_send_data.

Queue result and byte copies are synthetic. No DLL/API/device is called.
These are constructed call arguments, not a live-write implementation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_softusb_receive import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

START, STOP = 0x4021b8, 0x40223f
SWAP, SWAP_STOP = 0x40205c, 0x402084
BOUNDARIES = (0x402203, 0x402234)
STACK, BUFFER, EXIT = 0x20000000, 0x30000000, 0x40000000


def permitted_pc(address, size):
    return size > 0 and (START <= address and address+size <= STOP
                         or SWAP <= address and address+size <= SWAP_STOP)


def permitted_write(address, size):
    return size > 0 and STACK <= address and address+size <= STACK+0x10000


def run(data, *, frame=bytes.fromhex('0118ef03f935'), queue_level=0):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source SoftUSB pin changed')
    if (type(frame) is not bytes or not frame
            or type(queue_level) is not int or not -0x80000000 <= queue_level <= 0x7fffffff):
        raise ValueError('Invalid synthetic outgoing context')
    header_length = 3 if frame[0] == 0 else 5
    if not header_length <= len(frame) <= header_length+8:
        raise ValueError('Requires a complete synthetic CAN header and at most eight payload bytes')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ECX, UC_X86_REG_ESP, UC_X86_REG_EIP
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+24+28)[0]
    size = struct.unpack_from('<I', data, pe+24+56)[0]
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(base, (size+0xfff)&~0xfff)
    for section in executable_sections(data):
        off = section['raw_offset']
        uc.mem_write(section['va'], data[off:off+section['raw_bytes']])
    for address, size in ((STACK, 0x10000), (BUFFER, 0x1000), (EXIT, 0x1000)):
        uc.mem_map(address, size)
    uc.mem_write(BUFFER, frame)
    sp = STACK+0x8000
    uc.mem_write(sp, struct.pack('<6I', EXIT, 7, BUFFER, len(frame), 0, 0))
    uc.reg_write(UC_X86_REG_ESP, sp)
    queues, copies, stops, count = [], [], [], [0]
    def code(engine, pc, size, _):
        if pc in BOUNDARIES or pc == EXIT:
            stops.append(pc)
            engine.emu_stop()
            return
        if pc in (0x402054, 0x401218):
            current = engine.reg_read(UC_X86_REG_ESP)
            target = int.from_bytes(engine.mem_read(current, 4), 'little')
            if pc == 0x402054:
                if queues or target != 0x4021c8:
                    raise ValueError('Unexpected synthetic CAN queue callback')
                queues.append(queue_level)
                engine.reg_write(UC_X86_REG_EAX, queue_level & 0xffffffff)
            else:
                src, dst, length = (engine.reg_read(reg) for reg in (UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ECX))
                expected = (0x4021ea, BUFFER+1, 0x40473c, 2) if frame[0] == 0 else (0x40221c, BUFFER+1, 0x404738, 4)
                if copies or (target, src, dst, length) != expected:
                    raise ValueError('Unexpected synthetic outgoing ID copy')
                engine.mem_write(dst, bytes(engine.mem_read(src, length)))
                copies.append(dict(length=length, destination=hex(dst)))
            engine.reg_write(UC_X86_REG_ESP, current+4)
            engine.reg_write(UC_X86_REG_EIP, target)
            return
        if not permitted_pc(pc, size):
            raise ValueError(f'Unexpected SoftUSB outgoing PC {pc:#x}+{size}')
        count[0] += 1
    def write(engine, access, address, size, value, _):
        if not permitted_write(address, size):
            raise ValueError(f'Unexpected SoftUSB outgoing write {address:#x}+{size}')
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, 0, count=1000)
    if len(stops) != 1 or queues != [queue_level]:
        raise ValueError('Outgoing wrapper did not reach declared boundary')
    constructed, result = None, None
    if stops[0] in BOUNDARIES:
        if uc.reg_read(UC_X86_REG_ESP) != sp-28:
            raise ValueError('Unexpected pending lower-driver stack')
        identifier, extended, length, pointer = struct.unpack('<4I', uc.mem_read(sp-28, 16))
        if length != len(frame)-header_length or pointer != BUFFER+header_length:
            raise ValueError('Unexpected constructed lower-driver payload')
        constructed = dict(identifier=identifier, extended_selector=extended, payload_length=length,
                           payload_hex=bytes(uc.mem_read(pointer, length)).hex(),
                           lower_call_boundary=hex(stops[0]))
    else:
        if uc.reg_read(UC_X86_REG_ESP) != sp+24:
            raise ValueError('Outgoing queue rejection did not return with balanced stack')
        result = uc.reg_read(UC_X86_REG_EAX) & 65535
    return {'context': dict(frame_hex=frame.hex(), queue_level=queue_level),
            'boundary': 'lower_CAN_call' if constructed else 'returned',
            'constructed_CAN_arguments': constructed, 'return_word': result,
            'synthetic_copies': copies, 'instruction_observations': count[0],
            'lower_driver_executed': False, 'actual_driver_loaded_in_pccs': None,
            'transport_used': False, 'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def audit(data):
    contexts = ({}, {'frame': bytes.fromhex('0007e201a2aaaaaaaaaaaa')},
                {'frame': bytes.fromhex('0218ef03f935')}, {'frame': bytes.fromhex('6c18ef03f935')},
                {'queue_level': 69}, {'queue_level': 70}, {'queue_level': -1},
                {'frame': bytes.fromhex('0007e2')})
    cases = [run(data, **context) for context in contexts]
    ranges = []
    for start, stop in ((START, STOP), (SWAP, SWAP_STOP)):
        section = next(s for s in executable_sections(data) if s['va'] <= start and stop <= s['va']+s['raw_bytes'])
        off = section['raw_offset']+start-section['va']
        ranges.append(dict(start=hex(start), exclusive_end=hex(stop), file_offset=off,
                           sha256=hashlib.sha256(data[off:off+stop-start]).hexdigest()))
    return {'schema': 'pccs-softusb-outgoing-CAN-boundary-v1', 'source_sha256': SOURCE_SHA256,
            'source_ranges': ranges, 'cases': cases,
            'limitations': ['Synthetic queue result and ID copy; lower CANPC_send_data is never called.',
                            'Complete headers and up to eight payload bytes imposed by this bounded model.',
                            'Nonzero format is observed wrapper behavior, not validation of arbitrary headers.',
                            'No runtime-selected DLL, physical protocol, AL5 reply, programming or recovery proof.'],
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


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
