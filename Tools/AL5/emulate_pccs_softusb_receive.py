"""Pinned bundled SoftUSB RP1210 receive conversion, with synthetic CAN events.

Runs the actual exported receive entry and dispatch tables. CANPC_read_ac and
byte copies are guarded replacements. No DLL, driver, API or device executes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

SOURCE_SHA256 = 'ad0e619e90e35e84b468ddcd5cfd9c0e3c1b3b7eaa674776c91cb03bd6c9236d'
START, STOP = 0x402240, 0x402525
SWAP, SWAP_STOP = 0x40205c, 0x402084
STACK, BUFFER, EXIT = 0x20000000, 0x30000000, 0x40000000
BRANCHES = ((0x402240, 0x40226b), (0x4022a7, 0x402375), (0x40251d, STOP), (SWAP, SWAP_STOP))


def permitted_pc(address, size):
    return size > 0 and any(start <= address and address+size <= stop for start, stop in BRANCHES)


def permitted_write(address, size):
    return size > 0 and (STACK <= address and address+size <= STACK+0x10000
                        or address in (0x4046f0, 0x404720) and size == 4
                        or address == BUFFER+4 and size == 1)


def run(data, *, frame_format=0, identifier=0x7ea, payload=bytes(range(8)), timestamp=0x01020304):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source SoftUSB pin changed')
    if (type(frame_format) is not int or frame_format not in (0, 1)
            or type(identifier) is not int or not 0 <= identifier <= (0x7ff if frame_format == 0 else 0x1fffffff)
            or type(payload) is not bytes or len(payload) > 8
            or type(timestamp) is not int or not 0 <= timestamp <= 0xffffffff):
        raise ValueError('Invalid synthetic CAN receive event')
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
    count, optional = struct.unpack_from('<H', data, pe+6)[0], struct.unpack_from('<H', data, pe+20)[0]
    for index in range(count):
        entry = pe+24+optional+40*index
        rva, length, off = struct.unpack_from('<III', data, entry+12)
        if length:
            uc.mem_write(base+rva, data[off:off+length])
    for address, size in ((STACK, 0x10000), (BUFFER, 0x1000), (EXIT, 0x1000)):
        uc.mem_map(address, size)
    uc.mem_write(0x4046f0, struct.pack('<IHH', identifier, len(payload), 0))
    uc.mem_write(0x404700, payload+bytes(8-len(payload)))
    uc.mem_write(0x404720, struct.pack('<I', timestamp))
    uc.mem_write(BUFFER, b'\xcc'*64)
    sp = STACK+0x8000
    uc.mem_write(sp, struct.pack('<IIIII', EXIT, 7, BUFFER, 0x21a, 0))
    uc.reg_write(UC_X86_REG_ESP, sp)
    reads, copies, instructions = [], [], [0]
    def code(engine, pc, size, _):
        if pc in (0x40202c, 0x401218):
            current = engine.reg_read(UC_X86_REG_ESP)
            target = int.from_bytes(engine.mem_read(current, 4), 'little')
            if pc == 0x40202c:
                args = int.from_bytes(engine.mem_read(current+4, 4), 'little')
                if reads or target != 0x402252 or args != 0x4046f0:
                    raise ValueError('Unexpected synthetic CANPC event read')
                event = 1 if frame_format == 0 else 9
                reads.append({'event_code': event, 'synthetic': True})
                engine.reg_write(UC_X86_REG_EAX, event)
                engine.reg_write(UC_X86_REG_ESP, current+8)
            else:
                src, dst, length = (engine.reg_read(reg) for reg in (UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ECX))
                expected = ({0x4022e1: (0x404720, BUFFER, 4), 0x4022f3: (0x4046f2, BUFFER+5, 2),
                             0x402305: (0x404700, BUFFER+7, 8)} if frame_format == 0 else
                            {0x402348: (0x404720, BUFFER, 4), 0x40235a: (0x4046f0, BUFFER+5, 4),
                             0x40236c: (0x404700, BUFFER+9, 8)})
                if expected.get(target) != (src, dst, length):
                    raise ValueError('Unexpected synthetic receive copy')
                engine.mem_write(dst, bytes(engine.mem_read(src, length)))
                copies.append(dict(return_address=hex(target), length=length))
                engine.reg_write(UC_X86_REG_ESP, current+4)
            engine.reg_write(UC_X86_REG_EIP, target)
            return
        if not permitted_pc(pc, size):
            raise ValueError(f'Unexpected SoftUSB receive PC {pc:#x}+{size}')
        instructions[0] += 1
    def write(engine, access, address, size, value, _):
        if not permitted_write(address, size):
            raise ValueError(f'Unexpected SoftUSB receive write {address:#x}+{size}')
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, EXIT, count=1000)
    if (uc.reg_read(UC_X86_REG_EIP) != EXIT or uc.reg_read(UC_X86_REG_ESP) != sp+20
            or len(reads) != 1 or len(copies) != 3):
        raise ValueError('Receive conversion did not return through declared boundary')
    length = uc.reg_read(UC_X86_REG_EAX) & 0xffff
    if length != len(payload)+(7 if frame_format == 0 else 9):
        raise ValueError('Unexpected native receive length')
    return {'context': dict(frame_format=frame_format, identifier=identifier, payload_hex=payload.hex(), timestamp=timestamp),
            'reported_length': length, 'host_buffer_hex': bytes(uc.mem_read(BUFFER, length)).hex(),
            'event_reads': reads, 'synthetic_copies': copies, 'instruction_observations': instructions[0],
            'export_entry_and_dispatch_executed': True, 'hardware_event_production_proven': False,
            'actual_driver_loaded_in_pccs': None, 'transport_used': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def audit(data):
    contexts = ({}, {'frame_format': 1, 'identifier': 0x18eff903},
                {'identifier': 0}, {'frame_format': 1, 'identifier': 0x1fffffff},
                {'payload': b''}, {'frame_format': 1, 'identifier': 0x18eff903, 'payload': b'\x35\x00'})
    cases = [run(data, **context) for context in contexts]
    from inspect_pccs_methods import executable_sections
    ranges = []
    for start, stop in (*BRANCHES, (0x40226b, 0x4022a7)):
        section = next(s for s in executable_sections(data) if s['va'] <= start and stop <= s['va']+s['raw_bytes'])
        off = section['raw_offset']+start-section['va']
        ranges.append(dict(start=hex(start), exclusive_end=hex(stop), file_offset=off,
                           sha256=hashlib.sha256(data[off:off+stop-start]).hexdigest()))
    return {'schema': 'pccs-bundled-softusb-receive-conversion-v1', 'source_sha256': SOURCE_SHA256,
            'source_ranges': ranges, 'cases': cases,
            'limitations': ['Bundled DLL identity only; runtime PCCS driver choice is unknown.',
                            'Synthetic CANPC events; no hardware or actual event delivery.',
                            'Guarded byte-copy replacements; native event dispatch and byte order execute.',
                            'No actual filter installation, AL5 response, programming or recovery qualification.'],
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dll', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Output exists; refusing overwrite')
    result = audit(args.dll.read_bytes())
    result['source_path'] = str(args.dll.resolve())
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print(json.dumps({'cases': len(result['cases']), 'ready_to_flash': False}))


if __name__ == '__main__':
    main()
