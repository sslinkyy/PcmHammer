"""Pinned initial E2 post-receive frame gate, service gate and identifier copy.

The receive buffer is synthetic. Stages share private memory but have explicit
register handoffs; they are not complete helper calls or a driver replay.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

FRAME_START, FRAME_STOP = 0x5ab6b9, 0x5ab792
SERVICE_START, ACCEPT, UNMATCHED, READ_AGAIN = 0x5acc3e, 0x5ad07c, 0x5accba, 0x5aca89
SETTER, SETTER_STOP = 0x5b0af8, 0x5b0aff
COPY_START, COPY_STOP = 0x5bba73, 0x5bba89
THIS, STACK = 0x10000000, 0x20000000


def permitted_pc(stage, address, size):
    if size <= 0:
        return False
    ranges = {'frame': ((FRAME_START, FRAME_STOP),),
              'service': ((SERVICE_START, UNMATCHED), (SETTER, SETTER_STOP)),
              'copy': ((COPY_START, COPY_STOP),)}
    return any(start <= address and address+size <= stop for start, stop in ranges.get(stage, ()))


def permitted_write(stage, address, size, index):
    if stage == 'frame':
        return address == THIS+0x5288c and size == 4 or address == THIS+0x72d93 and size == 1
    if stage == 'service':
        return (STACK <= address and address+size <= STACK+0x10000 and size > 0
                or address in (THIS+0x72d92, THIS+0x528a4) and size == 1)
    return stage == 'copy' and address == THIS+index*0xa4+0x84 and size == 2


def run(data, *, identifier=0, received_id=0x7ea, expected_id=0x7ea, length=16,
        format_byte=0, pci=2, service=0xe2, index=3, alternate=1):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if (any(type(v) is not int or not 0 <= v <= 255
            for v in (identifier, format_byte, pci, service, alternate))
            or any(type(v) is not int or not 0 <= v <= 0xffff for v in (received_id, expected_id))
            or type(length) is not int or not 0 <= length <= 0x7fff
            or type(index) is not int or not 0 <= index <= 6):
        raise ValueError('Invalid synthetic E2 receive context')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import (UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EBP,
                                  UC_X86_REG_ESP, UC_X86_REG_EIP)
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+24+28)[0]
    size = struct.unpack_from('<I', data, pe+24+56)[0]
    uc.mem_map(base, (size+0xfff)&~0xfff)
    for section in executable_sections(data):
        off = section['raw_offset']
        uc.mem_write(section['va'], data[off:off+section['raw_bytes']])
    uc.mem_map(THIS, 0x75000)
    uc.mem_map(STACK, 0x10000)
    def put(addr, value):
        uc.mem_write(addr, struct.pack('<I', value))
    put(THIS+0x7488c, expected_id)
    put(0x81d0f4, index)
    uc.mem_write(THIS+0x52898, struct.pack('<H', length))
    uc.mem_write(THIS+0x528b4, bytes([format_byte])+received_id.to_bytes(2, 'big')
                 +bytes([pci, service, identifier]))
    uc.mem_write(THIS+0x72d90, bytes([alternate]))
    uc.mem_write(THIS+0x528a4, b'\x01')
    uc.mem_write(THIS+index*0xa4+0x84, b'\xff\xff')
    bp, sp = STACK+0x8000, STACK+0x7000
    uc.mem_write(bp-1, b'\x00')  # Exact-match selector from initial probe's CL=0.
    uc.reg_write(UC_X86_REG_EBP, bp)
    uc.reg_write(UC_X86_REG_ESP, sp)
    uc.reg_write(UC_X86_REG_ESI, THIS)
    uc.reg_write(UC_X86_REG_EBX, 0)
    stage, counts, service_stops = ['frame'], {'frame': 0, 'service': 0, 'copy': 0}, []
    def code(engine, pc, size, _):
        if stage[0] == 'service' and pc in (ACCEPT, UNMATCHED, READ_AGAIN):
            service_stops.append(pc)
            engine.emu_stop()
            return
        if not permitted_pc(stage[0], pc, size):
            raise ValueError(f'Unexpected E2 {stage[0]} PC {pc:#x}+{size}')
        counts[stage[0]] += 1
    def write(engine, access, addr, size, value, _):
        if not permitted_write(stage[0], addr, size, index):
            raise ValueError(f'Unexpected E2 {stage[0]} write {addr:#x}+{size}')
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(FRAME_START, FRAME_STOP, count=1000)
    if uc.reg_read(UC_X86_REG_EIP) != FRAME_STOP:
        raise ValueError('Frame gate did not reach boundary')
    frame_accepted = bool(uc.reg_read(UC_X86_REG_EBX) & 255)
    accepted, producer_executed = False, False
    boundary = 'frame_not_admitted'
    if frame_accepted:
        stage[0] = 'service'
        put(bp-4, THIS)
        uc.mem_write(bp-5, b'\x00')
        uc.reg_write(UC_X86_REG_EBX, 0xe2)
        uc.emu_start(SERVICE_START, 0, count=1000)
        stop = uc.reg_read(UC_X86_REG_EIP)
        if len(service_stops) != 1 or stop not in (ACCEPT, UNMATCHED, READ_AGAIN):
            raise ValueError('E2 service gate did not reach boundary')
        boundary = {ACCEPT: 'positive_service_accepted', UNMATCHED: 'unmatched_service_handoff',
                    READ_AGAIN: 'read_again'}[stop]
        accepted = stop == ACCEPT and uc.mem_read(THIS+0x528a4, 1)[0] == 0
        if accepted:
            stage[0] = 'copy'
            uc.emu_start(COPY_START, COPY_STOP, count=100)
            if uc.reg_read(UC_X86_REG_EIP) != COPY_STOP:
                raise ValueError('E2 identifier copy did not reach boundary')
            producer_executed = True
    if uc.reg_read(UC_X86_REG_ESP) != sp:
        raise ValueError('E2 staged calls were not balanced')
    return {'context': {'identifier': identifier, 'received_id': received_id,
                        'expected_id': expected_id, 'reported_length': length,
                        'format_byte': format_byte, 'pci': pci, 'service': service,
                        'selected_index': index, 'alternate': alternate},
            'frame_admitted': frame_accepted, 'service_boundary': boundary,
            'positive_e2_accepted': accepted, 'identifier_copy_executed': producer_executed,
            'final_identifier_word': int.from_bytes(uc.mem_read(THIS+index*0xa4+0x84, 2), 'little'),
            'final_host_status': uc.mem_read(THIS+0x528a4, 1)[0],
            'final_alternate': uc.mem_read(THIS+0x72d90, 1)[0],
            'final_receive_id': int.from_bytes(uc.mem_read(THIS+0x5288c, 4), 'little'),
            'instruction_observations': counts, 'continuous_helper_execution': False,
            'driver_or_transport_executed': False, 'live_write_enabled': False,
            'ready_to_flash': False, 'would_send': []}


def audit(data):
    contexts = ({}, {'identifier': 1}, {'identifier': 255}, {'received_id': 0x7eb},
                {'received_id': 0x5ea}, {'length': 8}, {'length': 9}, {'length': 127},
                {'length': 128}, {'format_byte': 1}, {'pci': 0x12}, {'service': 0xe3},
                {'pci': 0}, {'pci': 15})
    ranges = []
    for start, stop in ((FRAME_START, FRAME_STOP), (SERVICE_START, UNMATCHED),
                        (SETTER, SETTER_STOP), (COPY_START, COPY_STOP)):
        section = next(s for s in executable_sections(data)
                       if s['va'] <= start and stop <= s['va']+s['raw_bytes'])
        off = section['raw_offset']+start-section['va']
        ranges.append({'start': hex(start), 'exclusive_end': hex(stop), 'file_offset': off,
                       'sha256': hashlib.sha256(data[off:off+stop-start]).hexdigest()})
    return {'schema': 'pccs-initial-e2-staged-receive-validation-v1', 'source_sha256': SOURCE_SHA256,
            'source_ranges': ranges, 'cases': [run(data, **c) for c in contexts],
            'limitations': ['Synthetic post-driver object fields; no physical receive or frame decoding.',
                            'Frame/service/copy stages use explicit register handoffs, not complete calls.',
                            'Only the initial selector-zero format-zero path is positively modeled.',
                            'Negative-response parsing, retries, timeout logic and other receive formats are excluded.',
                            'No proof an AL5 or adapter produces these fields or that a complete flash/recovery works.'],
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
