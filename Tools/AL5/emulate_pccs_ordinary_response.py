"""Pinned PCCS post-driver ordinary response validation; isolated native slices.

Received bytes and routing globals are synthetic. Driver receive, request
sending and complete dispatcher entry do not run. Buffer copies are guarded
replacements; the native 32-bit byte-order helper executes directly.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

START, STOP = 0x5afbc7, 0x5b0233
SWAP_START, SWAP_STOP = 0x5adbfc, 0x5adc28
THIS, STACK = 0x10000000, 0x20000000
BOUNDARIES = {STOP: 'prefix_accepted', 0x5b05b6: 'prefix_not_matched',
              0x5b05c8: 'unusable_length', 0x5b05ea: 'frame_or_length_not_selected'}


def permitted_pc(address, size):
    return size > 0 and (START <= address and address+size <= STOP
                         or SWAP_START <= address and address+size <= SWAP_STOP)


def permitted_write(address, size):
    return size > 0 and (STACK <= address and address+size <= STACK+0x10000
                         or address == THIS+0x5288c and size == 4
                         or address == THIS+0x528a4 and size == 1)


def run(data, *, payload=b'\x35\x00', frame_format=1, received_id=0x18eff903,
        stale_identifier=0xaa, classify_zero=False):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if (type(payload) is not bytes or type(frame_format) is not int or not 0 <= frame_format <= 255
            or type(received_id) is not int or not 0 <= received_id <= 0xffffffff
            or type(stale_identifier) is not int or not 0 <= stale_identifier <= 255
            or type(classify_zero) is not bool):
        raise ValueError('Invalid synthetic ordinary response')
    header_bytes = 9 if frame_format == 1 else 7
    if len(payload) > 0x21a-header_bytes:
        raise ValueError('Synthetic received buffer exceeds native receive capacity')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ECX, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP
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
    uc.mem_write(THIS+0x52250, b'\x35')
    uc.mem_write(THIS+0x5289c, struct.pack('<I', 1))
    uc.mem_write(THIS+0x528a0, struct.pack('<I', 2))
    uc.mem_write(THIS+0x528a4, b'\x01')
    uc.mem_write(THIS+0x52679, bytes([stale_identifier]))
    uc.mem_write(THIS+0x72d90, b'\x01\x01\x01')
    uc.mem_write(THIS+0x52898, struct.pack('<H', header_bytes+len(payload)))
    uc.mem_write(THIS+0x528b4, bytes([frame_format]))
    if frame_format == 1:
        uc.mem_write(THIS+0x528b5, received_id.to_bytes(4, 'big'))
        payload_source = THIS+0x528b9
    else:
        uc.mem_write(THIS+0x528b5, (received_id & 0xffff).to_bytes(2, 'big'))
        payload_source = THIS+0x528b7
    if payload:
        uc.mem_write(payload_source, payload)
    uc.mem_write(0x81d108, b'\x00')
    uc.mem_write(0x81d138, b'\x00')
    uc.mem_write(0x81d0fc, b'\xf9')
    bp, sp = STACK+0x8000, STACK+0x7000
    uc.mem_write(bp-8, struct.pack('<I', THIS))
    uc.mem_write(bp+8, b'\x03')
    uc.reg_write(UC_X86_REG_EBP, bp)
    uc.reg_write(UC_X86_REG_ESP, sp)
    copies, stops, count, phase = [], [], [0], ['receive']
    classification_stops = []

    def code(engine, address, size, _):
        if phase[0] == 'classification':
            if address in (0x5da6f2, 0x5da8a3):
                classification_stops.append(address)
                engine.emu_stop()
                return
            if address == 0x407208:
                current = engine.reg_read(UC_X86_REG_ESP)
                target = struct.unpack('<I', engine.mem_read(current, 4))[0]
                if (target != 0x5da6dd or engine.reg_read(UC_X86_REG_EAX) != THIS+3*0xa4+0x44
                        or engine.reg_read(UC_X86_REG_EDX) != 0x5dc168):
                    raise ValueError('Unexpected synthetic classification string assignment')
                engine.reg_write(UC_X86_REG_ESP, current+4)
                engine.reg_write(UC_X86_REG_EIP, target)
                return
            if not (size > 0 and 0x5da13b <= address and address+size <= 0x5da6f2):
                raise ValueError('Unexpected zero-response classification PC')
            count[0] += 1
            return
        if address in BOUNDARIES:
            stops.append(BOUNDARIES[address])
            engine.emu_stop()
            return
        if address == 0x404820:
            current = engine.reg_read(UC_X86_REG_ESP)
            target = struct.unpack('<I', engine.mem_read(current, 4))[0]
            src, dst, length = (engine.reg_read(reg) for reg in (UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ECX))
            allowed = ((target == 0x5afe9d and src == THIS+0x528b5 and dst == THIS+0x5288c and length == 4)
                       or (target in (0x5b001f, 0x5b0039) and src == payload_source
                           and dst == THIS+0x52678 and length == len(payload) and length > 0))
            if not allowed:
                raise ValueError('Unexpected synthetic response copy context')
            engine.mem_write(dst, bytes(engine.mem_read(src, length)))
            copies.append({'kind': 'synthetic_buffer_copy', 'source_offset': src-THIS,
                           'destination_offset': dst-THIS, 'length': length})
            engine.reg_write(UC_X86_REG_ESP, current+4)
            engine.reg_write(UC_X86_REG_EIP, target)
            return
        if not permitted_pc(address, size):
            raise ValueError(f'Unexpected ordinary response PC {address:#x}+{size}')
        count[0] += 1

    def write(engine, access, address, size, value, _):
        if phase[0] == 'classification':
            permitted = size > 0 and (STACK <= address and address+size <= STACK+0x10000
                         or size == 1 and address in (0x81d14c, THIS+3*0xa4+0x80, THIS+3*0xa4+0xb6))
            if not permitted:
                raise ValueError('Unexpected zero-response classification write')
            return
        if not permitted_write(address, size):
            raise ValueError(f'Unexpected ordinary response write {address:#x}+{size}')

    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, 0, count=10000)
    if (uc.reg_read(UC_X86_REG_EIP) not in BOUNDARIES or len(stops) != 1
            or uc.reg_read(UC_X86_REG_ESP) != sp):
        raise ValueError('Ordinary response did not reach declared boundary with balanced calls')
    classification = None
    if classify_zero:
        if stops[0] != 'prefix_accepted' or uc.mem_read(THIS+0x52679, 1)[0] != 0:
            raise ValueError('Classification phase requires an accepted zero identifier')
        phase[0] = 'classification'
        uc.mem_write(bp-0x108, struct.pack('<II', 3, THIS))
        uc.mem_write(0x81d138, b'\x00')
        uc.emu_start(0x5da13b, 0, count=1000)
        if (classification_stops != [0x5da6f2] or uc.reg_read(UC_X86_REG_ESP) != sp):
            raise ValueError('Zero-response classification did not reach declared boundary')
        classification = {'family': uc.mem_read(THIS+3*0xa4+0x80, 1)[0],
                          'version': uc.mem_read(THIS+3*0xa4+0xb6, 1)[0],
                          'alternate': uc.mem_read(THIS+0x72d90, 1)[0],
                          'independent_phase_handoff': True,
                          'string_assignment_synthetic': True, 'full_caller_executed': False}
    copied_payload = any(c['destination_offset'] == 0x52678 for c in copies)
    return {'context': {'payload_hex': payload.hex(), 'frame_format': frame_format,
                        'received_id': received_id, 'stale_identifier': stale_identifier,
                        'classify_zero': classify_zero, 'target': 3, 'source_f9': 0xf9, 'ccp_control': 0, 'prior_alternate': 1},
            'boundary': stops[0], 'final_host_status': uc.mem_read(THIS+0x528a4, 1)[0],
            'response_identifier': uc.mem_read(THIS+0x52679, 1)[0],
            'identifier_from_current_payload': copied_payload and len(payload) >= 2,
            'final_alternate': uc.mem_read(THIS+0x72d90, 1)[0],
            'classification': classification, 'copies': copies, 'instruction_observations': count[0],
            'driver_receive_executed': False, 'full_dispatcher_executed': False,
            'transport_used': False, 'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def audit(data):
    contexts = [{'classify_zero': True}, {'payload': b'\x35\x01'}, {'payload': b'\x35\xff'},
                {'payload': b'\x35', 'stale_identifier': 0}, {'payload': b'\x35'},
                {'payload': b'\x35\x00\x00'}, {'payload': b''}, {'payload': b'\x36\x00'},
                {'received_id': 0x18eff904}, {'frame_format': 0}, {'frame_format': 2},
                {'payload': b'\x35'+bytes(144)}]
    cases = [run(data, **context) for context in contexts]
    ranges = []
    for name, (start, stop) in [('receive_gate', (START, STOP)), ('native_byte_order', (SWAP_START, SWAP_STOP)), ('zero_response_classification', (0x5da13b, 0x5da6f2))]:
        section = next(s for s in executable_sections(data)
                       if s['va'] <= start and stop <= s['va']+s['raw_bytes'])
        offset = section['raw_offset']+start-section['va']
        ranges.append({'name': name, 'start': hex(start), 'exclusive_end': hex(stop), 'file_offset': offset,
                       'sha256': hashlib.sha256(data[offset:offset+stop-start]).hexdigest()})
    return {'schema': 'pccs-ordinary-post-driver-response-native-v1', 'source_sha256': SOURCE_SHA256,
            'source_ranges': ranges, 'cases': cases,
            'limitations': ['Post-driver receive gates only; driver and full dispatcher entry are excluded.',
                            'Received buffers/globals are synthetic; copies are guarded replacements.',
                            'No complete 11-bit initial-probe to ordinary response transition is established.',
                            'Optional zero-classification stage uses an explicit independent phase handoff, not full caller execution.',
                            'Host acceptance does not qualify actual AL5 wire behavior, programming or recovery.'],
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
