"""Pinned post-helper caller path through ordinary request dispatch boundary.

Runs no dispatcher or I/O. The post-helper state is synthetic, the UI is off,
and one identity-string assignment is replaced. Controller index is fixed at 3.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

START = 0x5d91a1
RANGES = ((START, 0x5d91cf), (0x5d9ba9, 0x5d9bc6),
          (0x5d9bdf, 0x5d9be9), (0x5d9c0c, 0x5d9c56),
          (0x5d9c9a, 0x5d9caa), (0x5d9f04, 0x5d9fb6))
BOUNDARIES = {0x5dc085: 'identified_or_other_exit', 0x5d9c24: 'ccp_helper_selected',
              0x5da13b: 'caller_flag_skips_request', 0x5d9f94: 'ordinary_dispatch',
              0x5d9fb4: 'ordinary_dispatch'}
THIS, STACK, AUX = 0x10000000, 0x20000000, 0x30000000


def permitted_pc(address, size):
    return size > 0 and any(start <= address and address+size <= stop for start, stop in RANGES)


def permitted_write(address, size):
    return size > 0 and (STACK <= address and address+size <= STACK+0x10000
                        or address == THIS+0x52250 and size == 1
                        or address in (THIS+0x52894, THIS+0x5289c, THIS+0x528a0) and size == 4
                        or address == THIS+0x528a4 and size == 1)


def run(data, *, helper_flag=0, identification_word=0, host_status=9, alternate=1,
        ccp=0, ccp_handle=-1, caller_flag=0, short_wait=0):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if (any(type(v) is not int or not 0 <= v <= 255
            for v in (helper_flag, host_status, alternate))
            or any(type(v) is not int or v not in (0, 1) for v in (ccp, caller_flag, short_wait))
            or type(identification_word) is not int or not 0 <= identification_word <= 65535
            or type(ccp_handle) is not int or not -1 <= ccp_handle <= 0x7fffffff):
        raise ValueError('Invalid post-helper request context')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ECX
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+24+28)[0]
    size = struct.unpack_from('<I', data, pe+24+56)[0]
    uc.mem_map(base, (size+0xfff)&~0xfff)
    for section in executable_sections(data):
        off = section['raw_offset']
        uc.mem_write(section['va'], data[off:off+section['raw_bytes']])
    for address, size in ((THIS, 0x75000), (STACK, 0x10000), (AUX, 0x1000)):
        uc.mem_map(address, size)
    def put(address, value):
        uc.mem_write(address, struct.pack('<I', value & 0xffffffff))
    put(THIS, AUX)
    put(AUX, 0x5aedc4)  # Source-bound VMT+0; stopped before the native indirect call.
    put(0x81eb44, AUX+0x100)
    put(0x81d0f4, 3)
    put(THIS+0x74890, ccp_handle)
    uc.mem_write(0x81d108, bytes([ccp]))
    uc.mem_write(0x81d118, bytes([helper_flag]))
    uc.mem_write(0x81d138, b'\x00')
    uc.mem_write(THIS+3*0xa4+0x84, struct.pack('<H', identification_word))
    uc.mem_write(THIS+0x528a4, bytes([host_status]))
    uc.mem_write(THIS+0x72d90, bytes([alternate]))
    for offset in (0x52894, 0x5289c, 0x528a0):
        put(THIS+offset, 0xffffffff)
    bp, sp = STACK+0x8000, STACK+0x7000
    put(bp-0x108, 3)
    put(bp-0x104, THIS)
    uc.mem_write(bp+8, bytes([caller_flag]))
    uc.mem_write(bp-0x115, bytes([short_wait]))
    uc.reg_write(UC_X86_REG_EBP, bp)
    uc.reg_write(UC_X86_REG_ESP, sp)
    stops, strings, count = [], [], [0]
    def code(engine, pc, size, _):
        if pc in BOUNDARIES:
            stops.append(pc)
            engine.emu_stop()
            return
        if pc == 0x407208:
            current = engine.reg_read(UC_X86_REG_ESP)
            target = struct.unpack('<I', engine.mem_read(current, 4))[0]
            if (strings or target != 0x5d9bc4 or engine.reg_read(UC_X86_REG_EAX) != THIS+3*0xa4+0x44
                    or engine.reg_read(UC_X86_REG_EDX) != 0x5dc43c):
                raise ValueError('Unexpected fallback identity assignment')
            strings.append('synthetic_identity_string_assignment')
            engine.reg_write(UC_X86_REG_ESP, current+4)
            engine.reg_write(UC_X86_REG_EIP, target)
            return
        if not permitted_pc(pc, size):
            raise ValueError(f'Unexpected fallback request PC {pc:#x}+{size}')
        count[0] += 1
    def write(engine, access, address, size, value, _):
        if not permitted_write(address, size):
            raise ValueError(f'Unexpected fallback request write {address:#x}+{size}')
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, 0, count=500)
    if len(stops) != 1:
        raise ValueError('Fallback request did not reach boundary')
    dispatch = None
    pending = 8 if BOUNDARIES[stops[0]] == 'ordinary_dispatch' else 0
    if uc.reg_read(UC_X86_REG_ESP) != sp-pending:
        raise ValueError('Unexpected stack at fallback boundary')
    if pending:
        dispatch = {'vmt_offset': 0, 'source_bound_target': '0x5aedc4',
                    'edx': uc.reg_read(UC_X86_REG_EDX), 'timeout_parameter': uc.reg_read(UC_X86_REG_ECX),
                    'pending_stack_arguments': list(struct.unpack('<II', uc.mem_read(sp-8, 8))),
                    'request_hex': uc.mem_read(THIS+0x52250, 1).hex(),
                    'request_length': struct.unpack('<I', uc.mem_read(THIS+0x52894, 4))[0],
                    'prefix_length': struct.unpack('<I', uc.mem_read(THIS+0x5289c, 4))[0],
                    'maximum_response_length': struct.unpack('<I', uc.mem_read(THIS+0x528a0, 4))[0]}
    return {'context': dict(helper_flag=helper_flag, identification_word=identification_word,
                            host_status=host_status, alternate=alternate, ccp=ccp,
                            ccp_handle=ccp_handle, caller_flag=caller_flag, short_wait=short_wait),
            'boundary': BOUNDARIES[stops[0]], 'boundary_pc': hex(stops[0]), 'dispatch': dispatch,
            'final_host_status': uc.mem_read(THIS+0x528a4, 1)[0],
            'final_alternate': uc.mem_read(THIS+0x72d90, 1)[0],
            'synthetic_calls': strings, 'instruction_observations': count[0],
            'continuous_caller_slice': True, 'helper_executed': False, 'dispatcher_executed': False,
            'transport_used': False, 'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def audit(data):
    contexts = ({}, {'short_wait': 1}, {'host_status': 255}, {'alternate': 0},
                {'alternate': 255}, {'helper_flag': 1}, {'identification_word': 1},
                {'caller_flag': 1}, {'ccp': 1, 'ccp_handle': 1}, {'ccp': 1})
    ranges = []
    for start, stop in RANGES:
        section = next(s for s in executable_sections(data) if s['va'] <= start and stop <= s['va']+s['raw_bytes'])
        off = section['raw_offset']+start-section['va']
        ranges.append(dict(start=hex(start), exclusive_end=hex(stop), file_offset=off,
                           sha256=hashlib.sha256(data[off:off+stop-start]).hexdigest()))
    return {'schema': 'pccs-fallback-to-request-boundary-v1', 'source_sha256': SOURCE_SHA256,
            'source_ranges': ranges, 'cases': [run(data, **c) for c in contexts],
            'limitations': ['Synthetic post-helper state, index 3, UI/logging off.',
                            'One guarded identity-string assignment replacement.',
                            'Stops before dispatcher or CCP helper call; no transport or full identification.',
                            'No AL5 response production, programming or recovery qualification.'],
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
