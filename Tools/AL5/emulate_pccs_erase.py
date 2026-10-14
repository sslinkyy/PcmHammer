"""Pinned PCCS helper emulation with fake responses; no host/vehicle API calls.

Requires Unicorn 2.1.4. Only the declared helper, a no-op string cleanup stub,
and an in-memory dispatch stub may execute. Internal request buffers are not
qualified CAN or VPW frames. This does not implement an AL5 writer.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from inspect_pccs_methods import executable_sections

SOURCE_SHA256 = '13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d'
THIS, STACK, VTABLE = 0x10000000, 0x20000000, 0x30000000
SEND, EXIT = VTABLE+0x1000, VTABLE+0x2000


def run(data, block=3, lct=True, statuses=(0,), state=0, selector=0,
        suppressed=False, response_byte=0):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
    from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EDX,
                                   UC_X86_REG_ECX, UC_X86_REG_ESP)
    sections = executable_sections(data)
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+24+28)[0]
    image_size = struct.unpack_from('<I', data, pe+24+56)[0]
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(0, 0x1000)  # synthetic FS exception-list storage
    uc.mem_map(base, (image_size+0xfff) & ~0xfff)
    for section in sections:
        off = section['raw_offset']
        uc.mem_write(section['va'], data[off:off+section['raw_bytes']])
    uc.mem_map(THIS, 0x80000)
    uc.mem_map(STACK, 0x20000)
    uc.mem_map(VTABLE, 0x3000)
    uc.mem_write(THIS, struct.pack('<I', VTABLE))
    uc.mem_write(VTABLE, struct.pack('<I', SEND))
    uc.mem_write(SEND, b'\xc2\x08\x00')  # fake dispatcher returns, popping two arguments
    uc.mem_write(0x4084c8, b'\xc3')  # only string cleanup is replaced by a no-op
    uc.mem_write(0x81d138, b'\0')  # logging disabled in this modeled context
    target = 3
    uc.mem_write(THIS+target*0xa4+0x80, bytes([int(lct)]))
    uc.mem_write(THIS+target*0xa4+0xb6, bytes([state]))
    uc.mem_write(THIS+0x72d64, bytes([selector]))
    uc.mem_write(THIS+0x72d90, bytes([int(suppressed)]))
    uc.reg_write(UC_X86_REG_EAX, THIS)
    uc.reg_write(UC_X86_REG_EDX, block)
    uc.reg_write(UC_X86_REG_ECX, target)
    uc.reg_write(UC_X86_REG_ESP, STACK+0x10000)
    uc.mem_write(STACK+0x10000, struct.pack('<I', EXIT))
    calls, stopped = [], []

    def hook(engine, address, size, user):
        if address == EXIT:
            stopped.append(True)
            engine.emu_stop()
            return
        if address == SEND:
            if len(calls) >= len(statuses):
                raise ValueError('unexpected dispatch beyond supplied fake responses')
            length = struct.unpack('<I', engine.mem_read(THIS+0x52894, 4))[0]
            status = statuses[len(calls)]
            calls.append({'internal_buffer_hex': bytes(engine.mem_read(THIS+0x52250, length)).hex(' '),
                          'timeout_parameter': engine.reg_read(UC_X86_REG_ECX),
                          'dispatch_parameter': engine.reg_read(UC_X86_REG_EDX),
                          'stubbed_status': status})
            engine.mem_write(THIS+0x528a4, bytes([status]))
            engine.mem_write(THIS+0x52679, bytes([response_byte]))
            return
        if address != 0x4084c8 and not 0x5b5410 <= address <= 0x5b5697:
            raise ValueError(f'unexpected execution address {address:#x}')

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(0x5b5410, EXIT+1, count=10000)
    if not stopped:
        raise ValueError('bounded helper did not return')
    return {'inputs': {'block': block, 'lct_flag': lct, 'state': state,
                       'selector': selector, 'suppressed': suppressed,
                       'stubbed_statuses': list(statuses), 'response_byte': response_byte},
            'calls': calls, 'final_status': bytes(uc.mem_read(THIS+0x528a4, 1))[0],
            'scope': 'native helper with fake dispatch; not qualified vehicle frames',
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def audit(data):
    scenarios = [dict(), dict(statuses=(2, 0)), dict(statuses=(1,)),
                 dict(state=5, selector=0), dict(state=5, selector=1),
                 dict(state=5, selector=2), dict(state=6), dict(state=13),
                 dict(suppressed=True, statuses=()), dict(response_byte=1),
                 dict(state=5, statuses=(2, 0)), dict(statuses=(2, 2)),
                 dict(lct=False, block=1), dict(lct=False, block=4)]
    cases = [run(data, **scenario) for scenario in scenarios]
    if cases[0]['calls'][0]['internal_buffer_hex'] != '12 03':
        raise ValueError('base buffer differs from observed fixture')
    if [c['internal_buffer_hex'] for c in cases[10]['calls']] != ['12 03 b0', '12 03']:
        raise ValueError('extended-to-simple retry differs')
    if len(cases[11]['calls']) != 2 or cases[11]['final_status'] != 2:
        raise ValueError('second failure unexpectedly retried or hidden')
    if cases[8]['calls'] or cases[9]['final_status'] != 4:
        raise ValueError('suppression/response-status branch differs')
    if [c['calls'][0]['timeout_parameter'] for c in cases[6:8]] != [60000, 60000]:
        raise ValueError('long timeout branch differs')
    if [c['calls'][0]['internal_buffer_hex'] for c in cases[3:6]] != ['12 03 b0', '12 03 bf', '12 03 ac']:
        raise ValueError('selector-dependent buffer differs')
    if cases[1]['final_status'] != 0 or cases[2]['final_status'] != 1:
        raise ValueError('base fallback/failure status differs')
    if [c['calls'][0]['internal_buffer_hex'] for c in cases[12:14]] != ['14', '13']:
        raise ValueError('non-LCT branch differs')
    return {'source_sha256': SOURCE_SHA256, 'helper_address': '0x5b5410',
            'transport': 'in-memory dispatch stub only', 'windows_apis_executed': False,
            'cases': cases, 'live_write_enabled': False, 'ready_to_flash': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('exe', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.exe.resolve() == args.output.resolve():
        parser.error('output must not overwrite source')
    result = audit(args.exe.read_bytes())
    result['source_path'] = str(args.exe.resolve())
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'cases': len(result['cases']), 'ready_to_flash': False}))
