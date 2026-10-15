"""Pinned PCCS general RP1210 connect and initial pass-filter request, offline.

Two native phases with an explicit handoff. Connect, SendCommand and string
conversion are guarded synthetic callbacks. No library is loaded or called.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

CONNECT_START, CONNECT_STOP = 0x5d4ab7, 0x5d4ae0
FILTER_START, FILTER_STOP, REJECT = 0x5d4c59, 0x5d4c9a, 0x5d4ef1
THIS, STACK, AUX = 0x10000000, 0x20000000, 0x30000000
CONNECT, COMMAND = AUX+0x100, AUX+0x200


def permitted_pc(phase, address, size):
    start, stop = {'connect': (CONNECT_START, CONNECT_STOP),
                   'filter': (FILTER_START, FILTER_STOP)}.get(phase, (0, 0))
    return size > 0 and start <= address and address+size <= stop


def permitted_write(phase, address, size):
    return size > 0 and (STACK <= address and address+size <= STACK+0x10000
                        or phase == 'connect' and address == THIS+0x2c and size == 2
                        or phase == 'filter' and address in (THIS+0x2e, THIS+0x528a4) and size == 1)


def run(data, *, protocol='CAN', device=1, client_result=1, command_result=0):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if (type(protocol) is not str or protocol not in ('CAN', 'CAN:Baud=250', 'IESCAN')
            or type(device) is not int or not 0 <= device <= 65535
            or any(type(v) is not int or not -32768 <= v <= 32767 for v in (client_result, command_result))):
        raise ValueError('Invalid synthetic RP1210 connection context')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX
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
    put(THIS+4, CONNECT)
    put(THIS+0x10, COMMAND)
    uc.mem_write(AUX+0x300, protocol.encode('ascii')+b'\x00')
    uc.mem_write(THIS+0x528a4, b'\x0c')
    bp, sp = STACK+0x8000, STACK+0x7000
    put(bp-0x14, THIS)
    put(bp+0x14, device)
    uc.reg_write(UC_X86_REG_EBP, bp)
    uc.reg_write(UC_X86_REG_ESP, sp)
    phase, calls, counts, conversions, stops = ['connect'], [], {'connect': 0, 'filter': 0}, [], []
    def finish_callback(engine, return_address, argument_bytes, result):
        current = engine.reg_read(UC_X86_REG_ESP)
        engine.reg_write(UC_X86_REG_EAX, result & 0xffffffff)
        engine.reg_write(UC_X86_REG_ESP, current+4+argument_bytes)
        engine.reg_write(UC_X86_REG_EIP, return_address)
    def code(engine, pc, size, _):
        if phase[0] == 'filter' and pc in (FILTER_STOP, REJECT):
            stops.append(pc)
            engine.emu_stop()
            return
        if pc in (0x407a70, CONNECT, COMMAND):
            current = engine.reg_read(UC_X86_REG_ESP)
            target = struct.unpack('<I', engine.mem_read(current, 4))[0]
            if pc == 0x407a70:
                if phase[0] != 'connect' or target != 0x5d4acb or conversions or engine.reg_read(UC_X86_REG_EAX) != bp-8:
                    raise ValueError('Unexpected synthetic protocol conversion')
                conversions.append('caller_supplied_protocol_string')
                finish_callback(engine, target, 0, AUX+0x300)
            elif pc == CONNECT:
                args = struct.unpack('<6I', engine.mem_read(current+4, 24))
                if phase[0] != 'connect' or calls or target != 0x5d4ad9 or args != (0, device, AUX+0x300, 0x8000, 0x8000, 0):
                    raise ValueError('Unexpected synthetic RP1210_ClientConnect')
                calls.append({'name': 'synthetic_ClientConnect', 'protocol': protocol,
                              'device': device, 'tx_buffer': args[3], 'rx_buffer': args[4],
                              'packetizing': args[5], 'return_value': client_result})
                finish_callback(engine, target, 24, client_result)
            else:
                args = struct.unpack('<4I', engine.mem_read(current+4, 16))
                if (phase[0] != 'filter' or len(calls) != 1 or target != FILTER_STOP
                        or args != (3, client_result, bp-0x1d, 0)):
                    raise ValueError('Unexpected synthetic RP1210_SendCommand')
                calls.append({'name': 'synthetic_SendCommand', 'command': 3,
                              'connection': args[1], 'length': 0, 'return_value': command_result})
                finish_callback(engine, target, 16, command_result)
            return
        if not permitted_pc(phase[0], pc, size):
            raise ValueError(f'Unexpected RP1210 {phase[0]} PC {pc:#x}+{size}')
        counts[phase[0]] += 1
    def write(engine, access, address, size, value, _):
        if not permitted_write(phase[0], address, size):
            raise ValueError(f'Unexpected RP1210 {phase[0]} write {address:#x}+{size}')
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(CONNECT_START, CONNECT_STOP, count=200)
    if uc.reg_read(UC_X86_REG_EIP) != CONNECT_STOP or uc.reg_read(UC_X86_REG_ESP) != sp or len(calls) != 1:
        raise ValueError('Connect phase did not reach declared boundary')
    phase[0] = 'filter'
    uc.emu_start(FILTER_START, 0, count=200)
    if len(stops) != 1 or uc.reg_read(UC_X86_REG_ESP) != sp:
        raise ValueError('Filter phase did not reach declared boundary')
    return {'context': dict(protocol=protocol, device=device, client_result=client_result, command_result=command_result),
            'boundary': 'pass_filter_command_returned' if stops[0] == FILTER_STOP else 'client_rejected',
            'calls': calls, 'client_word': int.from_bytes(uc.mem_read(THIS+0x2c, 2), 'little'),
            'connected_byte': uc.mem_read(THIS+0x2e, 1)[0], 'host_status': uc.mem_read(THIS+0x528a4, 1)[0],
            'instruction_observations': counts, 'independent_phase_handoff': True,
            'protocol_selection_executed': False, 'driver_callbacks_synthetic': True,
            'filter_installation_proven': False, 'transport_used': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def audit(data):
    contexts = ({}, {'client_result': 0}, {'client_result': 127}, {'client_result': 128},
                {'client_result': -1}, {'command_result': 9}, {'protocol': 'CAN:Baud=250'}, {'protocol': 'IESCAN'})
    ranges = []
    for start, stop in ((CONNECT_START, CONNECT_STOP), (FILTER_START, FILTER_STOP)):
        section = next(s for s in executable_sections(data) if s['va'] <= start and stop <= s['va']+s['raw_bytes'])
        off = section['raw_offset']+start-section['va']
        ranges.append(dict(start=hex(start), exclusive_end=hex(stop), file_offset=off,
                           sha256=hashlib.sha256(data[off:off+stop-start]).hexdigest()))
    return {'schema': 'pccs-rp1210-connect-pass-filter-phases-v1', 'source_sha256': SOURCE_SHA256,
            'source_ranges': ranges, 'cases': [run(data, **c) for c in contexts],
            'limitations': ['General connect-call phase and common success phase are explicitly joined.',
                            'Protocol string selection, loader, retries and full initialization are excluded.',
                            'All runtime/driver callbacks synthetic; no actual filter installation.',
                            'No AL5 mixed-format, programming or recovery qualification.'],
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
