"""Execute a pinned PCCS explicit-length file-loop slice with synthetic callbacks.

No complete helper, stream, transport, controller, or recovery is emulated.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

ROUND = 0x404b98
START, END, STOP = 0x75951b, 0x7597d2, 0x759d33
STACK, STATE, STUBS = 0x20000000, 0x30000000, 0x40000000
SEEK, READ, SIZE = STUBS, STUBS+0x10, STUBS+0x20
CALLBACKS = {SEEK: 0, READ: 0, SIZE: 0, 0x442490: 0, 0x564fa4: 0,
             0x56853c: 0, 0x404b98: 0, 0x5b3a44: 0, 0x5b10bc: 12,
             0x5b3be0: 8, 0x5b3b90: 0, 0x5b0af0: 0}
BUFFER = 0x9bf2fc


def permitted_pc(address, size):
    return size > 0 and (START <= address and address+size <= END or
                        address == ROUND and size == 2 or address == ROUND+2 and size == 1 or
                        address in CALLBACKS and address != ROUND and size == (3 if CALLBACKS[address] else 1))


def permitted_write(address, size, chunk_size):
    return size > 0 and (STACK <= address and address+size <= STACK+0x10000 or
                        address in (STATE+0xf7, STATE+0x600) and size == 1 or
                        BUFFER <= address and address+size <= BUFFER+chunk_size)


def run(data, *, interpreter=4, payload=bytes(range(10)), chunk_size=4,
        address=0x10000, fixed_address=False, failure_at=None, final_flag=1, cancel=False):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if interpreter not in (3, 4) or not isinstance(payload, bytes) or not 1 <= len(payload) <= 256:
        raise ValueError('Requires interpreter 3/4 and 1..256 synthetic bytes')
    if not 1 <= chunk_size <= 256 or not 0 <= address <= 0xffffffff-len(payload)-chunk_size:
        raise ValueError('Invalid bounded chunk/address context')
    if failure_at is not None and (type(failure_at) is not int or not 1 <= failure_at <= (len(payload)+chunk_size-1)//chunk_size):
        raise ValueError('Invalid synthetic failure ordinal')
    if type(fixed_address) is not bool or type(cancel) is not bool or final_flag not in (0, 1):
        raise ValueError('Invalid synthetic flags')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+24+28)[0]
    image_size = struct.unpack_from('<I', data, pe+24+56)[0]
    uc.mem_map(base, (image_size+0xfff)&~0xfff)
    for section in executable_sections(data):
        off = section['raw_offset']
        uc.mem_write(section['va'], data[off:off+section['raw_bytes']])
    for start, size in ((STACK, 0x10000), (STATE, 0x1000), (STUBS, 0x1000)):
        uc.mem_map(start, size)
    for target, cleanup in CALLBACKS.items():
        uc.mem_write(target, b'\xc2'+struct.pack('<H', cleanup) if cleanup else b'\xc3')
    # The synthetic Delphi Round replacement consumes its x87 input and returns
    # synthetic integer progress; no native numerical rounding is claimed.
    uc.mem_write(ROUND, bytes.fromhex('ddd8c3'))  # FSTP ST(0); RET
    closure, array, stream, vtable = STATE+0x100, STATE+0x200, STATE+0x300, STATE+0x400
    def put(addr, value):
        uc.mem_write(addr, struct.pack('<I', value))
    put(closure-8, array)
    put(array, stream)
    put(stream, vtable)
    put(vtable, SIZE)
    put(vtable+0xc, READ)
    put(vtable+0x14, SEEK)
    put(closure-0x10, STATE+0x500)
    put(closure-0x14, 0)
    put(closure-0x18, len(payload))
    put(closure-0x1c, chunk_size)
    put(closure+0xc, STATE+0x600)
    put(0x81f328, STATE+0x700)
    put(STATE+0x700, STATE+0x710)
    put(0x81f0c8, STATE+0x720)
    put(STATE+0x720, STATE+0x730)
    uc.mem_write(0x9d2dee, struct.pack('<H', interpreter))
    bp = STACK+0x8000
    put(bp+0x10, closure)
    put(bp+8, 0)  # The alternate selector==3 helper is outside this model.
    put(bp+0xc, final_flag)
    put(bp-8, address)
    uc.mem_write(bp-9, bytes([int(fixed_address)]))
    put(bp-0x10, address)
    uc.reg_write(UC_X86_REG_EBP, bp)
    uc.reg_write(UC_X86_REG_ESP, bp-0x100)
    uc.reg_write(UC_X86_REG_ESI, 0)
    position = [0]
    calls, transfers = [], []
    status = [0]
    count = [0]
    def reg(r):
        return uc.reg_read(r)
    def code(engine, pc, size, _):
        if not permitted_pc(pc, size):
            raise ValueError(f'Unexpected native PC {pc:#x}+{size}')
        count[0] += 1
        if pc not in CALLBACKS:
            return
        eax, edx, ecx = reg(UC_X86_REG_EAX), reg(UC_X86_REG_EDX), reg(UC_X86_REG_ECX)
        if pc in (SEEK, READ, SIZE, 0x442490) and eax != stream:
            raise ValueError('Unexpected synthetic stream identity')
        if pc == SEEK:
            if edx != 0 or ecx != 0:
                raise ValueError('Only offset-zero synthetic seek is modeled')
            position[0] = 0
        elif pc == READ:
            if edx != BUFFER or not 1 <= ecx <= chunk_size or position[0]+ecx > len(payload):
                raise ValueError('Synthetic read escaped source/destination bounds')
            engine.mem_write(BUFFER, payload[position[0]:position[0]+ecx])
            position[0] += ecx
            engine.reg_write(UC_X86_REG_EAX, ecx)
        elif pc in (SIZE, 0x442490):
            engine.reg_write(UC_X86_REG_EAX, len(payload) if pc == SIZE else position[0])
            engine.reg_write(UC_X86_REG_EDX, 0)
        elif pc == 0x5b10bc:
            sp = reg(UC_X86_REG_ESP)
            counter, flag, length = struct.unpack('<III', engine.mem_read(sp+4, 12))
            if edx != BUFFER or not 1 <= length <= chunk_size:
                raise ValueError('Synthetic transfer escaped bounded buffer')
            transfers.append({'counter': counter, 'flag': flag, 'length': length,
                              'address': ecx, 'payload_hex': bytes(engine.mem_read(BUFFER, length)).hex()})
            status[0] = int(failure_at == len(transfers))
        elif pc == 0x564fa4 and cancel:
            engine.mem_write(STATE+0x600, b'\x01')
        elif pc == 0x5b0af0:
            engine.reg_write(UC_X86_REG_EAX, status[0])
        elif pc == 0x404b98:
            # FSTP ST(0) executes in the replacement to consume the input.
            engine.reg_write(UC_X86_REG_EAX, 0)
        elif pc == 0x5b3a44:
            calls.append({'helper': 'synthetic_download', 'address': edx, 'length': ecx})
        elif pc == 0x5b3b90:
            calls.append({'helper': 'synthetic_exit'})
        elif pc == 0x5b3be0:
            raise ValueError('Alternate transfer selector outside model')
    def write(engine, access, addr, size, value, _):
        if not permitted_write(addr, size, chunk_size):
            raise ValueError(f'Unexpected native write {addr:#x}+{size}')
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, STOP, count=200000)
    if reg(UC_X86_REG_EIP) != STOP or reg(UC_X86_REG_ESP) != bp-0x100:
        raise ValueError('Native slice did not reach its pre-cleanup boundary with balanced calls')
    return {'context': {'interpreter': interpreter, 'payload_hex': payload.hex(),
                        'chunk_size': chunk_size, 'fixed_address': fixed_address,
                        'initial_address': address, 'failure_at': failure_at, 'final_flag': final_flag, 'cancel': cancel},
            'transfers': transfers, 'calls': calls, 'final_status': status[0],
            'done_byte': engine_byte(uc, closure-9),
            'final_address': struct.unpack('<I', uc.mem_read(bp-0x10, 4))[0],
            'instructions': count[0], 'stop_before_cleanup': hex(STOP),
            'transport_used': False, 'windows_apis_executed': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def engine_byte(uc, address):
    return uc.mem_read(address, 1)[0]


def audit(data):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    contexts = ({}, {'interpreter': 3}, {'payload': bytes(range(8))},
                {'fixed_address': True}, {'failure_at': 1},
                {'interpreter': 3, 'failure_at': 1}, {'cancel': True}, {'chunk_size': 1})
    sections = executable_sections(data)
    section = next(s for s in sections if s['va'] <= START and END <= s['va']+s['raw_bytes'])
    offset = section['raw_offset']+START-section['va']
    source_range = {'start': hex(START), 'exclusive_end': hex(END), 'file_offset': offset,
                    'sha256': hashlib.sha256(data[offset:offset+END-START]).hexdigest()}
    return {'schema': 'pccs-file-chunk-native-slice-v1', 'source_sha256': SOURCE_SHA256,
            'native_range': source_range, 'cases': [run(data, **c) for c in contexts],
            'limitations': ['Explicit endpoint, offset-zero branch only; entry/prologue and cleanup do not execute.',
                            'Payload capped at 256 synthetic bytes; this is a harness resource bound, not a protocol limit.',
                            'The alternate selector==3 transfer helper is outside this model.',
                            'All stream, transfer, status, UI and round callbacks are synthetic replacements.',
                            'No retry, interruption recovery, FIL interpretation or AL5 transport is qualified.'],
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
    with args.output.open('x', encoding='utf-8') as out:
        json.dump(result, out, indent=2)
        out.write('\n')
    print(json.dumps({'cases': len(result['cases']), 'ready_to_flash': False}))


if __name__ == '__main__':
    main()
