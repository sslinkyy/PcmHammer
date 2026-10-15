"""Pinned PCCS CAN buffer helpers with synthetic copy/send callbacks only.

This executes selected native instruction ranges in private Unicorn memory.
No imported API, application entry point, transport or controller executes.
The modeled buffers are not qualified AL5 CAN/VPW programming frames.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

THIS, STACK, EXIT = 0x10000000, 0x20000000, 0x30000000
SEND = EXIT+0x100
COPY, CLEANUP = 0x404820, 0x4084c8
RANGES = ((0x5a8c18, 0x5a8c56), (0x5a8c58, 0x5a8d1d),
          (0x5adbfc, 0x5adc28), (0x5a924c, 0x5a958e),
          (0x5a8ad8, 0x5a8ba6), (0x5a8bb8, 0x5a8c17),
          (0x5a8d20, 0x5a9146), (0x5b0af8, 0x5b0aff))
STRING_CLEAR = 0x4071b4


def permitted_pc(address, size):
    return size > 0 and (any(a <= address and address+size <= b for a, b in RANGES)
                         or address in (COPY, CLEANUP, STRING_CLEAR) and size == 1
                         or address == SEND and size == 3)


def permitted_write(address, size, payload_length):
    return size > 0 and (STACK <= address and address+size <= STACK+0x20000
                         or 0 <= address and address+size <= 4
                         or address == THIS+0x528a4 and size == 1
                         or address == THIS+0x528a8 and size == 4
                         or THIS+0x528b0 <= address and
                         address+size <= THIS+0x528b0+max(5+payload_length, 5))


def run(data, *, payload=b'\x12\x03', target=3, source=0xf9,
        override=False, identifier=0x7e1, startup=False, fil=None):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= 8:
        raise ValueError('Model requires 1..8 bytes for its classical CAN contexts')
    if not 0 <= target <= 255 or not 0 <= source <= 255 or not 0 <= identifier <= 0x1fffffff:
        raise ValueError('Invalid synthetic CAN context')
    if fil not in (None, 'extended', 'standard') or fil and (startup or override):
        raise ValueError('Unsupported synthetic FIL context')
    if fil == 'standard' and identifier > 0x7ff:
        raise ValueError('Standard synthetic FIL context requires 11-bit identifier')
    sections = executable_sections(data)
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('This audit requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ECX, UC_X86_REG_ESP, UC_X86_REG_EIP
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base, image_size = struct.unpack_from('<I', data, pe+24+28)[0], struct.unpack_from('<I', data, pe+24+56)[0]
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(0, 0x1000)
    uc.mem_map(base, (image_size+0xfff)&~0xfff)
    for section in sections:
        off = section['raw_offset']
        uc.mem_write(section['va'], data[off:off+section['raw_bytes']])
    uc.mem_map(THIS, 0x75000)
    uc.mem_map(STACK, 0x20000)
    uc.mem_map(EXIT, 0x1000)
    uc.mem_write(SEND, bytes.fromhex('c21400'))
    uc.mem_write(COPY, b'\xc3')
    uc.mem_write(CLEANUP, b'\xc3')
    uc.mem_write(STRING_CLEAR, b'\xc3')
    uc.mem_write(THIS+8, struct.pack('<I', SEND))
    uc.mem_write(THIS+0x2c, struct.pack('<H', 0x1234))
    uc.mem_write(THIS+0x74890, struct.pack('<I', identifier))
    uc.mem_write(THIS+0x74888, struct.pack('<I', identifier))
    uc.mem_write(THIS+0x52250, payload)
    uc.mem_write(0x81d108, bytes([int(override)]))
    uc.mem_write(0x81d0fc, bytes([source]))
    uc.mem_write(0x81d0f4, struct.pack('<I', target))
    uc.mem_write(0x81d138, b'\x00')
    uc.mem_write(0x81d144, b'\x01')  # Choose explicit 18DA prefix branch; text branch unmodeled.
    calls, stages = [], []
    instructions = [0]

    def code(engine, address, size, _):
        if not permitted_pc(address, size):
            raise ValueError(f'Unexpected execution {address:#x}')
        instructions[0] += 1
        if address == COPY:
            src = engine.reg_read(UC_X86_REG_EAX)
            dst = engine.reg_read(UC_X86_REG_EDX)
            count = engine.reg_read(UC_X86_REG_ECX)
            valid_src = (STACK <= src and src+count <= STACK+0x20000
                         or src == THIS+0x52250 and count == len(payload))
            if not valid_src or not permitted_write(dst, count, len(payload)):
                raise ValueError('Synthetic copy escaped declared source/destination')
            engine.mem_write(dst, bytes(engine.mem_read(src, count)))
        elif address == SEND:
            sp = engine.reg_read(UC_X86_REG_ESP)
            args = struct.unpack('<IIIII', engine.mem_read(sp+4, 20))
            prefix_length = 5 if engine.mem_read(THIS+0x528b0, 1)[0] == 1 else 3
            if args[0] != 0x1234 or args[1] != THIS+0x528b0 or args[2] != len(payload)+prefix_length or args[3:] != (0, 0):
                raise ValueError('Unexpected synthetic callback arguments')
            calls.append({'arguments': list(args),
                          'internal_callback_buffer_hex': bytes(engine.mem_read(args[1], args[2])).hex()})
            engine.reg_write(UC_X86_REG_EAX, 0)

    def write(engine, access, address, size, value, _):
        if not permitted_write(address, size, len(payload)):
            raise ValueError(f'Unexpected native write {address:#x}+{size}')

    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    prefix = 0x5a8ad8 if fil == 'extended' else 0x5a8bb8 if fil == 'standard' else 0x5a8c18 if startup else 0x5a8c58
    wrapper = 0x5a8d20 if fil else 0x5a924c
    for start, edx in ((prefix, 0 if fil == 'standard' else target),
                       (wrapper, len(payload)+(3 if fil == 'standard' else 5) if fil else len(payload))):
        if fil and start == wrapper:
            # Payload is synthetic caller state. Native FIL opcode builders do not run.
            uc.mem_write(THIS+0x528b0+(3 if fil == 'standard' else 5), payload)
        sp = STACK+0x10000
        uc.mem_write(sp, struct.pack('<I', EXIT))
        uc.reg_write(UC_X86_REG_ESP, sp)
        uc.reg_write(UC_X86_REG_EAX, THIS)
        uc.reg_write(UC_X86_REG_EDX, edx)
        uc.reg_write(UC_X86_REG_ECX, 0)  # FIL send padding disabled in this context.
        uc.emu_start(start, EXIT, count=10000)
        if uc.reg_read(UC_X86_REG_EIP) != EXIT or uc.reg_read(UC_X86_REG_ESP) != sp+4:
            raise ValueError('Native framing stage did not return with expected stack')
        stages.append(hex(start))
    if len(calls) != 1:
        raise ValueError('Expected one synthetic callback')
    return {'context': {'payload_hex': payload.hex(), 'target': target, 'source': source,
                        'override': override, 'identifier': identifier, 'startup': startup,
                        'fil': fil, 'synthetic_prefilled_fil_payload': fil is not None,
                        'fil_prefix_flag_81d144': 1 if fil else None},
            'stages': stages, 'calls': calls, 'instruction_observations': instructions[0],
            'transport_used': False, 'windows_apis_executed': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def audit(data):
    contexts = ({}, {'source': 0xf8, 'target': 0x18},
                {'override': True, 'identifier': 0x7ff},
                {'override': True, 'identifier': 0x800},
                {'override': True, 'identifier': 0x18ef03f9}, {'startup': True, 'source': 0xf8},
                {'fil': 'extended', 'payload': b'\x36\x01'},
                {'fil': 'standard', 'payload': b'\x36\x01'})
    cases = [run(data, **context) for context in contexts]
    sections = executable_sections(data)
    source_ranges = []
    for start, end in RANGES:
        section = next(s for s in sections if s['va'] <= start and end <= s['va']+s['raw_bytes'])
        offset = section['raw_offset']+start-section['va']
        source_ranges.append({'start': hex(start), 'exclusive_end': hex(end),
                              'file_offset': offset, 'bytes': end-start,
                              'sha256': hashlib.sha256(data[offset:offset+end-start]).hexdigest()})
    return {'schema': 'pccs-framing-emulation-v1', 'source_sha256': SOURCE_SHA256,
            'emulator': 'Unicorn 2.1.4', 'source_ranges': source_ranges, 'cases': cases,
            'limitations': ['Synthetic classical CAN contexts only; no physical transport qualification.',
                            'Copy/cleanup/send callbacks are replacements; imported APIs do not execute.',
                            'No complete dispatcher, FIL interpreter or controller behavior is emulated.',
                            'FIL payloads are prefilled synthetic caller state; opcode builders do not execute.',
                            'The alternate 0CDA prefix/text comparison branch is not modeled.',
                            'These buffers do not establish AL5 compatibility or a VPW programming path.'],
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('exe', type=Path)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        p.error('Output exists; refusing overwrite')
    result = audit(args.exe.read_bytes())
    result['source_path'] = str(args.exe.resolve())
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print(json.dumps({'cases': len(result['cases']), 'ready_to_flash': False}))


if __name__ == '__main__':
    main()
