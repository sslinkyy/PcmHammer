"""Pinned GMW helper's failed first request and terminal classification gate.

Only a failed initial request is supported. Request callback/status/parent
fields are synthetic. Success parsing, full helper, driver and I/O do not run.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections
from emulate_pccs_can_fallback_gate import run as run_gate, run_identifier_producer
from emulate_pccs_standard_lct_identity import run as run_classification
from emulate_pccs_enter_write_poll_gate import run as run_enter_write_gate

START, TAIL, STOP = 0x5d7b40, 0x5d89fe, 0x5d8a62
GETTER, GETTER_END = 0x5b0af0, 0x5b0af8
THIS, STACK, VIRTUAL = 0x10000000, 0x20000000, 0x30000000
READ = VIRTUAL+0x100


def permitted_pc(address, size):
    return size > 0 and (START <= address and address+size <= 0x5d7b80
                         or TAIL <= address and address+size <= STOP
                         or GETTER <= address and address+size <= GETTER_END
                         or address == READ and size == 3)


def permitted_write(address, size, index):
    return size > 0 and (STACK <= address and address+size <= STACK+0x10000
                         or size == 1 and address in (0x81d10c, 0x81d158,
                             THIS+index*0xa4+0x80, THIS+index*0xa4+0xb6))


def run(data, *, read_status=9, recognized=0, identifier=0, alternate=1, index=3):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if (type(read_status) is not int or not 1 <= read_status <= 255
            or type(recognized) is not int or recognized not in (0, 1)
            or type(identifier) is not int or not 0 <= identifier <= 0xffff
            or type(alternate) is not int or not 0 <= alternate <= 255
            or type(index) is not int or not 0 <= index <= 6):
        raise ValueError('Requires a failed synthetic request and bounded helper context')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ECX, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+24+28)[0]
    size = struct.unpack_from('<I', data, pe+24+56)[0]
    uc.mem_map(base, (size+0xfff)&~0xfff)
    for section in executable_sections(data):
        off = section['raw_offset']
        uc.mem_write(section['va'], data[off:off+section['raw_bytes']])
    for addr, size in ((THIS, 0x75000), (STACK, 0x10000), (VIRTUAL, 0x1000)):
        uc.mem_map(addr, size)
    def put(addr, value):
        uc.mem_write(addr, struct.pack('<I', value))
    put(THIS, VIRTUAL)
    put(VIRTUAL+0x54, READ)
    uc.mem_write(READ, bytes.fromhex('c20c00'))
    uc.mem_write(THIS+index*0xa4+0x84, identifier.to_bytes(2, 'little'))
    for offset in (0x80, 0xb6):
        uc.mem_write(THIS+index*0xa4+offset, b'\x99')
    uc.mem_write(THIS+0x72d90, bytes([alternate]))
    uc.mem_write(0x81d118, bytes([recognized]))
    bp, parent, sp = STACK+0x8000, STACK+0xc000, STACK+0x7000
    put(bp+8, parent)
    put(parent-0x104, THIS)
    put(parent-0x108, index)
    uc.reg_write(UC_X86_REG_EBP, bp)
    uc.reg_write(UC_X86_REG_ESP, sp)
    requests, instructions = [], [0]
    def code(engine, pc, size, _):
        if not permitted_pc(pc, size):
            raise ValueError(f'Unexpected helper failure PC {pc:#x}+{size}')
        instructions[0] += 1
        if pc == READ:
            args = struct.unpack('<III', engine.mem_read(engine.reg_read(UC_X86_REG_ESP)+4, 12))
            if (requests or engine.reg_read(UC_X86_REG_EAX) != THIS
                    or engine.reg_read(UC_X86_REG_EDX) & 255 != 0xb4
                    or engine.reg_read(UC_X86_REG_ECX) != bp-0x210
                    or args != (0xffffffff, 1, 16)):
                raise ValueError('Unexpected synthetic first helper request')
            requests.append({'vmt_offset': 0x54, 'selector_low_byte': 0xb4,
                             'stack_arguments': list(args), 'synthetic_host_status': read_status})
            engine.mem_write(THIS+0x528a4, bytes([read_status]))
    def write(engine, access, addr, size, value, _):
        if not permitted_write(addr, size, index):
            raise ValueError(f'Unexpected helper failure write {addr:#x}+{size}')
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, STOP, count=1000)
    if (uc.reg_read(UC_X86_REG_EIP) != STOP or uc.reg_read(UC_X86_REG_ESP) != sp
            or len(requests) != 1):
        raise ValueError('Helper failure slice did not reach boundary with balanced calls')
    return {'context': {'read_status': read_status, 'recognized': recognized,
                        'identifier': identifier, 'alternate': alternate, 'index': index},
            'requests': requests, 'final_host_status': uc.mem_read(THIS+0x528a4, 1)[0],
            'final_recognized': uc.mem_read(0x81d118, 1)[0],
            'final_identifier': int.from_bytes(uc.mem_read(THIS+index*0xa4+0x84, 2), 'little'),
            'final_alternate': uc.mem_read(THIS+0x72d90, 1)[0],
            'final_family': uc.mem_read(THIS+index*0xa4+0x80, 1)[0],
            'final_version': uc.mem_read(THIS+index*0xa4+0xb6, 1)[0],
            'instruction_observations': instructions[0], 'full_helper_executed': False,
            'success_response_parsing_executed': False, 'transport_used': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


DISPATCH_START, DISPATCH_STOP = 0x5aee22, 0x5aee2c


def permitted_dispatch_pc(address, size):
    return size > 0 and DISPATCH_START <= address and address+size <= DISPATCH_STOP


def permitted_dispatch_write(address, size):
    return address == THIS+0x528a4 and size == 1


def run_dispatch_entry(data, *, prior_status=9):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if type(prior_status) is not int or not 0 <= prior_status <= 255:
        raise ValueError('Invalid synthetic dispatcher-entry status')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP
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
    bp, sp = STACK+0x8000, STACK+0x7000
    uc.mem_write(bp-8, struct.pack('<I', THIS))
    uc.mem_write(THIS+0x528a4, bytes([prior_status]))
    uc.reg_write(UC_X86_REG_EBP, bp)
    uc.reg_write(UC_X86_REG_ESP, sp)
    def code(engine, address, size, _):
        if not permitted_dispatch_pc(address, size):
            raise ValueError('Unexpected dispatcher-entry PC')
    def write(engine, access, address, size, value, _):
        if not permitted_dispatch_write(address, size):
            raise ValueError('Unexpected dispatcher-entry write')
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(DISPATCH_START, DISPATCH_STOP, count=100)
    if uc.reg_read(UC_X86_REG_EIP) != DISPATCH_STOP or uc.reg_read(UC_X86_REG_ESP) != sp:
        raise ValueError('Dispatcher-entry slice did not reach boundary')
    return {'prior_status': prior_status, 'final_host_status': uc.mem_read(THIS+0x528a4, 1)[0],
            'full_dispatcher_executed': False, 'transport_used': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def audit(data):
    contexts = ({}, {'read_status': 1}, {'read_status': 255}, {'identifier': 0x1234},
                {'recognized': 1}, {'alternate': 255}, {'index': 0},
                {'recognized': 1, 'identifier': 0x1234})
    ranges = []
    for start, stop in ((START, 0x5d7b80), (TAIL, STOP), (GETTER, GETTER_END), (DISPATCH_START, DISPATCH_STOP)):
        section = next(s for s in executable_sections(data)
                       if s['va'] <= start and stop <= s['va']+s['raw_bytes'])
        off = section['raw_offset']+start-section['va']
        ranges.append({'start': hex(start), 'exclusive_end': hex(stop), 'file_offset': off,
                       'sha256': hashlib.sha256(data[off:off+stop-start]).hexdigest()})
    cases = [run(data, **c) for c in contexts]
    identifier_producer = run_identifier_producer(data, response_byte=0)
    helper = run(data, identifier=identifier_producer['identification_word'])
    gate = run_gate(data, helper_flag=helper['final_recognized'],
                    identification_word=helper['final_identifier'],
                    host_status=helper['final_host_status'], alternate=helper['final_alternate'])
    dispatcher_entry = run_dispatch_entry(data, prior_status=gate['final_host_status'])
    classification = run_classification(data, prior_alternate=gate['final_alternate'])
    enter_write = run_enter_write_gate(data, status=0, alternate=classification['final_alternate'])
    pipeline = {'continuous_execution': False, 'actual_al5_reachability_proven': False,
                'initial_identifier_copy': identifier_producer,
                'helper_failure': helper, 'post_helper_gate': gate, 'dispatcher_entry': dispatcher_entry,
                'assumptions': ['Initial CAN probe accepted an E2-path reply with identifier byte zero and reached the helper with alternate=1.',
                                'Subsequent ordinary dispatch completes with status zero and a reply selecting standard LCT.',
                                'Other intervening guards/calls allow continuation without changing the alternate byte.',
                                'Later EnterWrite preparation completes with host status zero.'],
                'classification_if_assumptions_hold': classification,
                'enter_write_if_assumptions_hold': enter_write}
    return {'schema': 'pccs-gmw-helper-first-request-failure-v1', 'source_sha256': SOURCE_SHA256,
            'source_ranges': ranges, 'cases': cases, 'conditional_pipeline': pipeline,
            'limitations': ['Interior initial-request failure and terminal gate only; full helper excluded.',
                            'Selected index, parent state and request status are synthetic.',
                            'The virtual request is replaced; only the actual pure host status getter executes.',
                            'No success-response parsing, complete caller continuation, controller I/O or recovery proof.',
                            'Pipeline composes independent slices with explicit ordinary-response/reachability assumptions.'],
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
