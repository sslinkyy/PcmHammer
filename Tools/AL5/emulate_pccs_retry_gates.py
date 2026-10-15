"""Pinned, independent PCCS initialization/dialog/retry gate observations.

These gates do not form an executed complete wrapper. The input status,
dialog result and BL are synthetic; no initialization, UI or transport runs.
The initial status gate executes the actual pure host status getter.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections

THIS, STACK, POINTER = 0x10000000, 0x20000000, 0x30000000
SLICES = {'initial': (0x7be8a4, 0x7be8b8),
          'dialog': (0x7be9da, 0x7be9e1),
          'tail': (0x7be9f7, 0x7be9ff)}
BOUNDARIES = {'initial': {0x7be8b8: 'body_entry', 0x7be8e9: 'initialization_error_dialog_gate',
                          0x7be9f7: 'finish_gate'},
              'dialog': {0x7be9e1: 'accepted_retry', 0x7be9eb: 'declined_retry'},
              'tail': {0x7be897: 'repeat_initialization', 0x7be9ff: 'cleanup'}}
GETTER_START, GETTER_STOP = 0x5b0af0, 0x5b0af8


def permitted_pc(stage, address, size):
    if stage not in SLICES or size <= 0:
        return False
    start, stop = SLICES[stage]
    return start <= address and address+size <= stop or (
        stage == 'initial' and GETTER_START <= address and address+size <= GETTER_STOP)


def permitted_write(stage, address, size):
    return stage == 'initial' and size > 0 and STACK <= address and address+size <= STACK+0x1000


def run(data, *, stage='initial', status=0, dialog_result=0, prior_bl=0):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if (stage not in SLICES
            or any(type(v) is not int or not 0 <= v <= 255 for v in (status, prior_bl))
            or type(dialog_result) is not int or not 0 <= dialog_result <= 0xffffffff):
        raise ValueError('Invalid synthetic retry gate context')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_ESP, UC_X86_REG_EIP
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    base = struct.unpack_from('<I', data, pe+24+28)[0]
    size = struct.unpack_from('<I', data, pe+24+56)[0]
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(base, (size+0xfff)&~0xfff)
    for section in executable_sections(data):
        off = section['raw_offset']
        uc.mem_write(section['va'], data[off:off+section['raw_bytes']])
    uc.mem_map(THIS, 0x53000)
    uc.mem_map(POINTER, 0x1000)
    uc.mem_write(POINTER, struct.pack('<I', THIS))
    uc.mem_write(THIS+0x528a4, bytes([status]))
    uc.mem_map(STACK, 0x1000)
    uc.reg_write(UC_X86_REG_ESP, STACK+0x800)
    uc.reg_write(UC_X86_REG_ESI, POINTER)
    uc.reg_write(UC_X86_REG_EAX, dialog_result)
    uc.reg_write(UC_X86_REG_EBX, prior_bl)
    count, calls, stops = [0], [], []

    def code(engine, address, size, _):
        if address in BOUNDARIES[stage]:
            stops.append(BOUNDARIES[stage][address])
            engine.emu_stop()
            return
        if not permitted_pc(stage, address, size):
            raise ValueError(f'Unexpected retry gate PC {address:#x}+{size}')
        count[0] += 1
        if address == GETTER_START:
            calls.append('native_host_status_getter')

    def write(engine, access, address, size, value, _):
        if not permitted_write(stage, address, size):
            raise ValueError(f'Unexpected retry gate write {address:#x}+{size}')

    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(SLICES[stage][0], 0, count=100)
    eip = uc.reg_read(UC_X86_REG_EIP)
    if eip not in BOUNDARIES[stage] or len(stops) != 1 or uc.reg_read(UC_X86_REG_ESP) != STACK+0x800:
        raise ValueError('Retry gate did not reach declared boundary with balanced calls')
    return {'context': {'stage': stage, 'status': status, 'dialog_result': dialog_result, 'prior_bl': prior_bl},
            'boundary': stops[0], 'boundary_pc': hex(eip),
            'final_bl': uc.reg_read(UC_X86_REG_EBX) & 255,
            'calls': calls, 'instruction_observations': count[0],
            'full_wrapper_executed': False, 'transport_used': False, 'ui_executed': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def audit(data):
    contexts = [dict(stage='initial', status=x) for x in (0, 1, 12, 255)]
    contexts += [dict(stage='dialog', dialog_result=x, prior_bl=b) for x in (0, 4, 5) for b in (0, 1)]
    contexts += [dict(stage='tail', prior_bl=x) for x in (0, 1, 255)]
    cases = [run(data, **context) for context in contexts]
    ranges = []
    for name, (start, stop) in [*SLICES.items(), ('getter', (GETTER_START, GETTER_STOP))]:
        section = next(s for s in executable_sections(data)
                       if s['va'] <= start and stop <= s['va']+s['raw_bytes'])
        offset = section['raw_offset']+start-section['va']
        ranges.append({'name': name, 'start': hex(start), 'exclusive_end': hex(stop), 'file_offset': offset,
                       'sha256': hashlib.sha256(data[offset:offset+stop-start]).hexdigest()})
    return {'schema': 'pccs-retry-independent-native-gates-v1', 'source_sha256': SOURCE_SHA256,
            'source_ranges': ranges, 'cases': cases,
            'limitations': ['Independent interior gates only; no complete wrapper execution or reachability proof.',
                            'Initial status, dialog result and prior BL are synthetic.',
                            'Actual initialization, dialog, reidentification, programming and recovery do not execute.'],
            'transport_used': False, 'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


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
