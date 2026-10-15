"""Pinned identification entry clears alternate routing before later selectors.

No full identification, initialization, I/O or live write executes. Independent
poll-gate compositions illustrate ordering; they are not a continuous replay.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from emulate_pccs_erase import SOURCE_SHA256
from inspect_pccs_methods import executable_sections
from emulate_pccs_enter_write_poll_gate import run as run_poll
from emulate_pccs_standard_lct_identity import run as run_classification

START, STOP = 0x5d8efe, 0x5d8f5c
THIS, STACK = 0x10000000, 0x20000000
GLOBALS = (0x81d134, 0x81d118, 0x81d10c, 0x81d140, 0x81d150, 0x81d110)


def permitted_pc(address, size):
    return size > 0 and START <= address and address+size <= STOP


def permitted_write(address, size):
    return size == 1 and (address in GLOBALS or THIS+0x72d90 <= address < THIS+0x72d94)


def run(data, *, prior_alternate=1, prior_quick=1, gmw_control=1):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('source executable pin changed')
    if (type(prior_alternate) is not int or not 0 <= prior_alternate <= 255
            or type(gmw_control) is not int or not 0 <= gmw_control <= 255
            or type(prior_quick) is not int or prior_quick not in (0, 1)):
        raise ValueError('Invalid synthetic identification-entry context')
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
    uc.mem_write(THIS+0x72d90, bytes([prior_alternate, 0xa5, 0xa5, 0xa5]))
    uc.mem_write(THIS+0x68c60, bytes([prior_quick]))
    uc.mem_write(0x81d104, bytes([gmw_control]))
    for addr in GLOBALS:
        uc.mem_write(addr, b'\xa5')
    bp, sp = STACK+0x8000, STACK+0x7000
    uc.mem_write(bp-0x104, struct.pack('<I', THIS))
    uc.reg_write(UC_X86_REG_EBP, bp)
    uc.reg_write(UC_X86_REG_ESP, sp)
    instructions, writes = [0], []
    def code(engine, address, size, _):
        if not permitted_pc(address, size):
            raise ValueError(f'Unexpected entry PC {address:#x}+{size}')
        instructions[0] += 1
    def write(engine, access, address, size, value, _):
        if not permitted_write(address, size):
            raise ValueError(f'Unexpected entry write {address:#x}+{size}')
        writes.append({'address': hex(address), 'size': size, 'value': value})
    uc.hook_add(UC_HOOK_CODE, code)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(START, STOP, count=100)
    if uc.reg_read(UC_X86_REG_EIP) != STOP or uc.reg_read(UC_X86_REG_ESP) != sp:
        raise ValueError('Entry slice did not reach declared boundary')
    return {'context': {'prior_alternate': prior_alternate, 'prior_quick': prior_quick, 'gmw_control': gmw_control},
            'final_alternate': uc.mem_read(THIS+0x72d90, 1)[0],
            'final_route_bytes': bytes(uc.mem_read(THIS+0x72d90, 4)).hex(),
            'final_quick': uc.mem_read(THIS+0x68c60, 1)[0],
            'final_gmw_control': uc.mem_read(0x81d104, 1)[0],
            'final_globals': {hex(a): uc.mem_read(a, 1)[0] for a in GLOBALS},
            'native_writes': writes, 'instruction_observations': instructions[0],
            'full_identification_executed': False, 'transport_used': False,
            'live_write_enabled': False, 'ready_to_flash': False, 'would_send': []}


def audit(data):
    cases = [run(data, prior_alternate=a, prior_quick=q) for a in (0, 1, 255) for q in (0, 1)]
    compositions = []
    for prior in (0, 1, 255):
        entry = run(data, prior_alternate=prior)
        before = run_classification(data, prior_alternate=prior)
        after = run_classification(data, prior_alternate=entry['final_alternate'])
        compositions.append({'prior_alternate': prior, 'entry': entry,
                             'standard_lct_without_entry_clear': before,
                             'standard_lct_after_entry_clear': after,
                             'poll_without_entry_clear': run_poll(data, alternate=before['final_alternate']),
                             'poll_after_entry_clear': run_poll(data, alternate=after['final_alternate'])})
    section = next(s for s in executable_sections(data)
                   if s['va'] <= START and STOP <= s['va']+s['raw_bytes'])
    off = section['raw_offset']+START-section['va']
    return {'schema': 'pccs-alternate-identification-entry-v1', 'source_sha256': SOURCE_SHA256,
            'source_range': {'start': hex(START), 'exclusive_end': hex(STOP), 'file_offset': off,
                             'sha256': hashlib.sha256(data[off:off+STOP-START]).hexdigest()},
            'entry_cases': cases, 'independent_poll_compositions': compositions,
            'limitations': ['Interior entry stores only; subsequent identification selectors are excluded.',
                            'Prior fields and poll helper responses are synthetic.',
                            'Entry, standard-LCT classification and poll run independently; no continuous call-path replay or reachability proof.',
                            'A later setter can enable the alternate route after this entry clear.',
                            'QuickWrite reset, programming, controller acceptance and recovery do not execute.'],
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
    print(json.dumps({'entry_cases': len(result['entry_cases']),
                      'poll_compositions': len(result['independent_poll_compositions']),
                      'ready_to_flash': False}))


if __name__ == '__main__':
    main()
