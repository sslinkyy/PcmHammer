"""Captured AL5 finalization/checksum/error flow with synthetic marker readback.

Every flash command/reset store is skipped; hardware sender is a guarded RTS
stub. Stops before reset-side effects or at receive. No adapter or device API.
"""
import argparse
import json
from pathlib import Path
from al5_segment import START, END, LENGTH, ANCHORS, sha256, word_sum
from checksum import native_field, checksum_valid
from emulate_loader_parser import EXPECTED_SHA, BASE, STACK

RANGES = ((0xff91d6, 0xff9236), (0xff93ea, 0xff9462), (0xff94a8, 0xff952e))
MARKER = 0x1fffe


def permitted_pc(address, size):
    return size > 0 and any(a <= address and address+size <= b for a, b in RANGES)


def fixture():
    image = bytearray(LENGTH)
    for address, expected in ANCHORS.items():
        image[address-START:address-START+len(expected)] = expected
    image[-4:] = native_field(image)
    return bytes(image)


def experiment(code, image, *, marker=0xffff, readback='match'):
    if sha256(code) != EXPECTED_SHA:
        raise ValueError('captured loader hash mismatch')
    if (type(image) is not bytes or len(image) != LENGTH or type(marker) is not int or
            not 0 <= marker <= 65535 or type(readback) is not str or
            readback not in ('match', 'mismatch', 'stop_before_command')):
        raise ValueError('Requires exact calibration bytes, word marker and bounded readback mode')
    import unicorn
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Requires Unicorn 2.1.4')
    from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_PROT_READ
    from unicorn.m68k_const import (UC_CPU_M68K_M68020, UC_M68K_REG_SR,
        UC_M68K_REG_PC, UC_M68K_REG_A7, UC_M68K_REG_A1,
        UC_M68K_REG_D0, UC_M68K_REG_D1, UC_M68K_REG_D3, UC_M68K_REG_D7)
    uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
    uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    uc.mem_map(0, 0x30000)
    uc.mem_map(0xff8000, 0x8000)
    uc.mem_map(0xffff0000, 0x10000)
    uc.mem_write(BASE, code)
    uc.mem_write(START, image)
    uc.mem_write(MARKER, marker.to_bytes(2, 'big'))
    uc.mem_write(0x20046, START.to_bytes(4, 'big')+(END-1).to_bytes(4, 'big'))
    uc.mem_protect(0, 0x30000, UC_PROT_READ)
    for helper in (0xff960c, 0xff952e):
        uc.mem_write(helper, b'\x4e\x75')
    uc.reg_write(UC_M68K_REG_SR, 0x2700)
    uc.reg_write(UC_M68K_REG_A7, STACK)
    observed = dict(stop=None, status_bodies=[], synthetic_marker_readbacks=[],
                    watchdog_calls_stubbed=0, flash_reset_sequences_skipped=0, poll_reads=0,
                    flash_command_instructions_executed=0, mmio_instructions_executed=0,
                    physical_reset_executed=False)
    steps = 0
    def hook(machine, pc, size, _):
        nonlocal steps
        if pc in (0xff9236, 0xff903a):
            observed['stop'] = 'before_shared_reset_exit' if pc == 0xff9236 else 'receive_boundary'
            machine.emu_stop()
            return
        if pc == 0xff960c:
            observed['watchdog_calls_stubbed'] += 1
            return
        if pc == 0xff952e:
            current = machine.reg_read(UC_M68K_REG_A7)
            if int.from_bytes(machine.mem_read(current, 4), 'big') != 0xff952c or machine.reg_read(UC_M68K_REG_D1)&255 != 3:
                raise RuntimeError('Unexpected synthetic hardware sender boundary')
            body = bytes(machine.mem_read(0xffff9a80, 3))
            if body[:2] != b'\x76\x00':
                raise RuntimeError('Unexpected constructed response prefix')
            observed['status_bodies'].append(dict(service=body[0], subtype=body[1], status=body[2]))
            return
        if pc == 0xff940e:
            values = (machine.reg_read(UC_M68K_REG_A1), machine.reg_read(UC_M68K_REG_D0)&65535,
                      machine.reg_read(UC_M68K_REG_D3)&65535, machine.reg_read(UC_M68K_REG_D1)&255)
            if values != (MARKER, 0x4afc, 2, 0xaa) or observed['synthetic_marker_readbacks']:
                raise RuntimeError('Unexpected marker programming context')
            if readback == 'stop_before_command':
                observed['stop'] = 'marker_command_boundary'
                machine.emu_stop()
                return
            value = 0x4afc if readback == 'match' else 0x4afd
            machine.mem_write(MARKER, value.to_bytes(2, 'big'))
            observed['synthetic_marker_readbacks'].append(dict(address=hex(MARKER), value=hex(value), matched=readback == 'match'))
            machine.reg_write(UC_M68K_REG_PC, 0xff941c)
            return
        if pc == 0xff9452:
            observed['flash_reset_sequences_skipped'] += 1
            machine.reg_write(UC_M68K_REG_PC, 0xff945a)
            return
        if not permitted_pc(pc, size):
            raise RuntimeError(f'Escaped finalization model at {pc:#x}+{size}')
        steps += 1
    def write(machine, access, address, size, value, _):
        if not (STACK-32 <= address and address+size <= STACK or
                address == 0xffff9a6e and size == 2 or
                size == 1 and address in (0xffff9a80, 0xffff9a81, 0xffff9a82)):
            raise RuntimeError(f'Untrapped finalization write {address:#x}+{size}')
    def read(machine, access, address, size, value, _):
        if 0xffffe800 <= address < 0xffffe802:
            raise RuntimeError('Untrapped hardware read')
        if address < 0x30000 and not any(a <= address and address+size <= b for a, b in ((START, END), (MARKER, MARKER+2), (0x20046, 0x2004e))):
            raise RuntimeError('Finalization read outside declared synthetic image/pointers')
        if machine.reg_read(UC_M68K_REG_PC) in (0xff9420, 0xff942a):
            observed['poll_reads'] += 1
    uc.hook_add(UC_HOOK_CODE, hook)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.hook_add(UC_HOOK_MEM_READ, read)
    uc.emu_start(0xff91d6, 0xff962c, timeout=5_000_000, count=500000)
    if observed['stop'] is None:
        raise RuntimeError('Finalization exhausted its budget without a classified stop')
    observed.update(marker_after=hex(int.from_bytes(uc.mem_read(MARKER, 2), 'big')),
                    stack_delta=uc.reg_read(UC_M68K_REG_A7)-STACK,
                    retained_error_bits=uc.reg_read(UC_M68K_REG_D7)&255, native_instructions=steps)
    return dict(context=dict(image_sha256=sha256(image), marker_before=hex(marker), readback=readback,
                             image_be16_sum=word_sum(image), image_native_checksum_valid=checksum_valid(image)),
                observed=observed, synthetic_pointer_table=True, physical_marker_programming_proven=False,
                full_receive_or_session_executed=False, physical_recovery_proven=False,
                transport_used=False, live_write_enabled=False, ready_to_flash=False, would_send=[])


def audit(code):
    good = fixture()
    bad_sum = bytearray(good)
    bad_sum[0x100] ^= 1
    bad_crc = bytearray(good)
    bad_crc[-4] ^= 1
    bad_crc[-2:] = b'\0\0'
    bad_crc[-2:] = ((-word_sum(bad_crc))&65535).to_bytes(2, 'big')
    partial = good[:LENGTH//2]+b'\xff'*(LENGTH-LENGTH//2)
    contexts = [('valid', good, {}), ('zero_sum_bad_crc', bytes(bad_crc), {}),
                ('bad_sum', bytes(bad_sum), {}), ('erased_calibration', b'\xff'*LENGTH, {}),
                ('partial_calibration', partial, {}), ('marker_readback_failure', good, dict(readback='mismatch')),
                ('before_marker_command', good, dict(readback='stop_before_command')),
                ('bad_sum_old_marker', bytes(bad_sum), dict(marker=0x4afc))]
    cases = [dict(case=name, **experiment(code, image, **options)) for name, image, options in contexts]
    return dict(schema='al5-loader-finalize-v1', payload_sha256=EXPECTED_SHA,
                generator_sha256=sha256(Path(__file__).read_bytes()), cases=cases,
                scope='Actual captured checksum, marker-loop and status/error instructions with synthetic flash readback; stops before shared reset.',
                limits='No flash command/reset store, transport, actual elapsed polling, boot re-entry or physical interrupted-write recovery. Marker values are host-modeled.',
                live_write_enabled=False, ready_to_flash=False, erase_scope=None, would_send=[])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--loader', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        p.error('Output exists; refusing overwrite')
    result = audit(args.loader.read_bytes())
    with args.output.open('x', encoding='utf-8') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    print(json.dumps(dict(cases=len(result['cases']), ready_to_flash=False)))


if __name__ == '__main__':
    main()
