"""Offline execution of the AL5 boot RAM-transfer handler with synthetic FIFO events.

This is a firmware experiment in an emulator, not a vehicle command builder.
Execution outside the handler and explicit hardware stubs is rejected.
"""
import argparse
import json
import struct
from pathlib import Path
from al5_segment import sha256

ENTRY = 0x3074
END = 0x341A
RX = 0xFF8164
TX = 0xFF8174
STACK = 0x208000
RETURN = 0x300000


def experiment(low, *, address=0xFF9000, payload=b'\x12\x34\x56\x78',
               subtype=0, armed=True, corrupt_checksum=False, declared_length=None):
    from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE
    from unicorn.m68k_const import UC_CPU_M68K_M68020, UC_M68K_REG_SR, UC_M68K_REG_A7, UC_M68K_REG_D0
    length = len(payload) if declared_length is None else declared_length
    tail = bytes([subtype])+length.to_bytes(2, 'big')+address.to_bytes(3, 'big')+payload
    checksum = (sum(tail) + int(corrupt_checksum)) & 0xFFFF
    events = [(0x20, value) for value in tail+checksum.to_bytes(2, 'big')]+[(0xA0, 0)]
    uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
    uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    uc.mem_map(0, 0x4000)
    uc.mem_map(0xFF8000, 0x8000)  # emulated RAM/registers only; no host hardware
    uc.mem_map(0x200000, 0x10000)
    uc.mem_map(RETURN, 0x1000)
    code = low[ENTRY:END]
    uc.mem_write(ENTRY, code)
    for stub in (0x2E8C, 0x2ED0, 0x2D98, 0x2FE0):
        uc.mem_write(stub, bytes.fromhex('4e75'))
    uc.mem_write(RX+1, bytes.fromhex('6d18f036'))
    uc.mem_write(0xFF8170, struct.pack('>H', 4))
    uc.mem_write(0xFF8185, bytes([int(armed)]))
    uc.mem_write(STACK, struct.pack('>I', RETURN))
    uc.reg_write(UC_M68K_REG_SR, 0x2700)
    uc.reg_write(UC_M68K_REG_A7, STACK)
    observations = {'responses': [], 'negative_response_arguments': [], 'events_consumed': 0,
                    'flush_calls': 0, 'payload_entry_attempted': False}
    def hook(machine, pc, size, user_data):
        if pc == 0x2E8C:
            if observations['events_consumed'] >= len(events):
                raise RuntimeError('handler exhausted synthetic FIFO')
            status, value = events[observations['events_consumed']]
            observations['events_consumed'] += 1
            # The hardware read returns a word: high byte status, low byte data.
            # The firmware itself stores both at FF8160/FF8161.
            machine.reg_write(UC_M68K_REG_D0, (status << 8) | value)
        elif pc == 0x2ED0:
            tx_length = int.from_bytes(machine.mem_read(0xFF8180, 2), 'big')
            if not 0 < tx_length <= 10:
                raise RuntimeError('unexpected emulated response length')
            observations['responses'].append(bytes(machine.mem_read(TX+1, tx_length)).hex())
        elif pc == 0x2D98:
            observations['flush_calls'] += 1
        elif pc == 0x2FE0:
            sp = machine.reg_read(UC_M68K_REG_A7)
            observations['negative_response_arguments'].append(int.from_bytes(machine.mem_read(sp+4, 4), 'big'))
        elif 0xFF9000 <= pc <= 0xFFA7FF:
            observations['payload_entry_attempted'] = True
            machine.emu_stop()  # never execute uploaded bytes, even in this emulator
        elif not ENTRY <= pc < END:
            raise RuntimeError(f'Execution escaped permitted handler/stubs at {pc:#x}')
    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(ENTRY, RETURN, timeout=5_000_000, count=500_000)
    observations['emulated_ram_prefix'] = bytes(uc.mem_read(0xFF9000, 16)).hex()
    observations['emulated_ram_sha256'] = sha256(bytes(uc.mem_read(0xFF9000, 0x1800)))
    return observations


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--low', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    low = args.low.read_bytes()
    if len(low) != 0x20000:
        raise ValueError('wrong existing low dump size')
    cases = [
        ('valid_ram_transfer', {}, {'responses': ['6cf018760073']}),
        ('odd_address', {'address': 0xFF9001}, {'responses': ['6cf018760074']}),
        ('below_ram_window', {'address': 0xFF8FFE}, {'responses': ['6cf018760074']}),
        ('beyond_ram_window', {'address': 0xFFA800}, {'responses': ['6cf018760074']}),
        ('range_overrun', {'address': 0xFFA7FE}, {'responses': ['6cf018760075']}),
        ('last_permitted_byte', {'address': 0xFFA7FE, 'payload': b'\x42'}, {'responses': ['6cf018760073']}),
        ('maximum_start_window', {'payload': b'\x5a'*0x17FF}, {'responses': ['6cf018760073']}),
        ('empty_payload', {'payload': b''}, {'responses': ['6cf018760073']}),
        ('length_mismatch', {'declared_length': 5}, {'responses': ['6cf018760075']}),
        ('bad_checksum', {'corrupt_checksum': True}, {'responses': ['6cf018760077']}),
        ('download_not_armed', {'armed': False}, {'negative_response_arguments': [0x22]}),
        ('unsupported_subtype', {'subtype': 1}, {'responses': ['6cf018760176']}),
        ('execute_subtype_trapped', {'subtype': 0x80}, {'payload_entry_attempted': True}),
    ]
    records = []
    for label, kwargs, expected in cases:
        actual = experiment(low, **kwargs)
        passed = all(actual[key] == value for key, value in expected.items())
        records.append({'case': label, 'expected': expected, 'observed': actual, 'pass': passed})
        print(label, 'PASS' if passed else 'FAIL', actual)
    result = {'low_sha256': sha256(low), 'handler_sha256': sha256(low[ENTRY:END]),
              'scope': 'boot handler in isolated M68020 emulator; synthetic FIFO and state flag. '
                       'No proof of entry from current live application session. No flash implementation.',
              'cases': records, 'all_pass': all(r['pass'] for r in records)}
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    raise SystemExit(0 if result['all_pass'] else 1)
