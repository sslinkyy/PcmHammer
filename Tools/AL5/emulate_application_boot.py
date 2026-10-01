"""Offline application boot-request guards and reset-marker route experiments.

The handler receives a synthetic internal buffer. No live packet construction,
reset, flash code or uploaded code execution is provided.
"""
import argparse
import json
from pathlib import Path
from al5_segment import sha256

LOW_HASH = 'cf5dd139e52ba5925fc95f166627a9a7abcac1374ded8cb738df8297b961a3f6'
HIGH_HASH = '492040d9460d53b77dda606b9a89f4254e0680f239093001663f6ed5cf51ba75'
RANGES = [(0xBE6D0, 0xBE794), (0x21D08, 0x21D18), (0x8B2, 0x96E),
          (0x3B7C, 0x3CEA), (0x2E30, 0x2E4A)]
BASE, STACK, BUFFER, RETURN = 0xFF8000, 0x208800, 0x208000, 0x300000


def service_binding(data):
    count = data[0x99AF4]
    if count != 22: raise ValueError('service table count changed')
    records = []
    for index in range(count):
        offset = 0x99A70+index*6
        raw = data[offset:offset+6]
        descriptor = int.from_bytes(raw[2:], 'big')
        if raw[1] != 0 or descriptor & 1 or descriptor+6 > len(data):
            raise ValueError('malformed service descriptor')
        records.append({'service': hex(raw[0]), 'table_address': hex(offset),
                        'descriptor': hex(descriptor),
                        'descriptor_flags': data[descriptor:descriptor+2].hex(),
                        'handler': hex(int.from_bytes(data[descriptor+2:descriptor+6], 'big'))})
    binding = next(record for record in records if record['service'] == '0x34')
    if binding['descriptor'] != '0x99a30' or binding['handler'] != '0xbe6d0' or binding['descriptor_flags'] != '9000':
        raise ValueError('service binding changed')
    return {'table_address': '0x99a70', 'count_address': '0x99af4',
            'record_bytes': 6, 'table_hex': data[0x99A70:0x99AF4].hex(),
            'entries': records, 'boot_request': binding,
            'limits': 'Lookup traced statically. Descriptor flags and downstream scheduling/authorization are not fully decoded.'}


class ApplicationBoot:
    def __init__(self, low, high, *, request_length=4, guard_bit=False,
                 helper_value=0, guard_word=0, initial_marker=0, initial_upload_armed=False):
        from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_EXEC
        from unicorn.m68k_const import UC_CPU_M68K_M68020
        if sha256(low) != LOW_HASH or sha256(high) != HIGH_HASH:
            raise ValueError('unexpected firmware evidence')
        self.uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
        self.uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
        self.uc.mem_map(0, 0x100000)
        data = low+high
        for a, b in RANGES: self.uc.mem_write(a, data[a:b])
        for a in (0x2CFC, 0x2D1C): self.uc.mem_write(a, data[a:a+1])
        for a in (0xBD89C, 0xC2390, 0xA9D8C, 0x5BAB8, 0x2ED0):
            self.uc.mem_write(a, bytes.fromhex('4e75'))
        self.uc.mem_protect(0, 0x100000, UC_PROT_READ | UC_PROT_EXEC)
        self.uc.mem_map(BASE, 0x8000)
        self.uc.mem_map(0x200000, 0x10000)
        self.uc.mem_map(RETURN, 0x1000)
        self.uc.mem_write(BUFFER, bytes([request_length])+bytes.fromhex('6d18f03400'))
        self.uc.mem_write(BASE+0x1DBE, bytes([0x20 if guard_bit else 0]))
        self.uc.mem_write(BASE+0x1E6C, guard_word.to_bytes(2, 'big'))
        self.uc.mem_write(BASE, initial_marker.to_bytes(2, 'big'))
        self.uc.mem_write(BASE+0x185, bytes([int(initial_upload_armed)]))
        self.helper_value = helper_value
        self.uc.hook_add(UC_HOOK_CODE, self.hook)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self.write_hook)

    def write_hook(self, machine, access, address, size, value, user_data):
        if address in (0xFFE800, 0xFFE801):
            self.observed['synthetic_port_writes'].append({'address': hex(address), 'size': size, 'value': value})

    def hook(self, machine, pc, size, user_data):
        from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_D0
        sp = machine.reg_read(UC_M68K_REG_A7)
        if pc == 0xBD89C:
            machine.reg_write(UC_M68K_REG_D0, self.helper_value)
        elif pc == 0xC2390:
            self.observed['negative_helper_calls'].append({'buffer': hex(int.from_bytes(machine.mem_read(sp+4, 4), 'big')),
                'reason': int.from_bytes(machine.mem_read(sp+8, 4), 'big')})
        elif pc == 0xA9D8C:
            self.observed['response_helper_calls'].append({'buffer': hex(int.from_bytes(machine.mem_read(sp+4, 4), 'big')),
                'argument': int.from_bytes(machine.mem_read(sp+8, 4), 'big')})
        elif pc == 0x5BAB8:
            self.observed['cleanup_helper_calls'] += 1
        elif pc == 0x2ED0:
            length = int.from_bytes(machine.mem_read(0xFF8180, 2), 'big')
            if not 0 < length <= 11: raise RuntimeError('bad logical response length')
            self.observed['boot_responses'].append(bytes(machine.mem_read(0xFF8175, length)).hex())
        elif pc in (0xBE78C, 0x97C, 0x96E, 0x87C):
            self.observed['stop_pc'] = hex(pc)
            machine.emu_stop()  # trap reset wait, boot continuation or application jump
        elif not any(a <= pc < b for a, b in RANGES):
            raise RuntimeError(f'execution escaped permitted code at {pc:#x}')

    def run(self, entry):
        from unicorn.m68k_const import UC_M68K_REG_SR, UC_M68K_REG_A7, UC_M68K_REG_A5, UC_M68K_REG_PC
        self.observed = {'negative_helper_calls': [], 'response_helper_calls': [],
                         'cleanup_helper_calls': 0, 'boot_responses': [],
                         'synthetic_port_writes': [], 'stop_pc': None}
        self.uc.mem_write(STACK, RETURN.to_bytes(4, 'big')+BUFFER.to_bytes(4, 'big'))
        self.uc.reg_write(UC_M68K_REG_SR, 0x2000)
        self.uc.reg_write(UC_M68K_REG_A7, STACK)
        self.uc.reg_write(UC_M68K_REG_A5, BASE)
        self.uc.emu_start(entry, RETURN, timeout=5_000_000, count=100_000)
        if self.uc.reg_read(UC_M68K_REG_PC) != RETURN and self.observed['stop_pc'] is None:
            raise RuntimeError('emulator did not complete within limits')
        self.observed['marker'] = hex(int.from_bytes(self.uc.mem_read(BASE, 2), 'big'))
        self.observed['interrupt_mask'] = (self.uc.reg_read(UC_M68K_REG_SR) >> 8) & 7
        self.observed['upload_armed'] = int.from_bytes(self.uc.mem_read(BASE+0x185, 1), 'big')
        self.observed['flags_8182_to_818a'] = bytes(self.uc.mem_read(BASE+0x182, 9)).hex()
        return self.observed.copy()


def run_cases(low, high):
    trials = [
        ('length_rejected', {'request_length': 5}, [0xBE6D0], {'marker': '0x0', 'negative_helper_calls': [{'buffer': hex(BUFFER), 'reason': 0x12}]}),
        ('guard_bit_rejected', {'guard_bit': True}, [0xBE6D0], {'marker': '0x0', 'negative_helper_calls': [{'buffer': hex(BUFFER), 'reason': 0x33}]}),
        ('helper_above_threshold_rejected', {'helper_value': 401}, [0xBE6D0], {'marker': '0x0', 'negative_helper_calls': [{'buffer': hex(BUFFER), 'reason': 0x22}]}),
        ('guard_word_above_threshold_rejected', {'guard_word': 1601}, [0xBE6D0], {'marker': '0x0', 'negative_helper_calls': [{'buffer': hex(BUFFER), 'reason': 0x22}]}),
        ('guard_boundaries_accepted', {'helper_value': 400, 'guard_word': 1600}, [0xBE6D0], {'marker': '0xbfc1', 'stop_pc': '0xbe78c', 'interrupt_mask': 7, 'response_helper_calls': [{'buffer': hex(BASE+0xF36), 'argument': 0x55}]}),
        ('application_marker_then_boot_route', {}, [0xBE6D0, 0x8B2], {'marker': '0xb094', 'stop_pc': '0x97c'}),
        ('application_route_then_boot_initialization', {}, [0xBE6D0, 0x8B2, 0x3B7C], {'marker': '0xb094', 'upload_armed': 0, 'boot_responses': ['6cf0187444'], 'synthetic_port_writes': [{'address': '0xffe800', 'size': 1, 'value': 0x18}, {'address': '0xffe801', 'size': 1, 'value': 2}]}),
        ('normal_boot_init_no_transition_response', {}, [0x3B7C], {'marker': '0x0', 'upload_armed': 0, 'boot_responses': []}),
        ('boot_init_clears_previous_arming', {'initial_marker': 0xB094, 'initial_upload_armed': True}, [0x3B7C], {'marker': '0xb094', 'upload_armed': 0, 'boot_responses': ['6cf0187444']}),
        ('error_marker_route', {'initial_marker': 0x6124}, [0x8B2], {'marker': '0x23cb', 'stop_pc': '0x97c'}),
        ('already_boot_marker_unknown_route', {'initial_marker': 0xB094}, [0x8B2], {'marker': '0xb094', 'stop_pc': '0x96e'}),
        ('application_resume_marker', {'initial_marker': 0x2FE6}, [0x8B2], {'marker': '0x595', 'stop_pc': '0x87c'}),
    ]
    records = []
    for label, inputs, entries, expected in trials:
        experiment = ApplicationBoot(low, high, **inputs)
        observed = [experiment.run(entry) for entry in entries]
        passed = all(observed[-1][key] == value for key, value in expected.items())
        records.append({'case': label, 'synthetic_state': inputs, 'entries': list(map(hex, entries)),
                        'expected_final': expected, 'observed_steps': observed, 'pass': passed})
        print(label, 'PASS' if passed else 'FAIL', json.dumps(observed[-1]))
    return {'low_sha256': sha256(low), 'high_sha256': sha256(high),
            'application_service_table': service_binding(low+high),
            'code_sha256': {hex(a): sha256((low+high)[a:b]) for a, b in RANGES},
            'scope': 'Selected application handler and boot route/initializer; reset and intermediate boot startup abstracted. No live reachability proof.',
            'live_write_enabled': False, 'flash_code_loaded': False,
            'cases': records, 'all_pass': all(r['pass'] for r in records)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('low', 'high', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    result = run_cases(args.low.read_bytes(), args.high.read_bytes())
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf8')
    raise SystemExit(0 if result['all_pass'] else 1)
