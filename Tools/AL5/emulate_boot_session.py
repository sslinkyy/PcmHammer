"""Isolated boot dispatcher and RAM-transfer sequences; no live transport.

ROM is read-only, all external execution is rejected, and uploaded execution
is trapped. Synthetic receive buffers and FIFO events are test inputs only.
"""
import argparse
import json
from pathlib import Path
from al5_segment import sha256

EXPECTED_LOW = 'cf5dd139e52ba5925fc95f166627a9a7abcac1374ded8cb738df8297b961a3f6'
DISPATCH = (0x341C, 0x39AA)
TRANSFER = (0x3074, 0x341A)
NEGATIVE = (0x2FE0, 0x3074)
STACK, RETURN = 0x208000, 0x300000


class BootSession:
    def __init__(self, low):
        from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_EXEC
        from unicorn.m68k_const import UC_CPU_M68K_M68020
        if len(low) != 0x20000 or sha256(low) != EXPECTED_LOW:
            raise ValueError('unexpected existing firmware evidence')
        self.uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
        self.uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
        self.uc.mem_map(0, 0x5000)
        for start, end in (DISPATCH, TRANSFER, NEGATIVE):
            self.uc.mem_write(start, low[start:end])
        for address in (0x2CF8, 0x2D24):
            self.uc.mem_write(address, low[address:address+1])
        for address in (0x2ED0, 0x2E30, 0x2E8C, 0x2D98):
            self.uc.mem_write(address, bytes.fromhex('4e75'))
        self.uc.mem_protect(0, 0x5000, UC_PROT_READ | UC_PROT_EXEC)
        self.uc.mem_map(0xFF8000, 0x8000)  # synthetic RAM and registers only
        self.uc.mem_map(0x200000, 0x10000)
        self.uc.mem_map(RETURN, 0x1000)
        self.uc.hook_add(UC_HOOK_CODE, self.hook)
        self.events = []
        self.observed = {}

    def hook(self, machine, pc, size, user_data):
        from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_D0
        if pc == 0x2ED0:
            count = int.from_bytes(machine.mem_read(0xFF8180, 2), 'big')
            if not 0 < count <= 11: raise RuntimeError('unexpected response length')
            self.observed['responses'].append(bytes(machine.mem_read(0xFF8175, count)).hex())
        elif pc == 0x2E30:
            sp = machine.reg_read(UC_M68K_REG_A7)
            self.observed['external_helper_arguments'].append(bytes(machine.mem_read(sp+4, 2)).hex())
        elif pc == 0x2E8C:
            if not self.events: raise RuntimeError('synthetic FIFO exhausted')
            status, value = self.events.pop(0)
            self.observed['fifo_events_consumed'] += 1
            machine.reg_write(UC_M68K_REG_D0, (status << 8) | value)
        elif pc == 0x2D98:
            self.observed['flush_calls'] += 1
        elif 0xFF9000 <= pc <= 0xFFA7FF:
            self.observed['uploaded_execution_trapped'] = True
            machine.emu_stop()
        elif not any(a <= pc < b for a, b in (DISPATCH, TRANSFER, NEGATIVE)):
            raise RuntimeError(f'execution escaped permitted code at {pc:#x}')

    def run(self, entry):
        from unicorn.m68k_const import UC_M68K_REG_SR, UC_M68K_REG_A7, UC_M68K_REG_PC
        self.observed = {'responses': [], 'external_helper_arguments': [],
                         'fifo_events_consumed': 0, 'flush_calls': 0,
                         'uploaded_execution_trapped': False}
        self.uc.mem_write(STACK, RETURN.to_bytes(4, 'big'))
        self.uc.reg_write(UC_M68K_REG_SR, 0x2700)
        self.uc.reg_write(UC_M68K_REG_A7, STACK)
        self.uc.emu_start(entry, RETURN, timeout=5_000_000, count=500_000)
        if self.uc.reg_read(UC_M68K_REG_PC) != RETURN and not self.observed['uploaded_execution_trapped']:
            raise RuntimeError('firmware did not return within emulator limits')
        self.observed['flags_8183_to_8189'] = bytes(self.uc.mem_read(0xFF8183, 7)).hex()
        self.observed['upload_armed'] = int.from_bytes(self.uc.mem_read(0xFF8185, 1), 'big')
        self.observed['ram_prefix'] = bytes(self.uc.mem_read(0xFF9000, 16)).hex()
        return self.observed.copy()

    def dispatch(self, staged, *, status=0, declared_length=None):
        # A staged receive buffer is not a vehicle packet API.
        if not 4 <= len(staged) <= 10: raise ValueError('bad synthetic input')
        self.uc.mem_write(0xFF8164, bytes([status])+staged+b'\x00'*(11-len(staged)))
        length = len(staged) if declared_length is None else declared_length
        self.uc.mem_write(0xFF8170, length.to_bytes(2, 'big'))
        return self.run(DISPATCH[0])

    def transfer(self, *, payload=b'\x12\x34\x56\x78', corrupt_checksum=False, subtype=0):
        # Deliberately synthetic FIFO stream at the previously emulated RAM start.
        tail = bytes([subtype])+len(payload).to_bytes(2, 'big')+bytes.fromhex('ff9000')+payload
        checksum = (sum(tail)+int(corrupt_checksum)) & 0xFFFF
        self.events = [(0x20, b) for b in tail+checksum.to_bytes(2, 'big')]+[(0xA0, 0)]
        self.uc.mem_write(0xFF8164, bytes.fromhex('006d18f036')+b'\x00'*7)
        self.uc.mem_write(0xFF8170, b'\x00\x04')
        # The receive ISR clears this flag after the preceding handler call
        # (3ACA). We abstract that caller cleanup, not the upload-arming flag.
        self.uc.mem_write(0xFF8182, b'\x00')
        return self.run(TRANSFER[0])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--low', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    low = args.low.read_bytes()
    # Expectations are specified independently of the observed responses.
    trials = [
        ('arm_without_seed', [('dispatch', {'staged': '6d18f034'})], {'upload_armed': 1, 'responses': ['6df0187444']}),
        ('arm_global_destination', [('dispatch', {'staged': '6d fef0 34'})], {'upload_armed': 1, 'responses': ['6df0187444']}),
        ('arm_wrong_length', [('dispatch', {'staged': '6d18f03400'})], {'upload_armed': 0, 'responses': ['6cf0187f340012']}),
        ('arm_wrong_destination', [('dispatch', {'staged': '6d19f034'})], {'upload_armed': 0, 'responses': []}),
        ('arm_bad_priority_flag', [('dispatch', {'staged': '6918f034'})], {'upload_armed': 0, 'responses': []}),
        ('arm_receive_error', [('dispatch', {'staged': '6d18f034', 'status': 0x10})], {'upload_armed': 0, 'responses': []}),
        ('arm_receive_status_bit3', [('dispatch', {'staged': '6d18f034', 'status': 8})], {'upload_armed': 0, 'responses': []}),
        ('seed_zero_boot_only', [('dispatch', {'staged': '6d18f02701'})], {'upload_armed': 0, 'responses': ['6df01867010000']}),
        ('key_subfunction_rejected', [('dispatch', {'staged': '6d18f027021234'})], {'upload_armed': 0, 'responses': ['6cf0187f2702123422']}),
        ('seed_wrong_length', [('dispatch', {'staged': '6d18f02701', 'declared_length': 4})], {'upload_armed': 0, 'responses': ['6cf0187f2712']}),
        ('unsupported_service', [('dispatch', {'staged': '6d18f035'})], {'upload_armed': 0, 'responses': ['6cf0187f3511']}),
        ('response_service_ignored', [('dispatch', {'staged': '6d18f074'})], {'upload_armed': 0, 'responses': []}),
        ('communication_control_global', [('dispatch', {'staged': '6dfef02800'})], {'upload_armed': 0, 'responses': ['6df0186800']}),
        ('communication_control_local_rejected', [('dispatch', {'staged': '6d18f02800'})], {'upload_armed': 0, 'responses': ['6cf0187f280012']}),
        ('unarmed_transfer', [('transfer', {})], {'upload_armed': 0, 'responses': ['6cf0187f36000004ff9022'], 'ram_prefix': '12345678000000000000000000000000'}),
        ('arm_then_transfer', [('dispatch', {'staged': '6d18f034'}), ('transfer', {})], {'upload_armed': 1, 'responses': ['6cf018760073'], 'ram_prefix': '12345678000000000000000000000000'}),
        ('arm_duplicate_transfer', [('dispatch', {'staged': '6d18f034'}), ('transfer', {}), ('transfer', {})], {'upload_armed': 1, 'responses': ['6cf018760073'], 'ram_prefix': '12345678000000000000000000000000'}),
        ('bad_checksum_retains_arming', [('dispatch', {'staged': '6d18f034'}), ('transfer', {'corrupt_checksum': True})], {'upload_armed': 1, 'responses': ['6cf018760077'], 'ram_prefix': '12345678000000000000000000000000'}),
        ('checksum_failure_then_valid_retry', [('dispatch', {'staged': '6d18f034'}), ('transfer', {'corrupt_checksum': True}), ('transfer', {})], {'upload_armed': 1, 'responses': ['6cf018760073'], 'ram_prefix': '12345678000000000000000000000000'}),
        ('uploaded_execution_trapped', [('dispatch', {'staged': '6d18f034'}), ('transfer', {'subtype': 128})], {'upload_armed': 1, 'uploaded_execution_trapped': True, 'responses': []}),
        ('bad_arm_length_does_not_clear_previous_arm', [('dispatch', {'staged': '6d18f034'}), ('dispatch', {'staged': '6d18f03400'})], {'upload_armed': 1, 'responses': ['6cf0187f340012']}),
        ('service_3f_does_not_disarm', [('dispatch', {'staged': '6d18f034'}), ('dispatch', {'staged': '6d18f03f'})], {'upload_armed': 1, 'responses': []}),
        ('a1_without_a0_rejected', [('dispatch', {'staged': '6dfef0a1'})], {'upload_armed': 0, 'responses': ['6cf0187fa122']}),
        ('a0_sets_separate_flag', [('dispatch', {'staged': '6dfef0a0'})], {'upload_armed': 0, 'responses': ['6df018e0aa']}),
        ('a0_then_a1_external_helper_trapped', [('dispatch', {'staged': '6dfef0a0'}), ('dispatch', {'staged': '6dfef0a1'})], {'upload_armed': 0, 'responses': [], 'external_helper_arguments': ['1003'], 'flags_8183_to_8189': '01010001000100'}),
    ]
    records = []
    for label, steps, expected in trials:
        session = BootSession(low)
        observations = []
        for method, inputs in steps:
            values = dict(inputs)
            if 'staged' in values: values['staged'] = bytes.fromhex(values['staged'])
            observations.append(getattr(session, method)(**values))
        actual = observations[-1]
        passed = all(actual[key] == value for key, value in expected.items())
        records.append({'case': label, 'steps': [{'method': m, 'input': v} for m, v in steps],
                        'expected_final': expected, 'observed_steps': observations, 'pass': passed})
        print(label, 'PASS' if passed else 'FAIL', json.dumps(actual))
    report = {'low_sha256': sha256(low),
              'code_sha256': {name: sha256(low[a:b]) for name, (a, b) in
                              [('dispatcher', DISPATCH), ('transfer', TRANSFER), ('negative_helper', NEGATIVE)]},
              'scope': 'Extracted boot code only; synthetic RAM/FIFO and stubbed send/configuration helpers. No live application entry proof.',
              'live_write_enabled': False, 'flash_code_loaded': False,
              'cases': records, 'all_pass': all(r['pass'] for r in records)}
    args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
    raise SystemExit(0 if report['all_pass'] else 1)
