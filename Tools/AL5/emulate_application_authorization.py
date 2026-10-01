"""Offline descriptor callbacks, memory clearing and security guard lifecycle.

Uses extracted firmware with synthetic request/RAM state. No live seed/key,
session entry, reset, transport or flash operation is provided.
"""
import argparse
import json
from pathlib import Path
from al5_segment import sha256
from emulate_application_boot import ApplicationBoot, BASE, BUFFER

EXTRA_RANGES = [(0xB1970, 0xB1B24), (0xA9D8C, 0xA9DC8), (0x9820C, 0x984EC),
                (0x85438, 0x854B8)]
REQUEST = BASE+0xEB6


def result_payload(record):
    """Decode a staged result, excluding stale bytes beyond its declared length."""
    if len(record) != 4 or record[0] not in (2, 3):
        raise ValueError('unsupported staged security result')
    return record[1:1+record[0]].hex()


class Authorization(ApplicationBoot):
    def __init__(self, low, high, *, state=0, offset=0, guard_flags=0,
                 lockout_counter=0, descriptor_flags=0x9000):
        super().__init__(low, high)
        self.data = low+high
        self.ranges.extend(EXTRA_RANGES)
        for a, b in EXTRA_RANGES: self.uc.mem_write(a, self.data[a:b])
        for a, b in ((0x99A30, 0x99A36), (0xA9DD0, 0xA9DD8),
                     (0x10954, 0x10955), (0x3FD8, 0x3FDC), (0x85560, 0x85580)):
            self.uc.mem_write(a, self.data[a:b])
        # Synthetic descriptor changes are solely negative tests; ROM remains
        # write-protected against firmware instructions after initial loading.
        self.uc.mem_write(0x99A30, descriptor_flags.to_bytes(2, 'big'))
        self.uc.mem_write(BASE+0xF2A, bytes([state]))
        self.uc.mem_write(BASE+0xEFF, bytes([offset]))
        self.uc.mem_write(BASE+0x1DBE, bytes([guard_flags]))
        self.uc.mem_write(BASE+0x1DC0, bytes([lockout_counter]))
        self.offset = offset
        self.handler_entries = []

    def hook(self, machine, pc, size, user_data):
        from unicorn.m68k_const import UC_M68K_REG_A7
        if pc == 0xBE6D0:
            sp = machine.reg_read(UC_M68K_REG_A7)
            self.handler_entries.append(hex(int.from_bytes(machine.mem_read(sp+4, 4), 'big')))
        super().hook(machine, pc, size, user_data)

    def snapshot(self, observed):
        observed['memory_clear_helper_calls'] = observed.pop('response_helper_calls')
        observed['handler_entries'] = list(self.handler_entries)
        observed['guard_flags'] = hex(int.from_bytes(self.uc.mem_read(BASE+0x1DBE, 1), 'big'))
        observed['lockout_counter'] = int.from_bytes(self.uc.mem_read(BASE+0x1DC0, 1), 'big')
        record = bytes(self.uc.mem_read(BASE+0x1DBA, 4))
        observed['security_result_record'] = record.hex()
        observed['security_result_payload'] = result_payload(record) if record[0] in (2, 3) else None
        observed['clear_region'] = bytes(self.uc.mem_read(BASE+0xF36, 13)).hex()
        return observed

    def descriptor(self, call_argument=1):
        self.uc.mem_write(REQUEST+self.offset, bytes.fromhex('046d18f03400'))
        self.uc.mem_write(BASE+0xF36, b'\xa5'*13)
        args = (0x99A30).to_bytes(4, 'big')+call_argument.to_bytes(4, 'big')
        return self.snapshot(self.run(0xB1970, args))

    def key(self, value=0xBC08):
        self.uc.mem_write(BUFFER, bytes.fromhex('076d18f02702')+value.to_bytes(2, 'big'))
        return self.snapshot(self.run(0x9820C))

    def seed(self):
        self.uc.mem_write(BUFFER, bytes.fromhex('056d18f02701'))
        return self.snapshot(self.run(0x9820C))

    def transform(self, seed=0x9CE5):
        from unicorn.m68k_const import UC_M68K_REG_D0
        result = self.run(0x85438, seed.to_bytes(4, 'big'))
        result['key_low_word'] = hex(self.uc.reg_read(UC_M68K_REG_D0) & 0xFFFF)
        return self.snapshot(result)


def run_cases(low, high):
    trials = [
        ('callback_state0', {}, [('descriptor', {})], {'marker': '0xbfc1', 'handler_entries': [hex(REQUEST)], 'clear_region': '0000000000000000000000a5a5'}),
        ('callback_state1', {'state': 1}, [('descriptor', {})], {'marker': '0xbfc1', 'handler_entries': [hex(REQUEST)]}),
        ('callback_state2', {'state': 2}, [('descriptor', {})], {'marker': '0xbfc1', 'handler_entries': [hex(REQUEST)]}),
        ('callback_state3', {'state': 3}, [('descriptor', {})], {'marker': '0xbfc1', 'handler_entries': [hex(REQUEST)]}),
        ('callback_with_receive_offset', {'offset': 8}, [('descriptor', {})], {'marker': '0xbfc1', 'handler_entries': [hex(REQUEST+8)]}),
        ('state1_argument0_no_callback', {'state': 1}, [('descriptor', {'call_argument': 0})], {'marker': '0x0', 'handler_entries': []}),
        ('state2_argument0_no_callback', {'state': 2}, [('descriptor', {'call_argument': 0})], {'marker': '0x0', 'handler_entries': []}),
        ('callback_flag_removed', {'descriptor_flags': 0x8000}, [('descriptor', {})], {'marker': '0x0', 'handler_entries': []}),
        ('locked_callback_rejected', {'guard_flags': 0x20}, [('descriptor', {})], {'marker': '0x0', 'negative_helper_calls': [{'buffer': hex(REQUEST), 'reason': 0x33}]}),
        ('locked_fixed_seed', {'guard_flags': 0x20}, [('seed', {})], {'guard_flags': '0x60', 'security_result_record': '03019ce5'}),
        ('seed_key_then_descriptor', {'guard_flags': 0x20}, [('seed', {}), ('key', {}), ('descriptor', {})], {'guard_flags': '0x40', 'marker': '0xbfc1', 'handler_entries': [hex(REQUEST)]}),
        ('unlocked_seed_zero', {'guard_flags': 0}, [('seed', {})], {'guard_flags': '0x0', 'security_result_record': '03010000'}),
        ('key_without_seed_state', {'guard_flags': 0x20}, [('key', {})], {'guard_flags': '0x20', 'negative_helper_calls': [{'buffer': hex(BUFFER), 'reason': 0x22}]}),
        ('correct_fixed_key_unlocks', {'guard_flags': 0x60}, [('key', {})], {'guard_flags': '0x40', 'security_result_record': '02023400'}),
        ('unlocked_then_descriptor', {'guard_flags': 0x60}, [('key', {}), ('descriptor', {})], {'guard_flags': '0x40', 'marker': '0xbfc1', 'handler_entries': [hex(REQUEST)]}),
        ('first_wrong_key', {'guard_flags': 0x60}, [('key', {'value': 0})], {'guard_flags': '0xa0', 'lockout_counter': 0, 'security_result_record': '02023500'}),
        ('two_wrong_keys_with_real_seed_requests', {'guard_flags': 0x20}, [('seed', {}), ('key', {'value': 0}), ('seed', {}), ('key', {'value': 0})], {'guard_flags': '0x20', 'lockout_counter': 100, 'security_result_record': '020236e5', 'security_result_payload': '0236'}),
        ('lockout_rejects_correct_key', {'guard_flags': 0x60, 'lockout_counter': 100}, [('key', {})], {'guard_flags': '0x60', 'lockout_counter': 100, 'security_result_record': '02023700'}),
        ('already_unlocked_key_response', {'guard_flags': 0}, [('key', {})], {'guard_flags': '0x0', 'security_result_record': '02023400'}),
        ('separate_dynamic_transform', {}, [('transform', {})], {'key_low_word': '0xace1'}),
    ]
    records = []
    for label, initial, steps, expected in trials:
        session = Authorization(low, high, **initial)
        observations = [getattr(session, method)(**inputs) for method, inputs in steps]
        passed = all(observations[-1][key] == value for key, value in expected.items())
        records.append({'case': label, 'synthetic_state': initial, 'steps': [{'method': m, 'inputs': v} for m, v in steps],
                        'expected_final': expected, 'observed_steps': observations, 'pass': passed})
        print(label, 'PASS' if passed else 'FAIL', json.dumps(observations[-1]))
    data = low+high
    return {'low_sha256': sha256(low), 'high_sha256': sha256(high),
            'extra_code_sha256': {hex(a): sha256(data[a:b]) for a, b in EXTRA_RANGES},
            'saved_security_selector': data[0x10954], 'fixed_seed_key_bytes': data[0x3FD8:0x3FDC].hex(),
            'dynamic_table_hex': data[0x85560:0x85580].hex(),
            'scope': 'Extracted descriptor callback and fixed-selector seed/key handler with synthetic state. Dynamic seed generation, timers, receive path and reset are not emulated.',
            'live_write_enabled': False, 'flash_code_loaded': False,
            'cases': records, 'all_pass': all(r['pass'] for r in records)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('low', 'high', 'output'): parser.add_argument('--'+name, required=True, type=Path)
    args = parser.parse_args()
    report = run_cases(args.low.read_bytes(), args.high.read_bytes())
    args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
    raise SystemExit(0 if report['all_pass'] else 1)
