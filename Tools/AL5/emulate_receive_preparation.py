"""Offline receive classification and boot preparation with storage intercepted.

Flash erase/program implementations are not loaded or executed. All storage
and subsystem helpers are explicit stubs; no live transport/reset is provided.
"""
import argparse
import json
from pathlib import Path
from al5_segment import sha256
from checksum import crc16
from emulate_application_authorization import Authorization, BASE, REQUEST

RANGES = [(0xC1034, 0xC10BE), (0x5BAB8, 0x5BB6E),
          (0x21D18, 0x21D1E), (0xA95D0, 0xA960A)]
STUBS = (0x984EC, 0x94878, 0x602F4, 0xC2290, 0x90D50, 0xAE5DC,
         0xAED38, 0xAFF38, 0xA8938, 0xA8A18, 0x226F0)


class Preparation(Authorization):
    def __init__(self, low, high, **kwargs):
        super().__init__(low, high, **kwargs)
        self.uc.mem_map(0xFFFFF000, 0x1000)  # synthetic long-address MMIO alias
        self.ranges.extend(RANGES)
        for a, b in RANGES: self.uc.mem_write(a, self.data[a:b])
        for a, b in ((0xC10BE, 0xC10C5), (0xAA610, 0xAA810)):
            self.uc.mem_write(a, self.data[a:b])
        for address in STUBS: self.uc.mem_write(address, bytes.fromhex('4e75'))
        self.subsystem_calls = []
        self.storage_calls = []
        self.watchdog_writes = []
        context = bytes((i*37+11) & 255 for i in range(0x9F0))
        self.uc.mem_write(BASE+0x140, context)
        self.expected_crc = crc16(context)

    def write_hook(self, machine, access, address, size, value, user_data):
        if address == 0xFFFFFA26:
            self.watchdog_writes.append({'size': size, 'value': value})
        super().write_hook(machine, access, address, size, value, user_data)

    def hook(self, machine, pc, size, user_data):
        from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_SR
        if pc in STUBS:
            self.subsystem_calls.append(hex(pc))
            if pc == 0x226F0:
                sp = machine.reg_read(UC_M68K_REG_A7)
                self.storage_calls.append({'entry': hex(pc),
                    'source_argument': hex(int.from_bytes(machine.mem_read(sp+4, 4), 'big')),
                    'interrupt_mask': (machine.reg_read(UC_M68K_REG_SR) >> 8) & 7,
                    'implementation_executed': False, 'return_is_stubbed': True})
            return  # only RTS stub executes, no real storage/subsystem code
        super().hook(machine, pc, size, user_data)

    def snapshot(self, observed):
        observed = super().snapshot(observed)
        # Application context overlaps boot-only flag locations. Do not label
        # application bytes as upload arming state using the boot RAM layout.
        observed.pop('upload_armed')
        observed.pop('flags_8182_to_818a')
        observed['preparation_entry_count'] = observed.pop('cleanup_helper_calls')
        observed['receive_state'] = int.from_bytes(self.uc.mem_read(BASE+0xF2A, 1), 'big')
        observed['subsystem_calls'] = list(self.subsystem_calls)
        observed['storage_calls'] = list(self.storage_calls)
        observed['watchdog_writes'] = list(self.watchdog_writes)
        observed['context_crc_word'] = hex(int.from_bytes(self.uc.mem_read(BASE+0xB30, 2), 'big'))
        observed['expected_context_crc'] = hex(self.expected_crc)
        return observed

    def classify(self, priority=0x6D, destination=0x18, service=0x34):
        self.uc.mem_write(REQUEST+self.offset, bytes([4, priority, destination, 0xF0, service, 0]))
        return self.snapshot(self.run(0xC1034))

    def prepare_only(self):
        return self.snapshot(self.run(0x5BAB8))


def run_cases(low, high):
    trials = []
    table = [0, 3, 0, 0, 1, 2, 1, 3]
    for mask, state in enumerate(table):
        inputs = {'priority': 0x6C | ((mask >> 2) & 1),
                  'destination': 0x18 | ((mask >> 1) & 1),
                  'service': 0x34 | ((mask & 1) << 6)}
        trials.append((f'classifier_bits_{mask}', {}, [('classify', inputs)], {'receive_state': state, 'storage_calls': []}))
    trials += [
        ('receive_offset', {'offset': 8}, [('classify', {})], {'receive_state': 1, 'storage_calls': []}),
        ('classified_boot_request_prepares_storage', {}, [('classify', {}), ('descriptor', {})],
         {'receive_state': 1, 'marker': '0xbfc1', 'stop_pc': '0xbe78c', 'interrupt_mask': 7,
          'storage_calls': [{'entry': '0x226f0', 'source_argument': '0xff8140', 'interrupt_mask': 7,
                             'implementation_executed': False, 'return_is_stubbed': True}]}),
        ('locked_classified_request_no_preparation', {'guard_flags': 0x20}, [('classify', {}), ('descriptor', {})],
         {'receive_state': 1, 'marker': '0x0', 'storage_calls': [], 'subsystem_calls': []}),
        ('unlocked_classified_request_prepares_storage', {'guard_flags': 0x20}, [('seed', {}), ('key', {}), ('classify', {}), ('descriptor', {})],
         {'guard_flags': '0x40', 'marker': '0xbfc1', 'storage_calls': [{'entry': '0x226f0', 'source_argument': '0xff8140', 'interrupt_mask': 7,
                              'implementation_executed': False, 'return_is_stubbed': True}]}),
        ('preparation_restores_interrupt_mask', {}, [('prepare_only', {})],
         {'interrupt_mask': 0, 'marker': '0x0',
          'subsystem_calls': list(map(hex, STUBS)),
          'watchdog_writes': [{'size': 2, 'value': 0x55}, {'size': 2, 'value': 0xAA}]}),
    ]
    records = []
    for label, initial, steps, expected in trials:
        session = Preparation(low, high, **initial)
        observed = [getattr(session, method)(**inputs) for method, inputs in steps]
        passed = all(observed[-1][key] == value for key, value in expected.items())
        if observed[-1]['storage_calls']:
            passed &= observed[-1]['context_crc_word'] == observed[-1]['expected_context_crc']
        records.append({'case': label, 'synthetic_state': initial,
                        'steps': [{'method': m, 'inputs': v} for m, v in steps],
                        'expected_final': expected, 'observed_steps': observed, 'pass': bool(passed)})
        print(label, 'PASS' if passed else 'FAIL', json.dumps(observed[-1]))
    return {'low_sha256': sha256(low), 'high_sha256': sha256(high),
            'extra_code_sha256': {hex(a): sha256((low+high)[a:b]) for a, b in RANGES},
            'classifier_table_hex': (low+high)[0xC10BE:0xC10C5].hex(),
            'scope': 'Selected receive classifier and preparation caller; storage/subsystem routines stubbed before execution. Full receive lifecycle/reset not emulated.',
            'live_write_enabled': False, 'flash_code_loaded': False, 'storage_implementation_executed': False,
            'cases': records, 'all_pass': all(record['pass'] for record in records)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('low', 'high', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    result = run_cases(args.low.read_bytes(), args.high.read_bytes())
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf8')
    raise SystemExit(0 if result['all_pass'] else 1)
