"""Trace/replay alternate AL5 RPM lockup inhibit, with no vehicle I/O.

Original BINs are read only. Calibration markers and diagnostic controls are
synthetic emulator-memory changes, explicitly recorded in each case.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from trace_tcc_release_arbitration import replay, EXPECTED_LOW, EXPECTED_HIGH, EXPECTED_STOCK

WINDOWS = [(0xA3E00, 0xA4074), (0x87924, 0x879B6), (0x3AAD4, 0x3AAE2),
           (0xADAA8, 0xADC80), (0xA9BF0, 0xA9C5A)]


def investigate(low, high, stock):
    from capstone import Cs, CS_ARCH_M68K, CS_MODE_M68K_020, CS_MODE_BIG_ENDIAN
    sha = lambda b: hashlib.sha256(b).hexdigest()
    if tuple(map(sha, (low, high, stock))) != (EXPECTED_LOW, EXPECTED_HIGH, EXPECTED_STOCK):
        raise ValueError('unexpected saved input identity')
    original = low + high
    image = bytearray(original)
    image[0x8000:0x15FD8] = stock
    # Bound arbitration to its ordinary non-diagnostic path.
    image[0x23414:0x23416] = b'\0\0'
    image = bytes(image)
    cs = Cs(CS_ARCH_M68K, CS_MODE_M68K_020 | CS_MODE_BIG_ENDIAN)
    windows = []
    for start, end in WINDOWS:
        ins = list(cs.disasm(original[start:end], start))
        if sum(i.size for i in ins) != end-start:
            raise ValueError('incomplete decode')
        windows.append({'start': hex(start), 'end_exclusive': hex(end),
                        'sha256': sha(original[start:end]), 'instructions': [
                            {'address': hex(i.address), 'bytes': i.bytes.hex(),
                             'mnemonic': i.mnemonic, 'operands': i.op_str} for i in ins]})
    def run(mode, previous, rpm_raw, state=7, marker=False, enforce=1):
        rom = bytearray(image)
        if marker:
            rom[0x145E0:0x145E4] = struct.pack('>2H', 1100*8, 1250*8)
        rom[0x145B6] = enforce
        rom = bytes(rom)
        fields = [(0x2D1D, bytes([mode])), (0x1F14, bytes([previous])),
                  (0x1214, struct.pack('>H', rpm_raw)), (0x2407, bytes([state]))]
        result = {}
        stages = [('rpm_gate', 0xA3E00, [(0xA3E00, 0xA4074)]),
                  ('request_priority', 0x87924, [(0x87924, 0x879B6)]),
                  ('off_reason', 0x3AAD4, [(0x3AAD4, 0x3AAE2)]),
                  ('arbitration', 0xADAA8, [(0xADAA8, 0xADC80), (0xA9BF0, 0xA9C5A)])]
        for name, entry, allowed in stages:
            uc, _, instructions = replay(rom, entry, allowed, fields)
            ram = bytes(uc.mem_read(0x200000, 0x4000))
            result[name] = {'latch_1F14': ram[0x1F14], 'flags_2402': ram[0x2402],
                            'request_2406': ram[0x2406], 'state_2407': ram[0x2407],
                            'off_reason_240E_bit6': bool(ram[0x240E] & 0x40),
                            'instructions': instructions}
            fields = [(0, ram)]
        return result
    cases = []
    for mode in (0, 1, 2, 3, 255):
        for previous in (0, 1, 255):
            for raw in (0, 7199, 7200, 7201, 8399, 8400, 8401, 65535):
                actual = run(mode, previous, raw)
                expected = raw < (8400 if previous else 7200)
                passed = actual['rpm_gate']['latch_1F14'] == int(expected)
                if expected:
                    passed &= (actual['rpm_gate']['flags_2402'] == 0x80
                               and actual['request_priority']['request_2406'] == 0
                               and actual['off_reason']['off_reason_240E_bit6']
                               and actual['arbitration']['state_2407'] == 0)
                cases.append({'kind': 'stock_hysteresis_and_release_chain', 'mode': mode,
                              'previous_latch': previous, 'rpm_raw': raw,
                              'result': actual, 'pass': bool(passed)})
    for mode in (0, 1, 2, 3):
        for previous in (0, 1):
            for rpm in (1000, 1100, 1200, 1250):
                actual = run(mode, previous, rpm*8, marker=True)
                threshold = ((1250 if previous else 1100) if mode == 1 else
                             (1050 if previous else 900))
                cases.append({'kind': 'alternate_pair_marker_in_emulator_only',
                              'marker_rpm': [1100, 1250], 'mode': mode,
                              'previous_latch': previous, 'rpm': rpm, 'result': actual,
                              'pass': actual['rpm_gate']['latch_1F14'] == int(rpm < threshold)})
    for state in (0, 6, 7, 8):
        for enforce in (0, 1):
            actual = run(1, 0, 899*8, state=state, enforce=enforce)
            gate_applies = state != 7 or enforce != 0
            cases.append({'kind': 'state7_enforcement_switch', 'initial_state': state,
                          'emulator_cal145B6': enforce, 'result': actual,
                          'pass': actual['rpm_gate']['latch_1F14'] == 1
                              and (actual['rpm_gate']['flags_2402'] == 0x80) == gate_applies})
    return {'source_sha256': dict(low=sha(low), high=sha(high), stock=sha(stock)),
            'scope': 'Extracted M68020 code, isolated synthetic RAM, no call stubs or transport APIs.',
            'composition': 'Exact stock segment over saved low/high; diagnostic controls23414/15 zero in emulator only.',
            'stock_words': {hex(a): int.from_bytes(image[a:a+2], 'big')
                            for a in (0x1375C, 0x1375E, 0x145E0, 0x145E2)},
            'stock_cal145B6': image[0x145B6], 'static_windows': windows,
            'cases': cases, 'case_count': len(cases), 'all_match': all(c['pass'] for c in cases),
            'limitations': ['RAM is carried between selected producers/consumers, not a full scheduler replay.',
                            'External overrides/reasons and physical clutch response are not qualified.',
                            'Selector producer and physical interpretation are separate evidence.',
                            'RPM >= selected threshold clears this inhibit; it does not command engagement.']}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for n in ('low', 'high', 'stock', 'output'):
        p.add_argument('--'+n, type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        raise ValueError('choose an absent output path')
    inputs = {n: getattr(args,n).read_bytes() for n in ('low','high','stock')}
    report = investigate(**inputs)
    report['inputs'] = {n: str(getattr(args,n)) for n in inputs}
    with args.output.open('x',encoding='utf-8',newline='\n') as f:
        f.write(json.dumps(report,indent=2)+'\n')
    if any(getattr(args,n).read_bytes()!=v for n,v in inputs.items()):
        raise ValueError('source file changed')
    print(json.dumps({'case_count':report['case_count'],'all_match':report['all_match'],
                      'failed_cases':[{k:v for k,v in c.items() if k!='result'}
                                      for c in report['cases'] if not c['pass']]}))
    raise SystemExit(0 if report['all_match'] else 1)
