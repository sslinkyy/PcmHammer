"""Extract resident flash selector evidence into a blocked offline planning report.

Reads a saved editor dump only. Contains no emulation, transport or packet builder.
Neighboring selector starts imply candidate intervals, not proven erase geometry.
"""
import argparse
import json
import struct
from pathlib import Path
from al5_segment import START, LENGTH, sha256


def extract(low):
    if len(low) != 0x20000:
        raise ValueError('expected existing low editor dump')
    # Brief indexed extension 0x0206 means D0.W * 2 + displacement 6.
    # Capstone's textual output omits this index scale; verify raw bytes.
    if low[0x2A80:0x2A88] != bytes.fromhex('303b02064efb0002'):
        raise ValueError('unexpected selector dispatch encoding')
    selectors = []
    for selector in range(19):
        displacement = struct.unpack_from('>h', low, 0x2A88+selector*2)[0]
        target = 0x2A88+displacement
        if selector == 0:
            if target != 0x2C84 or low[target:target+2] != bytes.fromhex('7001'):
                raise ValueError('unexpected selector zero rejection')
            selectors.append({'selector': selector, 'branch': f'0x{target:05X}', 'accepted': False})
            continue
        opcode = low[target:target+2]
        if opcode == bytes.fromhex('3a7c'):
            address = struct.unpack_from('>H', low, target+2)[0]
        elif opcode == bytes.fromhex('2a7c'):
            address = struct.unpack_from('>I', low, target+2)[0]
        else:
            raise ValueError('unexpected selector target instruction')
        selectors.append({'selector': selector, 'branch': f'0x{target:05X}',
                          'accepted': True, 'start': f'0x{address:05X}'})
    starts = [int(r['start'], 0) for r in selectors if r['accepted']]
    if starts != sorted(set(starts)):
        raise ValueError('selector starts not strictly increasing')
    candidate_intervals = []
    for i, start in enumerate(starts[:-1]):
        end = starts[i+1]
        overlap = max(0, min(end, START+LENGTH)-max(start, START))
        if overlap:
            candidate_intervals.append({'selector': i+1, 'start': f'0x{start:05X}',
                'end_exclusive_inferred': f'0x{end:05X}', 'calibration_bytes': overlap,
                'outside_calibration_bytes': end-start-overlap})
    return {'source_sha256': sha256(low), 'routine_address': '0x02A58',
        'routine_sha256': sha256(low[0x2A58:0x2C90]),
        'copy_address': '0x02C90', 'copied_to': '0xFF8500', 'copied_bytes': 0x238,
        'selector_table_address': '0x02A88', 'dispatch_index_scale': 2,
        'selector_table_hex': low[0x2A88:0x2AAE].hex(),
        'selectors': selectors,
        'candidate_calibration_intervals': candidate_intervals,
        'geometry_confidence': 'neighbor-start inference only; hardware sector ends unverified',
        'program_count_field_bytes': 1, 'program_unit_bytes': 2,
        'program_count_warning': 'odd counts advance in words and can write one extra byte; zero-count return is uninitialized',
        'readiness_blockers': ['exact hardware geometry', 'diagnostic wire-to-primitive path',
            'session/security', 'full collateral backup and preservation policy',
            'timeout/recovery', 'independent native checksum compensation evidence'],
        'ready_to_flash': False, 'live_write_enabled': False, 'would_send': []}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--low', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    report = extract(args.low.read_bytes())
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
