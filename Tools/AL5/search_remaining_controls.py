"""Record remaining scalar/throttle candidates without promoting them into an XDF."""
import argparse
import json
import struct
from pathlib import Path
from al5_segment import occurrences, sha256, validate


def scalar_family(stock, native, ids, raw_units):
    raw = [round(native[i]['cells'][0][0]/unit) for i, unit in zip(ids, raw_units)]
    errors = [abs(native[i]['cells'][0][0]-count*unit)
              for i, count, unit in zip(ids, raw, raw_units)]
    if max(errors) >= .001:
        raise ValueError('candidate scalar scaling exceeds tolerance')
    needle = struct.pack('>'+str(len(raw))+'H', *raw)
    return {'ids': ids, 'raw_units': raw_units, 'raw_counts': raw,
            'max_abs_errors': errors, 'layout_hypothesis': 'consecutive BE16 scalars, no count headers',
            'start_candidates': [f'0x{a:05X}' for a in occurrences(stock, needle)],
            'status': 'candidate only; firmware references or differential identity proof required'}


def throttle_candidates(stock, native):
    results, families = [], []
    for ident in ('D5073', 'D5074', 'D5075'):
        c = native[ident]
        family = b''
        for col in range(c['column_count']):
            raw = [round(row[col]*655.36) for row in c['cells']]
            error = max(abs(row[col]-value/655.36) for row, value in zip(c['cells'], raw))
            if error >= .001:
                raise ValueError('throttle scaling exceeds tolerance')
            family += struct.pack('>H', c['row_count'])+struct.pack('>'+str(len(raw))+'H', *raw)
        families.append(family)
        results.append({'id': ident, 'rows': c['rows'], 'columns': c['columns'],
            'layout_hypothesis': 'five consecutive 0x0011-header BE16 column records',
            'math_hypothesis': 'X*100/65536',
            'header_candidates': [f'0x{a:05X}' for a in occurrences(stock, family)],
            'status': 'ambiguous complete values; not promoted'})
    joint = bytes.fromhex('4e714e71').join(families)
    return {'tables': results,
            'joint_layout_hypothesis': 'native mode order with four-byte 4E714E71 separators',
            'joint_start_candidates': [f'0x{a:05X}' for a in occurrences(stock, joint)],
            'warning': 'A unique joint context does not independently prove mode or gear ordering. '
                       'Normal and tow/haul native values are identical.'}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('stock', 'export', 'firmware-high', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    args = p.parse_args()
    stock, export_bytes = args.stock.read_bytes(), args.export.read_bytes()
    if validate(stock):
        raise ValueError('invalid stock segment anchors')
    native = {c['id']: c for c in json.loads(export_bytes.decode('cp1252'))['calibrations']}
    high = args.firmware_high.read_bytes()
    if len(high) != 0xE0000:
        raise ValueError('unexpected saved high editor dump size')
    groups = [(['D5042', 'D5043', 'D5044', 'D5045'], [1/4]*4),
              (['D5055', 'D5056'], [1/128]*2),
              (['D5057', 'D5058'], [1/8]*2),
              (['D5061', 'H0103', 'H0137'], [1/8192, 1/8192, native['H0137']['limits']['hard_max']/65535])]
    result = {'stock_sha256': sha256(stock), 'native_export_sha256': sha256(export_bytes),
              'firmware_high_sha256': sha256(high),
              'native_export_encoding': 'cp1252',
              'confidence': 'explicit packing/scaling hypotheses; no new XDF assignments',
              'scalar_families': [scalar_family(stock, native, ids, units) for ids, units in groups],
              'throttle_release': throttle_candidates(stock, native),
              'deferred_other_ids': ['D5053', 'D5054', 'D5062', 'D5063', 'D5183', 'D5197', 'H0105', 'H0136'],
              'deferral_note': 'enum encoding, repeated sentinel values or speedo-field identity unresolved'}
    references = []
    for group in result['scalar_families']:
        for start in group['start_candidates']:
            for col, ident in enumerate(group['ids']):
                address = int(start, 0)+col*2
                needle = struct.pack('>I', address)
                hits = [i for i in range(0, len(high)-3, 2) if high[i:i+4] == needle]
                references.append({'id_hint': ident, 'candidate_address': f'0x{address:05X}',
                    'literal_offsets': [f'0x{i+0x20000:05X}' for i in hits],
                    'note': 'even-aligned literal hits, not exhaustive decoded xrefs; indirect references may exist'})
    result['scalar_reference_candidates'] = references
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    for g in result['scalar_families']:
        print(g['ids'], g['start_candidates'])
    print('Throttle joint context:', result['throttle_release']['joint_start_candidates'])
