"""Audit imported AL5 XDF against local stock/PPEI segments and native export."""
import argparse
import ast
import json
import operator
import re
import struct
import xml.etree.ElementTree as ET
from pathlib import Path
from al5_segment import START, LENGTH, sha256, validate, word_sum, diff_ranges


def equation(text, value):
    # Only arithmetic on X; never execute XDF expressions as Python code.
    ops = {ast.Add: operator.add, ast.Sub: operator.sub,
           ast.Mult: operator.mul, ast.Div: operator.truediv}
    def visit(node):
        if isinstance(node, ast.Constant) and type(node.value) in (int, float):
            return node.value
        if isinstance(node, ast.Name) and node.id == 'X':
            return value
        if isinstance(node, ast.BinOp) and type(node.op) in ops:
            return ops[type(node.op)](visit(node.left), visit(node.right))
        raise ValueError(f'unsupported XDF math: {text}')
    return visit(ast.parse(text, mode='eval').body)


def decode(item, data):
    container = item if item.tag == 'XDFCONSTANT' else item.find("XDFAXIS[@id='z']")
    embedded = container.find('EMBEDDEDDATA')
    if 'mmedaddress' not in embedded.attrib:
        return None
    bits = int(embedded.get('mmedelementsizebits'))
    width = bits // 8
    rows = int(embedded.get('mmedrowcount', '1'))
    cols = int(embedded.get('mmedcolcount', '1'))
    offset = int(embedded.get('mmedaddress'), 0) - START
    if bits not in (8, 16, 32) or offset < 0 or offset + rows * cols * width > LENGTH:
        raise ValueError('XDF data out of segment or unsupported size')
    if int(embedded.get('mmedmajorstridebits', '0')) or int(embedded.get('mmedminorstridebits', '0')):
        raise ValueError('non-contiguous XDF data needs explicit stride support')
    signed = bool(int(embedded.get('mmedtypeflags', '0'), 0) & 1)
    values = [int.from_bytes(data[offset+i*width:offset+(i+1)*width], 'big', signed=signed)
              for i in range(rows * cols)]
    return [equation(container.find('MATH').get('equation'), v) for v in values]


def expected(item, native):
    title = item.findtext('title')
    match = re.match(r'(D\d+|H\d+)\b', title)
    if not match or match[1] not in native:
        return None
    entry = native[match[1]]
    cells = entry['cells']
    if not all(isinstance(v, (int, float)) for row in cells for v in row):
        return None  # text/enum encoding needs separate evidence
    if len(cells) == 1 and len(cells[0]) == 1:
        return [cells[0][0]]
    pattern = re.search(r'Pattern ([A-H])', title)
    tps = re.search(r' - (\d+)% TPS', title)
    native_column = re.search(r' - Native Column (\d+):', title)
    if native_column:
        col = int(native_column[1])
    elif pattern:
        col = ord(pattern[1]) - ord('A')
    elif tps:
        col = [0, 20, 40, 50, 60, 70, 80, 90, 100].index(int(tps[1]))
    elif len(cells[0]) == 1:
        col = 0
    else:
        return None
    return [row[col] for row in cells]


def audit(xdf, stock, ppei, export):
    root = ET.parse(xdf).getroot()
    base = root.find('XDFHEADER/BASEOFFSET')
    errors = []
    if base.get('offset') != str(START) or base.get('subtract') != '1':
        errors.append('XDF base offset mismatch')
    native = {c['id']: c for c in json.loads(Path(export).read_text())['calibrations']}
    result = {'xdf_sha256': sha256(Path(xdf).read_bytes()),
              'native_export_sha256': sha256(Path(export).read_bytes()), 'items': []}
    for name, data in [('stock', stock), ('ppei', ppei)]:
        errors.extend(f'{name}: {e}' for e in validate(data))
        if len(data) != LENGTH:
            raise ValueError('wrong segment length')
        result[name] = {'sha256': sha256(data), 'length': len(data),
                        'be16_sum': f'0x{word_sum(data):04X}',
                        'native_field': data[-4:].hex().upper()}
        if word_sum(data):
            errors.append(f'{name}: BE16 invariant failed')
    categories = {int(c.get('index'), 0)+1 for c in root.findall('XDFHEADER/CATEGORY')}
    ids = set()
    for item in root:
        if item.tag not in ('XDFCONSTANT', 'XDFTABLE'):
            continue
        uid = item.get('uniqueid')
        if uid in ids:
            errors.append(f'duplicate uniqueid {uid}')
        ids.add(uid)
        title = item.findtext('title')
        for cat in item.findall('CATEGORYMEM'):
            if int(cat.get('category'), 0) not in categories:
                errors.append(f'{title}: category does not exist')
        values = decode(item, stock)
        wanted = expected(item, native)
        record = {'title': title, 'stock': values, 'ppei': decode(item, ppei),
                  'native_comparison': 'not_numeric_or_not_resolved'}
        if wanted is not None and values is not None:
            error = max((abs(a-b) for a, b in zip(values, wanted)), default=0)
            record.update(native_comparison='pass' if len(values) == len(wanted) and error < .001 else 'FAIL',
                          max_abs_error=error, compared_cells=len(wanted))
            if record['native_comparison'] == 'FAIL':
                errors.append(f'{title}: native export mismatch')
        result['items'].append(record)
    result['diff_ranges'] = diff_ranges(stock, ppei)
    result['changed_bytes'] = sum(r['length'] for r in result['diff_ranges'])
    represented = {re.match(r'(D\d+|H\d+)\b', i['title'])[1] for i in result['items']
                   if re.match(r'(D\d+|H\d+)\b', i['title'])}
    result['coverage'] = {'native_definition_count': len(native),
                          'represented_ids': sorted(represented),
                          'absent_ids': sorted(set(native)-represented),
                          'note': 'Representation includes partial and research entries; it does not imply full validation.'}
    result['errors'] = errors
    result['status'] = 'pass' if not errors else 'FAIL'
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('xdf', 'stock', 'ppei', 'export', 'output'):
        parser.add_argument('--' + option, required=True, type=Path)
    args = parser.parse_args()
    report = audit(args.xdf, args.stock.read_bytes(), args.ppei.read_bytes(), args.export)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'items': len(report['items']),
                      'native_comparisons': sum(i['native_comparison'] == 'pass' for i in report['items']),
                      'changed_bytes': report['changed_bytes'], 'diff_ranges': len(report['diff_ranges']),
                      'errors': report['errors']}, indent=2))
    raise SystemExit(bool(report['errors']))
