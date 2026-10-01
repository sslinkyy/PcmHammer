"""Read-only decode of explicitly bounded local firmware windows."""
import argparse
import json
from pathlib import Path
from al5_segment import sha256


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--low', type=Path, required=True)
    p.add_argument('--high', type=Path, required=True)
    p.add_argument('--range', action='append', required=True, help='start:end-exclusive hex addresses')
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    low, high = args.low.read_bytes(), args.high.read_bytes()
    if len(low) != 0x20000 or len(high) != 0xE0000:
        raise ValueError('unexpected source dump size')
    data = low+high
    from capstone import Cs, CS_ARCH_M68K, CS_MODE_M68K_020, CS_MODE_BIG_ENDIAN
    cs = Cs(CS_ARCH_M68K, CS_MODE_M68K_020 | CS_MODE_BIG_ENDIAN)
    windows = []
    for value in args.range:
        start, end = (int(a, 0) for a in value.split(':'))
        if start & 1 or end <= start or end > len(data) or end-start > 0x2000:
            raise ValueError('invalid or excessive decode window')
        instructions = [{'address': f'0x{i.address:05X}', 'bytes': i.bytes.hex(),
                         'mnemonic': i.mnemonic, 'operands': i.op_str}
                        for i in cs.disasm(data[start:end], start)]
        windows.append({'start': f'0x{start:05X}', 'end_exclusive': f'0x{end:05X}',
                        'instructions': instructions})
        for i in instructions:
            print(i['address'], i['mnemonic'], i['operands'])
    args.output.write_text(json.dumps({'low_sha256': sha256(low), 'high_sha256': sha256(high),
                                       'windows': windows}, indent=2)+'\n')
