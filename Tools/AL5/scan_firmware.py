"""Offline literal references and tentative M68K decode windows (requires capstone)."""
import argparse
import json
import struct
from pathlib import Path
from al5_segment import sha256


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--low', type=Path, required=True)
    p.add_argument('--high', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    low, high = args.low.read_bytes(), args.high.read_bytes()
    if len(low) != 0x20000 or len(high) != 0xE0000:
        raise ValueError('expected existing 0-1FFFF and 20000-FFFFF editor dumps')
    data = low + high
    from capstone import Cs, CS_ARCH_M68K, CS_MODE_M68K_020, CS_MODE_BIG_ENDIAN
    decoder = Cs(CS_ARCH_M68K, CS_MODE_M68K_020 | CS_MODE_BIG_ENDIAN)
    result = {'source': 'EFILive editor memory; not a proven full physical flash image',
              'low_sha256': sha256(low), 'high_sha256': sha256(high),
              'decode_note': 'Tentative M68K-020 windows from even alignment; literals can be data. '
                             'No control-flow or routine reachability proof.', 'references': []}
    for address in (0x8000, 0x15FD4, 0x15FD8, 0xDFD8):
        needle = struct.pack('>I', address)
        for offset in range(0, len(data)-3, 2):
            if data[offset:offset+4] != needle:
                continue
            start = max(0, offset - 16)
            decoded = [{'address': f'0x{i.address:05X}', 'bytes': i.bytes.hex(),
                        'mnemonic': i.mnemonic, 'operands': i.op_str}
                       for i in decoder.disasm(data[start:offset+32], start)]
            result['references'].append({'literal': f'0x{address:05X}', 'offset': f'0x{offset:05X}',
                                         'window': data[start:offset+32].hex(), 'decode': decoded})
    result['routine_windows'] = []
    for start, end in ((0xA95D0, 0xA960C), (0xA960C, 0xA9710), (0x4FFD0, 0x50040)):
        result['routine_windows'].append({'start': f'0x{start:05X}', 'end_exclusive': f'0x{end:05X}',
            'decode': [{'address': f'0x{i.address:05X}', 'bytes': i.bytes.hex(),
                        'mnemonic': i.mnemonic, 'operands': i.op_str}
                       for i in decoder.disasm(data[start:end], start)]})
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('Literal references:', len(result['references']))
    for r in result['routine_windows']:
        print('Window', r['start'])
        for i in r['decode']:
            print(i['address'], i['mnemonic'], i['operands'])
