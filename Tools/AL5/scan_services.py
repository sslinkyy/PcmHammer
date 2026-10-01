"""Offline diagnostic-service comparison candidates; matches are not protocol proof."""
import argparse
import json
from pathlib import Path
from al5_segment import sha256


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('low', 'high', 'output'):
        p.add_argument('--'+name, required=True, type=Path)
    args = p.parse_args()
    low, high = args.low.read_bytes(), args.high.read_bytes()
    if len(low) != 0x20000 or len(high) != 0xE0000:
        raise ValueError('unexpected existing editor dump sizes')
    data = low+high
    from capstone import Cs, CS_ARCH_M68K, CS_MODE_M68K_020, CS_MODE_BIG_ENDIAN
    cs = Cs(CS_ARCH_M68K, CS_MODE_M68K_020 | CS_MODE_BIG_ENDIAN)
    services = {0x10, 0x20, 0x23, 0x27, 0x28, 0x34, 0x35, 0x36, 0x37, 0x3B, 0x3C}
    records = []
    for address in range(0, len(data)-8, 2):
        opcode = int.from_bytes(data[address:address+2], 'big')
        if opcode & 0xFF00 != 0x0C00:
            continue  # CMP immediate only; not a complete service-dispatch search
        size = (opcode >> 6) & 3
        width = 4 if size == 2 else 2
        value = int.from_bytes(data[address+2:address+2+width], 'big')
        if value not in services:
            continue
        ins = next(cs.disasm(data[address:address+12], address, count=1), None)
        if ins is None or not ins.mnemonic.startswith('cmp'):
            continue
        window = [{'address': f'0x{i.address:05X}', 'bytes': i.bytes.hex(),
                    'mnemonic': i.mnemonic, 'operands': i.op_str}
                   for i in cs.disasm(data[address:address+100], address)]
        records.append({'service_value': f'0x{value:02X}', 'address': f'0x{address:05X}',
                        'instruction': ins.mnemonic+' '+ins.op_str, 'forward_window': window})
    result = {'low_sha256': sha256(low), 'high_sha256': sha256(high),
              'warning': 'Even-aligned literal CMP candidates, including data false positives. '
                         'Requires control-flow and buffer-source tracing before service attribution.',
              'candidates': records}
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print('Candidates:', len(records))
    for r in records:
        if int(r['address'], 0) < 0x8000 or r['service_value'] in ('0x23', '0x27', '0x34', '0x36'):
            print(r['address'], r['service_value'], r['instruction'],
                  '; '.join(i['mnemonic']+' '+i['operands'] for i in r['forward_window'][:6]))
