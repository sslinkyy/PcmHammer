"""Read-only metadata for saved AL5 storage banks; never a recovery/write plan."""
import argparse
import json
from pathlib import Path
from al5_segment import sha256
from checksum import crc16

SIGNATURE = bytes.fromhex('553232ff')
CONTEXT_SIZE = 0x9F2


def inspect(data, origin=0):
    if (origin, len(data)) not in ((0, 0x20000), (0x4000, 0x4000)):
        raise ValueError('require the existing low editor dump or an explicit 0x4000-origin two-bank image')
    banks = []
    for bank in (0x4000, 0x6000):
        offset = bank-origin
        raw = data[offset:offset+0x2000]
        context = raw[0x2A:0x2A+CONTEXT_SIZE]
        marker = int.from_bytes(raw[0x28:0x2A], 'big')
        banks.append({'start': hex(bank), 'candidate_bytes': len(raw),
                      'bank_sha256': sha256(raw), 'header_signature_matches': raw[:4] == SIGNATURE,
                      'generation_word': int.from_bytes(raw[4:6], 'big'),
                      'record_marker': f'0x{marker:04X}',
                      'marker_interpretation': {0xFFAA: 'committed', 0xAA: 'pending', 0: 'zero marker'}.get(marker, 'unclassified'),
                      'context_sha256': sha256(context), 'context_bytes': len(context),
                      'context_crc_stored': f'0x{int.from_bytes(context[-2:], "big"):04X}',
                      'context_crc_computed': f'0x{crc16(context[:-2]):04X}',
                      'context_crc_matches': int.from_bytes(context[-2:], 'big') == crc16(context[:-2])})
    return {'source_sha256': sha256(data), 'source_origin': hex(origin), 'source_bytes': len(data),
            'provenance': 'saved local file; physical/current controller identity not verified',
            'scope': 'Two candidate storage banks, header/marker/hash/context CRC metadata only; no contents exported.',
            'banks': banks, 'live_write_enabled': False, 'ready_to_flash': False,
            'physical_geometry_verified': False, 'current_physical_backup_verified': False,
            'preservation_verified': False, 'would_send': [],
            'note': 'Matching metadata does not prove recovery, current physical preservation or active-bank selection.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--origin', type=lambda value: int(value, 0), default=0)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.source.read_bytes(), args.origin)
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf8')
    print(json.dumps({'banks': [{k: bank[k] for k in ('start', 'header_signature_matches', 'record_marker', 'context_crc_matches')} for bank in result['banks']],
                      'preservation_verified': False, 'ready_to_flash': False}, indent=2))
