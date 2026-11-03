"""Execute the pinned resident handler for both banks offline; no adapter access."""
import argparse
import hashlib
import json
from pathlib import Path
from audit_sps_read_regions import OS_HASH
from emulate_mode23_coverage import Probe


def run(module, output):
    if len(module) != 679828 or hashlib.sha256(module).hexdigest() != OS_HASH:
        raise ValueError('Exact saved SPS OS required')
    output.mkdir(parents=True, exist_ok=False)
    # Bank-specific synthetic bytes expose offset mistakes; these are not original data.
    fixture = bytes((i ^ (i >> 7) ^ 0xA7) & 255 for i in range(0x4000))
    probe = Probe(module, source='sps_os')
    probe.u.mem_write(0x4000, fixture)
    with (output / 'frames.jsonl').open('x', encoding='utf-8') as stream:
        for offset in range(0, len(fixture), 4):
            address = 0x4000 + offset
            if not probe.permission(address):
                raise ValueError('Resident permission denied at ' + hex(address))
            observed = probe.handler(address)
            expected = (address & 0xFFFF).to_bytes(2, 'big') + fixture[offset:offset+4]
            if (observed['negative_reasons'] or observed['pending_flag'] != '10'
                    or observed['response_body'] != expected.hex()):
                raise ValueError('Native bank handler mismatch at ' + hex(address))
            json.dump(dict(address=address,
                           vpw_request_hex=(bytes.fromhex('6d18f023') + address.to_bytes(3, 'big') + b'\x01').hex(),
                           vpw_reply_hex=(bytes.fromhex('6cf01863') + expected).hex()), stream)
            stream.write('\n')
    (output / 'fixture.offline.bin').write_bytes(fixture)
    result = dict(schema='al5-offline-persistent-banks-v1', complete=True, bytes=len(fixture),
                  requests=len(fixture)//4, sps_os_sha256=OS_HASH,
                  fixture_sha256=hashlib.sha256(fixture).hexdigest(),
                  sources={name: hashlib.sha256((Path(__file__).parent/name).read_bytes()).hexdigest()
                           for name in ('rehearse_persistent_banks.py', 'emulate_mode23_coverage.py',
                                        'audit_sps_read_regions.py')},
                  physical_readback_verified=False, pre_entry_acquisition_proven=False,
                  freshness_proven=False, live_read_enabled=False, live_upload_enabled=False,
                  live_execution_enabled=False, live_write_enabled=False,
                  limits=['Synthetic fixture, isolated native handler and permission checks only.',
                          'Dispatcher, security, receive scheduling and physical session boundary are not exercised.',
                          'The low-16 echo cannot distinguish an old reply from another bank with the same echo.'])
    with (output / 'result.json').open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sps-os', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.sps_os.read_bytes(), args.output_dir)
    print('PASS', result['requests'], 'native saved-bank handler cases; physical boundary unqualified.')
