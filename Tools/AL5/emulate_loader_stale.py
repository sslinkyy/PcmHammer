"""Trace short synthetic frames into saved stale dispatch bytes; no handler execution."""
import argparse
import json
from pathlib import Path
from al5_segment import sha256
from emulate_loader_receive import experiment, frame_events
from emulate_loader_parser import RX


def run(code):
    erased_prefix = bytes.fromhex('6d18f036ee')
    cases = [
        ('short_clean_buffer', frame_events(b'\x6d\x18'), b'', 'receive_boundary'),
        ('two_bytes_stale_erase', frame_events(b'\x6d\x18'), erased_prefix, 'erase_route_trap'),
        ('three_bytes_stale_erase', frame_events(b'\x6d\x18\xf0'), erased_prefix, 'erase_route_trap'),
        ('four_bytes_stale_erase', frame_events(b'\x6d\x18\xf0\x36'), erased_prefix, 'erase_route_trap'),
        ('two_bytes_stale_finalize', frame_events(b'\x6d\x18'), bytes.fromhex('6d18f036ff'), 'finalize_route_trap'),
        ('two_bytes_stale_block', frame_events(b'\x6d\x18'), bytes.fromhex('6d18f03600'), 'block_parser_trap'),
        ('two_bytes_stale_exit', frame_events(b'\x6d\x18'), bytes.fromhex('6d18f03c55'), 'shared_exit_trap'),
        ('rejected_frame_leaves_erase_tail', frame_events(erased_prefix, flags=0x40) + frame_events(b'\x6d\x18'), b'', 'erase_route_trap'),
    ]
    records = []
    for name, events, stale, expected in cases:
        observed = experiment(code, events, stale_prefix=stale, trace_dispatch=True)
        records.append({'case': name, 'expected_stop': expected, 'observed': observed,
                        'pass': observed['stop'] == expected})
    root = Path(__file__).resolve().parents[2]
    static_path = root / 'Docs/AL5/CAPTURED_LOADER_STATIC.json'
    static = json.loads(static_path.read_text())
    return {'payload_sha256': sha256(code), 'generator_sha256': sha256(Path(__file__).read_bytes()),
            'receive_generator_sha256': sha256((root / 'Tools/AL5/emulate_loader_receive.py').read_bytes()),
            'static_evidence_sha256': sha256(static_path.read_bytes()),
            'address_observations': {
                'load_address': static['load_address'], 'payload_bytes': static['payload_bytes'],
                'receive_effective_address': hex(RX), 'initial_stack_address': '0xffa7fe',
                'conditional_receive_low24': hex(RX & 0xFFFFFF),
                'distance_to_initial_stack_if_low24_aliases': 0xFFA7FE - (RX & 0xFFFFFF),
                'physical_aliasing_verified': False, 'physical_receive_capacity_verified': False},
            'scope': 'Synthetic short completed frames with modeled zero completion flags and stale RAM. Saved priority/service/subtype dispatch instructions execute; every command handler and shared exit is trapped.',
            'limits': 'Physical FIFO may impose additional length/CRC constraints. No flash/reset/session operation executes. Conditional low24 address arithmetic is not proof of physical RAM mapping or safe capacity; emulator address regions remain separate.',
            'cases': records, 'all_pass': all(c['pass'] for c in records),
            'ready_to_flash': False, 'live_write_enabled': False, 'erase_scope': None, 'would_send': []}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--loader', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    report = run(args.loader.read_bytes())
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'cases': len(report['cases']), 'all_pass': report['all_pass']}))
    raise SystemExit(0 if report['all_pass'] else 1)
