"""Hash-pin supplied offline artifacts; conditional coverage never enables writes."""
import argparse
import json
from pathlib import Path
import re
from al5_segment import sha256, LENGTH
from write_plan import plan


def bind(name, data, expected_hash, length, start):
    errors = []
    missing = data is None and expected_hash is None
    if not missing:
        if data is None or expected_hash is None:
            errors.append(f'{name}: bytes and expected hash must be supplied together')
        if data is not None and len(data) != length:
            errors.append(f'{name}: expected exactly {length} bytes')
        if expected_hash is not None and not re.fullmatch('[0-9a-fA-F]{64}', expected_hash):
            errors.append(f'{name}: expected hash must be 64 hex characters')
        elif data is not None and expected_hash is not None and sha256(data) != expected_hash.lower():
            errors.append(f'{name}: pinned hash mismatch')
    return {'name': name, 'start': hex(start), 'end_exclusive': hex(start + length),
            'expected_bytes': length, 'supplied_bytes': len(data) if data is not None else None,
            'sha256': sha256(data) if data is not None else None,
            'expected_sha256': expected_hash.lower() if expected_hash else None,
            'missing': missing, 'input_errors': errors,
            'offline_binding_valid': not missing and not errors,
            'current_physical_provenance_verified': False}


def manifest(current, candidate, expected_current_hash, expected_candidate_hash,
             *, collateral=None, expected_collateral_hash=None,
             persistent_banks=None, expected_persistent_hash=None):
    logical_plan = plan(current, candidate, expected_current_hash, 'AL5', 15184109)
    components = [bind('current_calibration', current, expected_current_hash, LENGTH, 0x8000),
                  bind('candidate_calibration', candidate, expected_candidate_hash, LENGTH, 0x8000),
                  bind('conditional_sector_collateral', collateral, expected_collateral_hash, 41000, 0x15FD8),
                  bind('persistent_bank_region', persistent_banks, expected_persistent_hash, 0x4000, 0x4000)]
    errors = sorted(set(logical_plan['input_errors'] + [e for c in components for e in c['input_errors']]))
    root = Path(__file__).resolve().parents[2]
    geometry = (root / 'Docs/AL5/LOADER_GEOMETRY_FINALIZATION.json').read_bytes()
    return {'mode': 'offline_artifact_binding', 'controller': 'AL5', 'os_id': 15184109,
            'input_errors': errors, 'components': components,
            'missing_components': [c['name'] for c in components if c['missing']],
            'all_required_components_hash_bound': all(c['offline_binding_valid'] for c in components) and not errors,
            'geometry_evidence': 'Docs/AL5/LOADER_GEOMETRY_FINALIZATION.json',
            'geometry_evidence_sha256': sha256(geometry),
            'conditional_erase_span_bytes': 98304, 'conditional_collateral_bytes': 41000,
            'completion_marker_inside_collateral': {'address': '0x1fffe', 'planned_handling_verified': False},
            'physical_chip_geometry_verified': False, 'current_backups_verified': False,
            'collateral_preservation_verified': False, 'persistent_bank_preservation_verified': False,
            'physical_recovery_verified': False, 'ready_to_flash': False,
            'live_write_enabled': False, 'erase_scope': None,
            'would_send': [], 'erase_packets': [], 'program_packets': [],
            'limits': 'Hash binding proves file identity only. Regions derive from conditional saved geometry and storage analysis. Supplied bytes are not verified current physical backups. Finalization may modify the collateral marker; application preparation may modify persistent banks. No restoration or erase/program protocol is specified.'}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('current', 'candidate'):
        p.add_argument('--' + name, type=Path, required=True)
        p.add_argument('--expected-' + name + '-sha256', required=True)
    for name in ('collateral', 'persistent-banks'):
        p.add_argument('--' + name, type=Path)
        p.add_argument('--expected-' + name + '-sha256')
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if args.output.resolve() in {f.resolve() for f in (args.current, args.candidate, args.collateral, args.persistent_banks) if f}:
        p.error('output must not overwrite an input artifact')
    result = manifest(args.current.read_bytes(), args.candidate.read_bytes(),
                      args.expected_current_sha256, args.expected_candidate_sha256,
                      collateral=args.collateral.read_bytes() if args.collateral else None,
                      expected_collateral_hash=args.expected_collateral_sha256,
                      persistent_banks=args.persistent_banks.read_bytes() if args.persistent_banks else None,
                      expected_persistent_hash=args.expected_persistent_banks_sha256)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'missing_components': result['missing_components'], 'input_errors': result['input_errors'], 'ready_to_flash': False}))
    raise SystemExit(2)
