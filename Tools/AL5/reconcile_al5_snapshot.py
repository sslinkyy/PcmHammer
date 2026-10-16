"""Reconcile saved AL5 flash-model/readback files; never execute a retry or erase.

File identity is pinned, but file contents do not establish current physical state.
The 0x8000..0x20000 scope follows the conditional erase model, not proven geometry.
"""
import argparse
import json
from pathlib import Path

from al5_segment import START, END, LENGTH, validate, sha256
from checksum import checksum_valid

MARKER = 0x1FFFE
FLASH_LENGTH = 0x20000-START
COLLATERAL_LENGTH = MARKER-END


def compare_words(observed, desired, address):
    """Bit compatibility is arithmetic only; it does not authorize programming."""
    if len(observed) != len(desired) or len(desired) % 2:
        raise ValueError('comparison requires equally sized complete words')
    counts = dict(matching_words=0, additional_clear_words=0, requires_set_words=0)
    first = None
    for offset in range(0, len(desired), 2):
        actual = int.from_bytes(observed[offset:offset+2], 'big')
        target = int.from_bytes(desired[offset:offset+2], 'big')
        if actual == target:
            key = 'matching_words'
        elif actual & target == target:
            key = 'additional_clear_words'
        else:
            key = 'requires_set_words'
            if first is None:
                first = hex(address+offset)
        counts[key] += 1
    return dict(counts, exact_match=observed == desired,
                first_requires_set_address=first,
                classification='exact' if observed == desired else
                'requires_zero_to_one' if counts['requires_set_words'] else
                'one_to_zero_compatible_only')


def reconcile(candidate, snapshot=None, collateral_backup=None):
    if type(candidate) is not bytes or len(candidate) != LENGTH:
        raise ValueError('requires exact calibration bytes')
    errors = validate(candidate)
    if errors or not checksum_valid(candidate):
        raise ValueError('candidate must pass layout and native checksum validation')
    if snapshot is not None and (type(snapshot) is not bytes or len(snapshot) != FLASH_LENGTH):
        raise ValueError('snapshot must be absent or exactly 98304 bytes at 0x8000')
    if collateral_backup is not None and (type(collateral_backup) is not bytes or
                                         len(collateral_backup) != COLLATERAL_LENGTH):
        raise ValueError('backup must be absent or exactly 40998 bytes at 0x15fd8')
    calibration = collateral = marker = None
    if snapshot is not None:
        calibration = compare_words(snapshot[:LENGTH], candidate, START)
        marker = compare_words(snapshot[-2:], bytes.fromhex('4afc'), MARKER)
        if collateral_backup is not None:
            collateral = compare_words(snapshot[LENGTH:-2], collateral_backup, END)
    comparisons = (calibration, collateral, marker)
    complete = all(item is not None and item['exact_match'] for item in comparisons)
    conflict = any(item is not None and item['requires_set_words'] for item in comparisons)
    required = ['establish_current_controller_identity_and_fresh_complete_readback',
                'requalify_loader_session_and_stack_state',
                'prove_physical_programming_and_interrupted_flash_recovery']
    if collateral_backup is None:
        required.append('obtain_independent_pre_erase_collateral_baseline')
    if conflict:
        required.append('resolve_zero_to_one_conflict_before_any_retry')
    return dict(schema_version=1, scope='offline_saved_snapshot_reconciliation',
        conditional_erase_range=dict(start=hex(START), end_exclusive='0x20000',
                                    physical_geometry_verified=False),
        candidate_sha256=sha256(candidate),
        snapshot_sha256=sha256(snapshot) if snapshot is not None else None,
        collateral_backup_sha256=sha256(collateral_backup) if collateral_backup is not None else None,
        calibration=calibration, collateral=collateral, completion_marker=marker,
        exact_saved_image_match=complete, observed_zero_to_one_conflict=conflict,
        operation_outcome='unknown_without_current_physical_evidence',
        loader_session_state='unknown', required_evidence=required,
        physical_readback_verified=False, recovery_verified=False,
        automatic_retry_enabled=False, live_writes_enabled=False, ready_to_flash=False,
        would_send=[])


def pinned_file(path, digest):
    # Bound reads before allocation; all supported files are smaller than 0x20000.
    with path.open('rb') as stream:
        data = stream.read(0x20001)
    if len(data) > 0x20000:
        raise ValueError('input exceeds supported offline range')
    if sha256(data) != digest:
        raise ValueError('input SHA256 does not match caller pin')
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('candidate', 'snapshot', 'collateral-backup'):
        parser.add_argument('--'+name, type=Path, required=name == 'candidate')
        parser.add_argument('--'+name+'-sha256', required=name == 'candidate')
    parser.add_argument('--output', type=Path, required=True, help='new JSON report only')
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error('output already exists')
    values, sources = {}, {}
    try:
        for name in ('candidate', 'snapshot', 'collateral_backup'):
            path, digest = getattr(args, name), getattr(args, name+'_sha256')
            if (path is None) != (digest is None):
                raise ValueError(name+' requires both path and SHA256')
            values[name] = pinned_file(path, digest) if path is not None else None
            sources[name] = str(path.resolve()) if path is not None else None
        result = reconcile(**values)
        result['input_paths'] = sources
        result['implementation_sha256'] = sha256(Path(__file__).read_bytes())
        with args.output.open('x', encoding='utf-8', newline='\n') as stream:
            stream.write(json.dumps(result, indent=2)+'\n')
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
