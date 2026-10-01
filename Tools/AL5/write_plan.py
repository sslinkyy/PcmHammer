"""AL5 file-only write readiness report. Always blocked; never emits/programs packets."""
import argparse
import csv
import json
import re
from pathlib import Path
from al5_segment import START, END, LENGTH, CHECKSUM, validate, sha256, word_sum, diff_ranges
from checksum import checksum_valid

DEFAULT_TARGETS = Path(__file__).resolve().parents[2] / 'Docs/AL5/TunerPro/AL5_FIRST_VEHICLE_TEST_1-2_MINIMAL_v0_2_TARGETS.csv'
RESIDENT_EVIDENCE = Path(__file__).resolve().parents[2] / 'Docs/AL5/RESIDENT_FLASH_INVENTORY.json'
BOOT_SESSION_EVIDENCE = Path(__file__).resolve().parents[2] / 'Docs/AL5/BOOT_SESSION_EMULATION.json'
APPLICATION_BOOT_EVIDENCE = Path(__file__).resolve().parents[2] / 'Docs/AL5/APPLICATION_BOOT_EMULATION.json'
AUTHORIZATION_EVIDENCE = Path(__file__).resolve().parents[2] / 'Docs/AL5/APPLICATION_AUTHORIZATION_EMULATION.json'
PREPARATION_EVIDENCE = Path(__file__).resolve().parents[2] / 'Docs/AL5/RECEIVE_PREPARATION_EMULATION.json'


def preparation_assessment():
    evidence_bytes = PREPARATION_EVIDENCE.read_bytes()
    evidence = json.loads(evidence_bytes)
    return {'evidence': 'Docs/AL5/RECEIVE_PREPARATION_EMULATION.json',
            'evidence_sha256': sha256(evidence_bytes),
            'offline_cases_pass': evidence['all_pass'],
            'scope': evidence['scope'],
            'storage_call_entry': '0x226F0',
            'storage_source_argument': '0xFF8140',
            'candidate_storage_bank_starts': ['0x04000', '0x06000'],
            'storage_geometry_verified': False,
            'current_storage_backup_supplied': False,
            'storage_implementation_executed': False,
            'calibration_only_backup_establishes_preservation': False,
            'note': 'Application boot preparation reaches a flash-storage caller. '
                    'Its storage implementation was intercepted, not executed. '
                    'Bank starts are static evidence, not executable erase scope.'}


def boot_loader_assessment():
    evidence_bytes = BOOT_SESSION_EVIDENCE.read_bytes()
    evidence = json.loads(evidence_bytes)
    application_bytes = APPLICATION_BOOT_EVIDENCE.read_bytes()
    application = json.loads(application_bytes)
    authorization_bytes = AUTHORIZATION_EVIDENCE.read_bytes()
    authorization = json.loads(authorization_bytes)
    return {'evidence': 'Docs/AL5/BOOT_SESSION_EMULATION.json',
            'evidence_sha256': sha256(evidence_bytes),
            'firmware_source_sha256': evidence['low_sha256'],
            'code_sha256': evidence['code_sha256'],
            'scope': evidence['scope'],
            'offline_cases_pass': evidence['all_pass'],
            'application_transition_evidence': {
                'evidence': 'Docs/AL5/APPLICATION_BOOT_EMULATION.json',
                'evidence_sha256': sha256(application_bytes),
                'offline_cases_pass': application['all_pass'],
                'scope': application['scope'],
                'reset_hardware_verified': False,
                'startup_response_proves_upload_armed': False},
            'application_authorization_evidence': {
                'evidence': 'Docs/AL5/APPLICATION_AUTHORIZATION_EMULATION.json',
                'evidence_sha256': sha256(authorization_bytes),
                'offline_cases_pass': authorization['all_pass'],
                'scope': authorization['scope'],
                'live_key_submission_verified': False,
                'lockout_duration_verified': False},
            'application_entry_verified': False,
            'live_session_authorized': False,
            'note': 'Boot arming and RAM-transfer sequences are exercised offline. '
                    'They do not prove entry from the running application or a flash protocol.'}


def preservation_assessment():
    evidence_bytes = RESIDENT_EVIDENCE.read_bytes()
    evidence = json.loads(evidence_bytes)
    intervals = evidence['candidate_calibration_intervals']
    return {'evidence': 'Docs/AL5/RESIDENT_FLASH_INVENTORY.json',
            'evidence_sha256': sha256(evidence_bytes),
            'firmware_source_sha256': evidence['source_sha256'],
            'confidence': evidence['geometry_confidence'],
            'candidate_intervals': intervals,
            'outside_calibration_bytes_inferred': sum(i['outside_calibration_bytes'] for i in intervals),
            'current_collateral_backup_supplied': False,
            'preservation_verified': False,
            'note': 'Saved editor evidence is not a current physical backup. '
                    'These inferred intervals must not become executable erase scope.'}


def plan(current, candidate, expected_hash, controller, os_id):
    errors = []
    if not re.fullmatch('[0-9a-fA-F]{64}', expected_hash):
        errors.append('expected current SHA256 must be 64 hex characters')
    if controller != 'AL5' or os_id != 15184109:
        errors.append('controller/OS context must be AL5 / 15184109')
    if sha256(current) != expected_hash.lower():
        errors.append('current read does not match expected source SHA256')
    for name, data in [('current', current), ('candidate', candidate)]:
        errors.extend(f'{name}: {e}' for e in validate(data))
        if len(data) == LENGTH and word_sum(data):
            errors.append(f'{name}: BE16 word-sum invariant failed')
        if len(data) == LENGTH and not checksum_valid(data):
            errors.append(f'{name}: native CRC16/compensation checksum invalid')
    ranges = diff_ranges(current, candidate) if len(current) == len(candidate) == LENGTH else []
    allowed = set()
    target_words = {}
    allowed.update(range(CHECKSUM, END))  # accepted only if native checksum validates
    with DEFAULT_TARGETS.open(newline='') as stream:
        for row in csv.DictReader(stream):
            address = int(row['TCM_Address'], 0)
            if address < START or address + 2 > CHECKSUM:
                raise ValueError('target sheet address outside writable calibration data')
            allowed.update((address, address+1))
            target_words[address] = (int(row['Raw_Before'], 0), int(row['Raw_Target'], 0))
    if ranges:
        for r in ranges:
            for address in range(int(r['start'], 0), int(r['end_inclusive'], 0)+1):
                if address not in allowed:
                    errors.append(f'change outside minimal first-test allowlist at 0x{address:05X}')
        for address, (before, target) in target_words.items():
            offset = address - START
            if current[offset:offset+2] != candidate[offset:offset+2]:
                if int.from_bytes(current[offset:offset+2], 'big') != before:
                    errors.append(f'changed source word is not OEM stock at 0x{address:05X}')
                if int.from_bytes(candidate[offset:offset+2], 'big') != target:
                    errors.append(f'candidate word is not the supplied target at 0x{address:05X}')
    return {'mode': 'offline_dry_run', 'live_write_enabled': False, 'ready_to_flash': False,
            'context': {'controller': controller, 'os_id': os_id, 'provenance': 'caller-supplied; no live identity verification'},
            'current_sha256': sha256(current), 'candidate_sha256': sha256(candidate),
            'input_errors': sorted(set(errors)),
            'native_checksum_valid': {'current': checksum_valid(current), 'candidate': checksum_valid(candidate)},
            'blockers': ['AL5 session/loader/erase/program/verify/recovery protocol is unresolved.',
                         'Exact erase geometry and current collateral backup/preservation are unverified.',
                         'Application boot preparation can reach persistent-storage updates outside the calibration; preservation is unresolved.',
                         'Live AL5 writing is unconditionally disabled.'],
            'preservation_assessment': preservation_assessment(),
            'boot_loader_assessment': boot_loader_assessment(),
            'boot_preparation_assessment': preparation_assessment(),
            'diff_ranges': ranges,
            'requested_calibration_range': {'start': '0x08000', 'end_inclusive': '0x15FD7'},
            'erase_scope': None, 'program_block_size': None,
            'would_send': [], 'erase_packets': [], 'program_packets': [],
            'plan_note': 'No packets can be specified honestly until the offline protocol is proven. '
                         'The diff ranges are logical requested edits, not an erase/program transaction.'}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--current', required=True, type=Path)
    p.add_argument('--candidate', required=True, type=Path)
    p.add_argument('--expected-current-sha256', required=True)
    p.add_argument('--controller', required=True)
    p.add_argument('--os-id', required=True, type=int)
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    result = plan(args.current.read_bytes(), args.candidate.read_bytes(),
                  args.expected_current_sha256, args.controller, args.os_id)
    report = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(report)
    print(report)
    raise SystemExit(2)  # Blocked readiness, including unchanged known-valid inputs.
