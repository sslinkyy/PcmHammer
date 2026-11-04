"""Seal or verify a private offline bench package. Never launches tests or hardware.

Sealing copies the already built application, offline writer tool, explicit evidence
and current source inputs. Verification is a hash check, not a new qualification run.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

SCOPES = ('Apps', 'Kernels', 'Tools/AL5', 'Docs/TCMHammer',
          'Directory.Build.props', 'Directory.Build.targets', 'Directory.Packages.props',
          'NuGet.Config', 'global.json')


def digest(path):
    with path.open('rb') as stream:
        value = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024*1024), b''):
            value.update(chunk)
    return value.hexdigest()


def safe_child(root, relative):
    relative = Path(relative)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('Package paths must stay relative: ' + str(relative))
    path = root / relative
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Path leaves selected root: ' + str(path))
    return path


def source_paths(repo):
    result = subprocess.run(['git', 'ls-files', '-z', '--cached', '--others',
                             '--exclude-standard', '--', *SCOPES], cwd=repo,
                            check=True, capture_output=True).stdout
    return sorted(set(x.decode('utf-8') for x in result.split(b'\0') if x))


def seal(repo, output, app, writer, evidence, capture_dir=None, backup_tool=None):
    repo, output = repo.resolve(), output.resolve()
    if output.exists():
        raise ValueError('Choose a new package directory; existing evidence is retained')
    # Validate caller-selected inputs before creating the exclusive output directory.
    if not (app/'PcmHammer.exe').is_file() or not (writer/'WriteCandidateTool.dll').is_file():
        raise ValueError('Completed application and offline writer builds are required')
    if not evidence or any(not p.is_file() for p in evidence):
        raise ValueError('Explicit existing qualification evidence files required')
    if backup_tool is not None and not (backup_tool/'SavedBackupTool.dll').is_file():
        raise ValueError('Completed saved backup tool build required')
    builds = [('application', app), ('offline_writer', writer)]
    if backup_tool is not None:
        builds.append(('offline_backup', backup_tool))
    for _, source in builds:
        if output.is_relative_to(source.resolve()) or source.resolve().is_relative_to(output):
            raise ValueError('Package and input directories must not contain each other')
    paths = source_paths(repo)
    output.mkdir(parents=True, exist_ok=False)
    originals = {}

    def copy(source, relative):
        target = safe_child(output, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise ValueError('Duplicate package output: ' + str(relative))
        before = digest(source)
        shutil.copyfile(source, target)
        if digest(source) != before or digest(target) != before:
            raise ValueError('Input changed while freezing: ' + str(source))
        originals[str(relative).replace('\\', '/')] = dict(selected=str(source), resolved=str(source.resolve()), sha256=before)

    for relative in paths:
        copy(safe_child(repo, relative), Path('source')/relative)
    for label, folder in builds:
        for source in sorted(folder.rglob('*')):
            if source.is_file():
                if not source.resolve().is_relative_to(folder.resolve()):
                    raise ValueError('Build symlink leaves selected directory')
                copy(source, Path(label)/source.relative_to(folder))
    for i, source in enumerate(evidence):
        copy(source, Path('evidence')/f'{i:02d}_{source.name}')
    if capture_dir is not None:
        for name in ('usbpcap_pipe_supervisor.py', 'usbpcap_console_supervisor.py', 'receipt_io.py'):
            copy(capture_dir/name, Path('capture')/name)
    manifest = dict(schema='al5-offline-bench-package-v1', created_utc=datetime.now(timezone.utc).isoformat(),
                    source_root=str(repo), files=originals, source_inputs=paths,
                    boundary='Frozen offline writer candidate and read-only application. Not a live AL5 writer.',
                    hardware_access=False, live_upload_enabled=False, live_execution_enabled=False,
                    live_write_enabled=False, ready_to_flash=False,
                    remaining_hardware_gates=['Spare identity and correct bench wiring', 'Fresh security and programming entry',
                        'Independent preservation baseline and physical readback', 'Recovery qualification'])
    (output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
    return manifest


def drift_group(relative):
    if relative.startswith('Apps/') or relative in SCOPES[4:]:
        return 'application'
    if relative.startswith('Kernels/'):
        return 'kernel'
    if relative.startswith('Tools/'):
        return 'tools'
    if relative.startswith('Docs/'):
        return 'documentation'
    # Unknown input categories must not silently bypass application checks.
    return 'application'


def verify(package, repo=None, application_only=False):
    if application_only and repo is None:
        raise ValueError('Application input verification requires --repo')
    manifest = json.loads((package/'manifest.json').read_text(encoding='utf-8'))
    if manifest.get('schema') != 'al5-offline-bench-package-v1' or not manifest.get('files'):
        raise ValueError('Not a sealed AL5 bench package')
    for flag in ('hardware_access', 'live_upload_enabled', 'live_execution_enabled', 'live_write_enabled', 'ready_to_flash'):
        if manifest.get(flag) is not False:
            raise ValueError('Unexpected package authority flag: ' + flag)
    mismatches = []
    for name, item in manifest['files'].items():
        path = safe_child(package, name)
        if not path.is_file() or digest(path) != item['sha256']:
            mismatches.append(name)
    expected = set(manifest['files']) | {'manifest.json'}
    actual = {p.relative_to(package).as_posix() for p in package.rglob('*') if p.is_file()}
    unexpected = sorted(actual-expected)
    drift = []
    if repo is not None:
        current = set(source_paths(repo))
        old = set(manifest['source_inputs'])
        drift.extend(sorted(current ^ old))
        for relative in sorted(current & old):
            path = safe_child(repo, relative)
            if not path.is_file() or digest(path) != manifest['files']['source/'+relative]['sha256']:
                drift.append(relative)
    groups = {name: [] for name in ('application', 'kernel', 'tools', 'documentation')}
    for relative in drift:
        groups[drift_group(relative)].append(relative)
    integrity = not mismatches and not unexpected
    relevant_drift = groups['application'] if application_only else drift
    return dict(verified=integrity and not relevant_drift, files_checked=len(manifest['files']),
                verification_scope='application' if application_only else 'complete',
                package_integrity_verified=integrity,
                application_inputs_match=(not groups['application']) if repo is not None else None,
                source_snapshot_matches=(not drift) if repo is not None else None,
                source_drift_by_group=groups,
                mismatches=mismatches, unexpected_files=unexpected, source_drift=drift,
                tests_rerun=False, hardware_access=False, live_write_enabled=False, ready_to_flash=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    make = sub.add_parser('seal')
    for name in ('repo', 'output', 'app', 'writer'):
        make.add_argument('--'+name, type=Path, required=True)
    make.add_argument('--evidence', type=Path, action='append', required=True)
    make.add_argument('--capture-dir', type=Path)
    make.add_argument('--backup-tool', type=Path)
    check = sub.add_parser('verify')
    check.add_argument('--package', type=Path, required=True)
    check.add_argument('--repo', type=Path)
    check.add_argument('--application-only', action='store_true',
                       help='Check package integrity and application source inputs; report other source drift separately')
    args = parser.parse_args()
    if args.operation == 'seal':
        value = seal(args.repo, args.output, args.app, args.writer, args.evidence, args.capture_dir, args.backup_tool)
        print('Sealed', len(value['files']), 'files; private/offline package only.')
    else:
        value = verify(args.package, args.repo, args.application_only)
        print(json.dumps(value, indent=2))
        raise SystemExit(0 if value['verified'] else 1)
