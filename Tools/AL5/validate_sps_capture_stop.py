"""Windows offline qualification of the private capture helper; never opens USBPcap.

Requires the existing LocalOnly native fixtures. Every child command uses
--self-test or the fixture-only cleanup test. No hardware launch mode exists.
Evidence directories are exclusive and retained, including failed runs.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid


BASE = Path(__file__).resolve().parents[2] / 'LocalOnly/usb_capture_setup_20261030'
EXPECTED = bytes(i % 251 for i in range(65537))


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def run_stop(mode, invalid=False):
    session = BASE / ('sps_stop_' + uuid.uuid4().hex)
    args = [str(Path(sys.executable).with_name('pythonw.exe')),
            str(BASE / 'usbpcap_pipe_supervisor.py'), '--self-test',
            '--self-test-stop', mode, '--session-dir', str(session),
            '--max-seconds', '3' if mode == 'duration' else '10']
    child = subprocess.Popen(args, creationflags=subprocess.DETACHED_PROCESS)
    if mode == 'external':
        deadline = time.monotonic() + 10
        while not (session / 'surrogate_ready.json').exists():
            if child.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError(f'Fixture not ready; retained evidence at {session}')
            time.sleep(.02)
        request = read(session / 'receipt.json')['stop_request']
        if invalid:
            request['session'] = 'wrong-session'
        with (session / 'stop.json').open('x', encoding='utf-8') as stream:
            json.dump(request, stream)
    # Timeout does not terminate a child or discard its supervisor ownership.
    code = child.wait(timeout=30)
    receipt = read(session / 'receipt.json')
    assert code == (1 if invalid else 0), receipt
    assert receipt['self_test'] and not receipt['capture_started']
    assert not receipt['ownership_retained'] and receipt['exit_code'] == 0
    assert read(session / 'surrogate_result.json') == {'stop_error': 109}
    assert (session / 'capture.pcap').read_bytes() == EXPECTED
    assert all(receipt['cleanup_operations'].values()), receipt
    if invalid:
        assert not receipt['graceful_stop_observed']
        assert 'Stop request does not match' in receipt['error']
    else:
        assert receipt['graceful_stop_observed']
        assert receipt['stop_reason'] == {'ready': 'self_test_ready',
                                          'external': 'stop_file', 'duration': 'duration'}[mode]
        assert receipt['quiet_tail_achieved']
        assert receipt['pipe_bytes_available_before_close'] == 0
    return {'mode': mode, 'invalid_request': invalid, 'passed': True,
            'receipt': str(session / 'receipt.json')}


def main():
    if sys.platform != 'win32':
        raise RuntimeError('Requires Windows native offline fixtures')
    results = [run_stop('ready'), run_stop('external'), run_stop('duration'),
               run_stop('external', invalid=True)]
    # Reuse real native fault tests: they verify byte equality, child exit and
    # closed native handles even when receipt, fsync or file-close operations fail.
    for fault in ('receipt', 'fsync', 'close'):
        name = 'sps_fault_' + uuid.uuid4().hex
        code = ('import test_pipe_cleanup_faults as t; '
                f't.run_case({name!r}, {fault!r})')
        child = subprocess.Popen([str(Path(sys.executable).with_name('pythonw.exe')),
                                  '-c', code], cwd=BASE,
                                 creationflags=subprocess.DETACHED_PROCESS)
        assert child.wait(timeout=30) == 0, name
        result = read(BASE / name / 'fault_test_result.json')
        assert result['passed']
        results.append(result)
    report = BASE / ('sps_stop_validation_' + uuid.uuid4().hex + '.json')
    value = {'passed': True, 'hardware_access': False, 'usbpcap_started': False,
             'fixture_bytes': len(EXPECTED),
             'fixture_sha256': hashlib.sha256(EXPECTED).hexdigest(),
             'sources': {name: hashlib.sha256((BASE / name).read_bytes()).hexdigest()
                         for name in ('usbpcap_pipe_supervisor.py',
                                      'usbpcap_console_supervisor.py', 'receipt_io.py')},
             'cases': results}
    with report.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
    print(f'{len(results)} offline native cases passed; evidence: {report}')


if __name__ == '__main__':
    main()
