"""Drive production C# sequencing with original AL5 instructions and synthetic flash.

No adapter imports, packet transport, physical reset or recovery qualification.
Private candidate/snapshot bytes pass only over owned child-process pipes.
"""
import argparse
import json
from pathlib import Path
import platform
import queue
import subprocess
import threading
import uuid

from al5_segment import START, END, sha256
from emulate_al5_interruptions import InterruptionSession, enter_loader
from emulate_al5_program_session import fixture

CASES = ('complete_dense', 'lost_ack', 'partial_block', 'conflicting_word', 'erase_failure', 'marker_failure')


class Bridge:
    def __init__(self, dll, candidate, backup):
        self.process = subprocess.Popen(['dotnet', str(dll), '--offline-coordinator-bridge'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding='utf-8', bufsize=1)
        self.lines = queue.Queue(maxsize=8)
        self.thread = threading.Thread(target=self.read_output, daemon=True)
        self.thread.start()
        self.attempt = uuid.uuid4().hex
        self.state = None
        try:
            self.hello = self.receive()
            if self.hello.get('protocol') != 'al5-offline-coordinator-v1' or self.hello.get('bridge_sha256') != sha256(dll.read_bytes()):
                raise RuntimeError('bridge identity/protocol mismatch')
            self.request('init', candidate=candidate.hex(), candidate_sha256=sha256(candidate),
                         backup=backup.hex(), backup_sha256=sha256(backup))
        except BaseException:
            self.close()
            raise

    def read_output(self):
        while True:
            line = self.process.stdout.readline(16385)
            try:
                self.lines.put(line, timeout=1)
            except queue.Full:
                return
            if not line or len(line) > 16384:
                return

    def receive(self):
        try:
            line = self.lines.get(timeout=30)
        except queue.Empty as error:
            raise RuntimeError('owned bridge response timed out') from error
        if not line or len(line) > 16384 or not line.endswith('\n'):
            raise RuntimeError('bridge closed or exceeded response budget')
        result = json.loads(line)
        if result.get('live_writes_enabled') is not False:
            raise RuntimeError('bridge did not retain offline gate')
        if 'state' in result and any(result.get(key) is not False for key in
                                    ('automatic_retry_enabled', 'physical_recovery_verified')):
            raise RuntimeError('bridge elevated retry/recovery authority')
        return result

    def request(self, action, *, expect_error=False, **fields):
        message = dict(action=action, attempt=self.attempt)
        if self.state is not None and self.state['pending'] is not None:
            message['sequence'] = self.state['pending']['sequence']
        message.update(fields)
        line = json.dumps(message, separators=(',', ':'))
        if len(line) > 256*1024:
            raise ValueError('bridge request exceeds harness budget')
        self.process.stdin.write(line+'\n')
        self.process.stdin.flush()
        response = self.receive()
        if bool(response.get('error')) != expect_error:
            raise RuntimeError('unexpected bridge result: '+str(response.get('error')))
        self.state = response
        return response

    def close(self):
        try:
            try:
                self.process.stdin.close()
            except BrokenPipeError:
                pass
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        finally:
            self.process.stdout.close()
            self.thread.join(timeout=1)
        if self.process.returncode != 0:
            raise RuntimeError('owned bridge exited unsuccessfully')


def loader_result(bridge, native, operation):
    responses = native['responses']
    if len(responses) > 1:
        raise RuntimeError('operation produced multiple constructed bodies')
    sender = ('TimedOutWithSoftwareReentry' if native['sender_timeout_jumps'] else
              'Returned' if native['native_sender_returns'] == 1 else 'Unobserved')
    count = native.get('modeled_program_words', 0)*2
    return bridge.request('loader', body=responses[0] if responses else None, sender=sender,
        stack_delta=native['stack_delta'], program_start=operation['start'] if count else None,
        program_bytes=count if count else None)


def case(low, code, dll, name):
    native = InterruptionSession(low, code)
    image = fixture()
    backup = native.collateral_before
    bridge = Bridge(dll, image, backup)
    programmed = 0
    last = None
    try:
        # A stale/foreign stream request cannot select an operation in this attempt.
        bridge.request('outcome', outcome='ModelCompleted', attempt=uuid.uuid4().hex, expect_error=True)
        bridge.request('outcome', outcome='ModelCompleted', sequence=2, expect_error=True)
        if bridge.state['observations'] != 0 or bridge.state['pending']['sequence'] != 1:
            raise RuntimeError('rejected bridge request changed coordinator')
        for _ in range(389):
            operation = bridge.state['pending']
            if operation is None:
                break
            phase = operation['phase']
            if phase == 'BootAndLoaderEntry':
                handoff = enter_loader(native)
                if handoff['uploaded_sha256'] != sha256(code):
                    raise RuntimeError('native handoff identity mismatch')
                bridge.request('outcome', outcome='ModelCompleted')
            elif phase == 'ConditionalErase':
                bridge.request('outcome', outcome='ModelCompleted', expect_error=True)
                last = native.erase(patterns=('persistent_toggle', 'stable') if name == 'erase_failure' else ('stable', 'stable'))
                loader_result(bridge, last, operation)
            elif phase in ('CalibrationBlocks', 'CollateralRestoration'):
                start, length = operation['start'], operation['length']
                data, base = (image, START) if phase == 'CalibrationBlocks' else (backup, END)
                if start == START+0x1000:
                    if name == 'lost_ack':
                        native.timeout_at_byte = 6
                    elif name == 'partial_block':
                        native.arm_interruption('after_word', occurrence=4)
                    elif name == 'conflicting_word':
                        # Explicit chosen flash-model fault: requested 0x0001 cannot set this zero bit.
                        native.uc.mem_write(start, b'\x00\x00')
                last = native.program_block(start, data[start-base:start-base+length])
                programmed += last['modeled_program_words']*2
                if last['stop'] == 'modeled_interruption':
                    bridge.request('outcome', outcome='Interrupted')
                else:
                    loader_result(bridge, last, operation)
            elif phase == 'Finalization':
                last = native.finalize(marker_matches=name != 'marker_failure')
                loader_result(bridge, last, operation)
            elif phase == 'IndependentVerification':
                snapshot = native.snapshot().flash
                bridge.request('verify', snapshot=snapshot.hex(), snapshot_sha256='0'*64, expect_error=True)
                bridge.request('verify', snapshot=snapshot.hex(), snapshot_sha256=sha256(snapshot))
            else:
                raise RuntimeError('unknown coordinator phase')
            if bridge.state['state'] == 'Stopped':
                snapshot = native.snapshot().flash
                bridge.request('reconcile', snapshot=snapshot.hex(), snapshot_sha256=sha256(snapshot))
                result = bridge.state['detail']
                expected = dict(lost_ack='SavedRangeMatches', partial_block='ClearOnlyDifferences',
                    conflicting_word='ZeroToOneConflict', erase_failure='ZeroToOneConflict', marker_failure='ClearOnlyDifferences')
                if result['disposition'] != expected[name] or result['retry_enabled'] or result['can_resume']:
                    raise RuntimeError('native memory and coordinator reconciliation disagree')
                if name == 'partial_block' and (result['matching_words'], result['clear_words']) != (4, 124):
                    raise RuntimeError('partial native word coverage disagrees')
                if name == 'conflicting_word' and result['first_conflict'] != START+0x1000:
                    raise RuntimeError('conflicting word address disagrees')
                before = bridge.state['observations']
                bridge.request('outcome', outcome='Cancelled', expect_error=True)
                if bridge.state['state'] != 'Stopped' or bridge.state['observations'] != before:
                    raise RuntimeError('stopped coordinator resumed')
                return dict(name=name, state='Stopped', pending=operation, reconciliation=result,
                    native_response=last['responses'], native_stack_delta=last['stack_delta'],
                    native_sender_returns=last['native_sender_returns'], native_program_bytes=programmed,
                    observations=before, bridge_runtime=bridge.hello['runtime'], stale_and_terminal_requests_rejected=True)
        if name != 'complete_dense' or bridge.state['state'] != 'SavedImageVerified':
            raise RuntimeError('coordinator did not reach expected terminal state')
        if programmed != 98302 or bridge.state['observations'] != 389:
            raise RuntimeError('dense native coverage disagrees')
        verified = bridge.state['detail']
        bridge.request('outcome', outcome='Cancelled', sequence=389, expect_error=True)
        if bridge.state['state'] != 'SavedImageVerified' or bridge.state['observations'] != 389:
            raise RuntimeError('completed coordinator accepted another outcome')
        return dict(name=name, state=bridge.state['state'], native_program_bytes=programmed,
            observations=bridge.state['observations'], verification=verified, bridge_runtime=bridge.hello['runtime'],
            stale_and_terminal_requests_rejected=True)
    finally:
        bridge.close()


def exact_file(path, count):
    with path.open('rb') as stream:
        data = stream.read(count+1)
    if len(data) != count:
        raise ValueError('requires exact pinned native input length')
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('low', 'loader', 'bridge', 'output'):
        parser.add_argument('--'+name, required=True, type=Path)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error('output must be a new metadata report')
    low, code = exact_file(args.low, 0x20000), exact_file(args.loader, 1590)
    cases = []
    for name in CASES:
        cases.append(case(low, code, args.bridge.resolve(), name))
        print('PASS native/C# coordinator '+name, flush=True)
    root = Path(__file__).resolve().parents[2]
    sources = [Path(__file__), *[root/'Apps/PcmLibrary'/name for name in (
        'AL5OfflineProgrammingSession.cs', 'AL5ProgrammingWorkflow.cs', 'AL5LoaderModelReply.cs', 'AL5CalibrationInspection.cs')],
        *[Path(__file__).with_name(name) for name in ('OfflineCoordinatorBridge.cs', 'CalibrationInspectionTest.cs',
          'CalibrationInspectionTest.csproj', 'emulate_al5_program_session.py',
          'emulate_al5_interruptions.py', 'emulate_boot_loader_handoff.py', 'emulate_loader_error_sender.py',
          'emulate_loader_erase_failures.py', 'emulate_loader_entry.py', 'emulate_loader_parser.py',
          'emulate_boot_receive_session.py', 'emulate_boot_receive_isr.py', 'emulate_boot_session.py', 'checksum.py', 'al5_segment.py')]]
    import unicorn
    report = dict(scope='production_csharp_coordinator_with_original_instruction_emulation',
        low_sha256=sha256(low), loader_sha256=sha256(code), bridge_sha256=sha256(args.bridge.read_bytes()),
        source_sha256={str(path.relative_to(root)).replace('\\', '/'): sha256(path.read_bytes()) for path in sources},
        runtime=dict(python=platform.python_version(), unicorn=unicorn.__version__),
        cases=cases, physical_programming_verified=False, physical_readback_verified=False,
        physical_recovery_verified=False, automatic_retry_enabled=False, live_writes_enabled=False,
        ready_to_flash=False, would_send=[], limitations=[
            'Conditional sector map, flash bytes, FIFO readiness, boot entry and fault word values remain synthetic.',
            'Original command/MMIO stores are suppressed. Software reentry and saved image matches do not prove physical recovery.',
            'Boot/loader entry is one explicit host-model milestone; real power-cycle/interrupt behavior is not established.',
            'Pinned LOW is saved editor memory, not an independently acquired current physical backup.'])
    with args.output.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
