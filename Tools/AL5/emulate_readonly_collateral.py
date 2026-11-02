"""Complete collateral/marker read using compiled kernel and one persistent synthetic CPU/RAM session."""
import argparse
import hashlib
import json
from pathlib import Path
from emulate_readonly_runtime import Runtime
from emulate_readonly_core import request
from readonly_ram_layout import FIXED

START, END = 0x15FD8, 0x20000


def analyze(code, receipt, low=None):
    from unicorn.m68k_const import UC_M68K_REG_PC
    if low is None:
        r = Runtime(code, receipt)
    else:
        from emulate_readonly_handoff import Handoff
        from emulate_boot_receive_session import frame_events
        r = Handoff(low, code, receipt)
        r.interrupt(frame_events(bytes.fromhex('6d18f034')))
        r.entry_steps = 0
        r.transfer()
        assert r.phase == 'runtime' and r.handoff and len(r.watchdog) == 2
    # Bootstrap owns different RAM before handoff. Compare reader-era canaries
    # against that explicit boundary, rather than inventing all-A5 boot RAM.
    baseline = bytes(r.u.mem_read(0xFF8000, 0x4000))
    frames = []
    for sequence, address in enumerate(range(START, END, 32), 1):
        count = min(32, END-address)
        wire = bytes.fromhex('6d18f0b1')+request(address, count, sequence=sequence)
        r.fifo.extend((0x20, b) for b in wire)
        r.fifo.append((0xE0, 0))
        # Initialization/entry runs once. Resume the real assembly polling loop
        # at its saved PC thereafter; no per-request stack/RAM reset or call stub.
        r.entry_steps = 100
        pc = receipt['entry'] if sequence == 1 and low is None else r.u.reg_read(UC_M68K_REG_PC)
        r.u.emu_start(pc, 0x1000000, count=1000000)
        assert r.entry_steps == -1 and not r.fifo and len(r.frames) == sequence
        reply = r.frames[-1]
        assert reply[:4] == bytes.fromhex('6df018f1')
        assert reply[4:24] == b'ar\x01\0'+wire[8:24]
        assert reply[24:-2] == r.flash[address:address+count]
        frames.append(dict(address=address, count=count, vpw_request_hex=wire.hex(), vpw_reply_hex=reply.hex()))
    r.validate_watchdog()
    assert r.flash_reads == list(range(START, END))  # Exactly once; no calibration/OS overread.
    reconstructed = b''.join(bytes.fromhex(f['vpw_reply_hex'])[24:-2] for f in frames)
    assert reconstructed == r.flash[START:END] and len(reconstructed) == 41000
    assert len(frames) == 1282 and frames[-1]['address'] == 0x1FFF8 and frames[-1]['count'] == 8
    canaries = bytes(r.u.mem_read(0xFF8000, 0x4000))
    checked = 0
    for offset, value in enumerate(canaries):
        a = 0xFF8000+offset
        if r.base <= a < r.end or any(lo <= a < hi for _, lo, hi in FIXED):
            continue
        assert value == baseline[offset]
        checked += 1
    if low is not None:
        from emulate_boot_receive_isr import STACK
        assert hashlib.sha256(bytes(r.u.mem_read(STACK-72, 72))).hexdigest() == r.handoff['abandoned_frame_sha256']
    dependencies = ['emulate_readonly_runtime.py', 'emulate_readonly_core.py', 'readonly_ram_layout.py']
    if low is not None:
        dependencies += ['emulate_readonly_handoff.py', 'emulate_boot_receive_session.py', 'emulate_boot_receive_isr.py', 'emulate_boot_session.py']
    return dict(schema='al5-offline-compiled-collateral-campaign-v1', code_sha256=receipt['code_sha256'],
                generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256={n:hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in dependencies},
                native_boot_handoff=None if low is None else r.handoff,
                low_sha256=None if low is None else hashlib.sha256(low).hexdigest(),
                start=START, end_exclusive=END, bytes=len(reconstructed), request_count=len(frames),
                supplement_sha256=hashlib.sha256(reconstructed).hexdigest(), marker_hex=reconstructed[-2:].hex(),
                frames=frames, actual_assembly_entry_runs=1, persistent_cpu_ram_session=True,
                watchdog_pairs=len(r.watchdog)//2, stack_low=r.stack_low, unowned_canary_bytes_checked=checked,
                flash_writes=0, live_upload_enabled=False, live_execution_enabled=False, live_write_enabled=False,
                hardware_qualified=False, independent_physical_readback=False,
                limits=['All flash contents, FIFO events and MMIO are synthetic; no controller or adapter opened.',
                        'No physical timing, TX completion, watchdog deadline, SRAM ownership or recovery qualification.',
                        'Synthetic marker bytes are retained, not replaced by expected 4AFC.',
                        'Optional boot handoff uses a synthetic external stack/ISR context and FIFO callbacks; boot watchdog stores and RTE are not executed.'])


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build-dir', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--low', type=Path, help='Optional pinned boot evidence for same-CPU native-copy handoff')
    a = p.parse_args()
    if a.output.exists():
        p.error('New output path required')
    result = analyze((a.build_dir/'readonly_kernel.offline.bin').read_bytes(), json.loads((a.build_dir/'build_receipt.json').read_text()),
                     None if a.low is None else a.low.read_bytes())
    with a.output.open('x', encoding='utf-8') as f:
        json.dump(result, f, indent=2)
    print('PASS', result['request_count'], 'persistent compiled-runtime reads;', result['bytes'], 'bytes; marker', result['marker_hex'])
