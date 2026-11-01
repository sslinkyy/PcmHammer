"""Pinned native boot transfer into independent reader; synthetic ISR/FIFO only.

No device, upload API, physical interrupt, boot watchdog or exception return.
"""
import argparse
import hashlib
import json
from pathlib import Path
from emulate_readonly_runtime import Runtime
from emulate_boot_session import EXPECTED_LOW
from emulate_boot_receive_session import executable_span, frame_events, WATCHDOG_STORES
from emulate_boot_receive_isr import START, RTE, STACK


class Handoff(Runtime):
    def __init__(self, low, code, receipt):
        if len(low) != 0x20000 or hashlib.sha256(low).hexdigest() != EXPECTED_LOW:
            raise ValueError('Unrecognized boot evidence')
        self.phase = 'boot'
        super().__init__(code, receipt)
        from unicorn import UC_PROT_READ, UC_PROT_EXEC
        from unicorn.m68k_const import UC_M68K_REG_A7
        self.low, self.code = low, code
        self.u.mem_write(0, low[:0x5000])
        self.u.mem_protect(0, 0x5000, UC_PROT_READ | UC_PROT_EXEC)
        self.u.mem_map(0x200000, 0x10000)
        self.u.reg_write(UC_M68K_REG_A7, STACK)
        self.u.mem_write(self.base, bytes(len(code)))  # No preloaded executable.
        self.u.mem_write(0xFF8010, b'\x01')  # Synthetic boot ISR enabled context.
        self.u.mem_write(0xFF8160, bytes(0x2A))
        self.events, self.copied, self.responses = [], set(), []
        self.boundary = None
        self.handoff = None
        self.boot_watchdog_skips = 0

    def callback_return(self, target):
        from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_PC
        sp = self.u.reg_read(UC_M68K_REG_A7)
        if not STACK-512 <= sp <= STACK-4:
            raise ValueError('Boot callback stack outside test ownership')
        ret = int.from_bytes(self.u.mem_read(sp, 4), 'big')
        bsr = self.low[ret-4:ret-2] == b'\x61\x00' and ret-2+int.from_bytes(self.low[ret-2:ret], 'big', signed=True) == target
        jsr = self.low[ret-6:ret-4] == b'\x4e\xb9' and int.from_bytes(self.low[ret-4:ret], 'big') == target
        if not executable_span(ret, 2) or not (bsr or jsr):
            raise ValueError('Unexpected native callback caller')
        self.u.reg_write(UC_M68K_REG_A7, sp+4)
        self.u.reg_write(UC_M68K_REG_PC, ret)

    def instruction(self, u, pc, size, unused):
        if self.phase == 'runtime':
            return super().instruction(u, pc, size, unused)
        from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_PC, UC_M68K_REG_D0
        if pc == self.base:
            sp = u.reg_read(UC_M68K_REG_A7)
            if bytes(u.mem_read(self.base, len(self.code))) != self.code or len(self.copied) != len(self.code):
                raise ValueError('Native copy did not supply the complete runtime')
            if sp != STACK-72 or int.from_bytes(u.mem_read(sp, 4), 'big') != 0x33B8 or self.events not in ([], [(0, 0)]):
                raise ValueError('Unexpected handoff stack/FIFO context')
            self.handoff = dict(incoming_sp=sp, pending_return=0x33B8, stack_delta=-72,
                                native_copied_bytes=len(self.copied), code_preloaded=False,
                                abandoned_frame_sha256=hashlib.sha256(bytes(u.mem_read(sp, 72))).hexdigest())
            self.phase = 'runtime'
            return super().instruction(u, pc, size, unused)
        if pc == RTE:
            self.boundary = 'before_rte'
            u.emu_stop()
        elif pc in WATCHDOG_STORES:
            self.boot_watchdog_skips += 1
            u.reg_write(UC_M68K_REG_PC, WATCHDOG_STORES[pc])
        elif pc == 0x2E8C:
            if not self.events:
                raise ValueError('Synthetic boot FIFO exhausted')
            status, value = self.events.pop(0)
            u.reg_write(UC_M68K_REG_D0, status << 8 | value)
            self.callback_return(pc)
        elif pc == 0x2ED0:
            count = int.from_bytes(u.mem_read(0xFF8180, 2), 'big')
            if not 0 < count <= 11:
                raise ValueError('Boot response bounds')
            self.responses.append(bytes(u.mem_read(0xFF8175, count)).hex())
            self.callback_return(pc)
        elif pc == 0x2D98:
            self.callback_return(pc)
        elif not executable_span(pc, size):
            raise ValueError('Unexpected boot PC '+hex(pc))

    def write(self, u, access, address, size, value, unused):
        if self.phase == 'runtime':
            return super().write(u, access, address, size, value, unused)
        if STACK-512 <= address and address+size <= STACK or 0xFF8160 <= address and address+size <= 0xFF818A:
            return
        if self.base <= address and address+size <= self.end and size == 1:
            self.copied.add(address-self.base)
            return
        raise ValueError('Boot write outside declared ownership '+hex(address))

    def read(self, u, access, address, size, value, unused):
        if self.phase == 'runtime':
            return super().read(u, access, address, size, value, unused)
        if any(a <= address and address+size <= b for a, b in
               ((0, 0x5000), (STACK-512, STACK), (0xFF8010, 0xFF8011), (0xFF8160, 0xFF818A), (self.base, self.end))):
            return
        raise ValueError('Boot read outside declared ownership '+hex(address))

    def interrupt(self, events):
        from unicorn.m68k_const import UC_M68K_REG_A7
        if self.phase != 'boot' or self.u.reg_read(UC_M68K_REG_A7) != STACK:
            raise ValueError('Boot entry unavailable')
        self.events, self.boundary = list(events), None
        self.u.emu_start(START, 0x1000000, count=1000000)
        if self.phase == 'boot' and (self.boundary != 'before_rte' or self.u.reg_read(UC_M68K_REG_A7) != STACK):
            raise ValueError('Boot budget/boundary failure')

    def transfer(self, *, execute=True, bad_checksum=False):
        self.copied.clear()
        tail = bytes([0x80 if execute else 0])+len(self.code).to_bytes(2, 'big')+self.base.to_bytes(3, 'big')+self.code
        checksum = ((sum(tail)+int(bad_checksum)) & 65535).to_bytes(2, 'big')
        self.interrupt(tuple((0x20, b) for b in bytes.fromhex('6d18f036')+tail+checksum)+((0xA0, 0), (0, 0)))


def analyze(low, code, receipt):
    from unicorn.m68k_const import UC_M68K_REG_A7, UC_M68K_REG_SR
    cases = []
    for name in ('armed_entry', 'unarmed_rejected_after_copy', 'bad_checksum_rejected_after_copy', 'copy_without_execute', 'checksum_retry'):
        r = Handoff(low, code, receipt)
        if name != 'unarmed_rejected_after_copy':
            r.interrupt(frame_events(bytes.fromhex('6d18f034')))
        if name == 'checksum_retry':
            r.transfer(bad_checksum=True)
            assert r.phase == 'boot' and not r.watchdog and r.responses[-1] == '6cf018768077'
        r.entry_steps = 2
        r.transfer(execute=name != 'copy_without_execute', bad_checksum=name == 'bad_checksum_rejected_after_copy')
        assert len(r.copied) == len(code) and bytes(r.u.mem_read(r.base, len(code))) == code
        entered = name in ('armed_entry', 'checksum_retry')
        assert (r.phase == 'runtime') == entered
        if entered:
            assert r.handoff and r.u.reg_read(UC_M68K_REG_SR) & 0x700 == 0x700
            assert 0xFFA700 <= r.u.reg_read(UC_M68K_REG_A7) < 0xFFA800
            assert int.from_bytes(r.u.mem_read(STACK-72, 4), 'big') == 0x33B8
            assert hashlib.sha256(bytes(r.u.mem_read(STACK-72, 72))).hexdigest() == r.handoff['abandoned_frame_sha256']
            r.validate_watchdog()
            assert len(r.watchdog) == 6 and not r.tx and not r.flash_reads
        else:
            assert not r.handoff and not r.watchdog and not r.tx
            expected = {'unarmed_rejected_after_copy':'6cf0187f3680048eff9022',
                        'bad_checksum_rejected_after_copy':'6cf018768077',
                        'copy_without_execute':'6cf018760073'}
            assert r.responses[-1] == expected[name], r.responses
        cases.append(dict(case=name, handoff=r.handoff, responses=r.responses, copied_bytes=len(r.copied),
                          runtime_entered=entered, final_sp=r.u.reg_read(UC_M68K_REG_A7),
                          suppressed_boot_watchdog_stores=r.boot_watchdog_skips))
    return dict(schema='al5-offline-readonly-handoff-v1', low_sha256=EXPECTED_LOW, code_sha256=receipt['code_sha256'], cases=cases,
                generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256={n:hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in
                                   ('emulate_readonly_runtime.py','emulate_boot_session.py','emulate_boot_receive_session.py',
                                    'emulate_boot_receive_isr.py','readonly_ram_layout.py')},
                actual_interrupt_delivered=False, physical_ram_ownership_proven=False, physical_fifo_qualified=False,
                live_upload_enabled=False, live_execution_enabled=False, live_write_enabled=False,
                limits=['Synthetic external boot stack and ISR-enabled context; no physical startup/IRQ/exception frame.',
                        'Boot FIFO/sender/flush callbacks are synthetic and boot watchdog stores suppressed.',
                        'Runtime resets SP and abandons pending native frames; no return/restore path is implemented.',
                        'Copy before checksum/arming rejection is not rollback or permission to upload.'])


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--low', type=Path, required=True)
    p.add_argument('--build-dir', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    result = analyze(a.low.read_bytes(), (a.build_dir/'readonly_kernel.offline.bin').read_bytes(),
                     json.loads((a.build_dir/'build_receipt.json').read_text()))
    with a.output.open('x', encoding='utf-8') as f:
        json.dump(result, f, indent=2)
    print('PASS', len(result['cases']), 'native boot/read-only runtime handoff cases')
