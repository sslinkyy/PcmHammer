"""Trace resident bank reads through native application dequeue/lookup/descriptor before programming entry.

Only pinned firmware, synthetic RX/RAM state and intercepted subsystems are used.
Storage primitives are stopped before execution. No hardware or uploader exists.
"""
import argparse
import hashlib
import json
from pathlib import Path
from emulate_application_reset_chain import PreparationStorageBoundary
from emulate_application_boot import BASE
from emulate_mode23_coverage import RANGES as READ_RANGES

DISPATCH_RANGES = ((0xA4A38, 0xA4C9E), (0xBA824, 0xBA8C4),
                   (0x23694, 0x2377A), (0x23C9C, 0x23D14), (0x23E88, 0x23F28),
                   (0xC17E4, 0xC180C), (0x70E34, 0x70E56))


def digest(data):
    return hashlib.sha256(data).hexdigest()


class PreEntryBanks(PreparationStorageBoundary):
    def __init__(self, low, high, guard_flags=0x20):
        super().__init__(low, high)
        self.uc.mem_write(BASE + 0x1DBE, bytes([guard_flags]))
        self.ranges.extend(DISPATCH_RANGES + READ_RANGES)
        for start, end in DISPATCH_RANGES + READ_RANGES:
            self.uc.mem_write(start, self.data[start:end])
        self.uc.mem_write(0x99A00, self.data[0x99A00:0x99AF5])
        self.uc.mem_write(0xC591E, self.data[0xC591E:0xC5930])
        self.uc.mem_write(0x6DDBA, self.data[0x6DDBA:0x6DDC0])
        self.uc.mem_write(0x6DF50, self.data[0x6DF50:0x6DF56])
        self.entries = []
        self.flash_stores = []

    def hook(self, machine, pc, size, user_data):
        if pc in (0xA4A38, 0xBA824, 0xB1970, 0xBFDA0, 0xBE6D0, 0x5BAB8, 0x226F0):
            self.entries.append(pc)
        super().hook(machine, pc, size, user_data)

    def write_hook(self, machine, access, address, size, value, user_data):
        if address < 0x100000:
            self.flash_stores.append(dict(address=address, size=size, value=value))
            raise ValueError('Native execution attempted a flash store')
        super().write_hook(machine, access, address, size, value, user_data)

    def dispatch(self, frame, offset=1):
        if offset not in (1, 10):
            raise ValueError('Declared synthetic ring slots only')
        # Explicit model input: one RX record in a fresh synthetic ring. This is
        # not a live drain/fence or proof that previous responses cannot requeue.
        self.uc.mem_write(BASE + 0xEB6, bytes(54))
        record = bytes([len(frame)]) + frame
        self.uc.mem_write(BASE + 0xEB6 + offset, record)
        self.uc.mem_write(BASE + 0xEFF, bytes([offset]))
        self.uc.mem_write(BASE + 0xEFE, bytes([offset + len(record)]))
        self.uc.mem_write(BASE + 0xF00, b'\x01')
        self.entries = []
        self.primitive_boundary = None
        observed = self.snapshot(self.run(0xA4A38, b''))
        observed.update(entries=[hex(a) for a in self.entries],
                        primitive_boundary=self.primitive_boundary,
                        bank_sha256=digest(bytes(self.uc.mem_read(0x4000, 0x4000))),
                        banks_unchanged=bytes(self.uc.mem_read(0x4000, 0x4000)) == self.data[0x4000:0x8000],
                        response_body=bytes(self.uc.mem_read(BASE + 0x2269, 6)).hex(),
                        mode23_pending=bytes(self.uc.mem_read(BASE + 0xF3F, 1)).hex(),
                        flash_stores=list(self.flash_stores))
        return observed

    def format_read(self):
        self.uc.mem_write(BASE + 0x16E9, b'\x00')
        self.call_local(0xC17E4, [75])
        self.call_local(0x23C9C, [0x6DDBA, 1])
        count=bytes(self.uc.mem_read(BASE + 0x16E9, 1))[0]
        return bytes(self.uc.mem_read(BASE + 0x16DE, count))

    def call_local(self, pc, arguments):
        return self.run(pc, b''.join(v.to_bytes(4, 'big') for v in arguments))


def analyze(low, high, output, complete=False):
    output.mkdir(parents=True, exist_ok=False)
    cases=[]
    for guard in (0, 0x20, 0x60):
        for offset in (1, 10):
            for address in (0x4000, 0x5FFC, 0x6000, 0x7FFC):
                p=PreEntryBanks(low, high, guard)
                request=bytes.fromhex('6d18f023')+address.to_bytes(3, 'big')+b'\x01'
                observed=p.dispatch(request, offset)
                expected=(address & 0xFFFF).to_bytes(2, 'big')+p.data[address:address+4]
                assert observed['response_body']==expected.hex() and observed['mode23_pending']=='10'
                assert '0xbfda0' in observed['entries'] and '0xb1970' in observed['entries']
                assert not observed['storage_calls'] and not observed['preparation_entry_count']
                assert observed['banks_unchanged'] and observed['marker']=='0x0' and not observed['flash_stores']
                reply=p.format_read()
                assert reply==bytes.fromhex('6cf01863')+expected
                cases.append(dict(case='resident_bank_read',guard_flags=guard,offset=offset,address=address,
                                  reply_hex=reply.hex(),observed=observed))
    # Native control: the same dispatcher reaches the preparation storage boundary
    # for an unlocked programming request, unlike the resident read.
    p=PreEntryBanks(low, high, 0)
    control=p.dispatch(bytes.fromhex('6d18f034'))
    assert '0xbe6d0' in control['entries'] and '0x5bab8' in control['entries']
    assert control['primitive_boundary']['entry']==0x22B18 and control['banks_unchanged']
    cases.append(dict(case='programming_entry_stops_before_erase',observed=control))
    campaign=None
    if complete:
        p=PreEntryBanks(low, high, 0x20);readback=bytearray()
        with (output/'resident_frames.jsonl').open('x', encoding='utf-8') as stream:
            for address in range(0x4000,0x8000,4):
                request=bytes.fromhex('6d18f023')+address.to_bytes(3,'big')+b'\x01'
                observed=p.dispatch(request);reply=p.format_read()
                assert observed['response_body']==((address & 0xFFFF).to_bytes(2,'big')+p.data[address:address+4]).hex()
                assert not observed['storage_calls'] and not observed['preparation_entry_count'] and observed['banks_unchanged']
                readback.extend(reply[6:])
                stream.write(json.dumps(dict(address=address,vpw_request_hex=request.hex(),vpw_reply_hex=reply.hex()))+'\n')
        assert bytes(readback)==low[0x4000:0x8000]
        (output/'banks.historical_readback.bin').write_bytes(readback)
        campaign=dict(requests=4096,bytes=len(readback),sha256=digest(readback),
                      unique_low16_echoes=4096,physical_readback_verified=False)
    report=dict(schema='al5-offline-resident-preentry-banks-v1',cases=cases,campaign=campaign,
                low_sha256=digest(low),high_sha256=digest(high),
                code_sha256={hex(a):digest((low+high)[a:b]) for a,b in DISPATCH_RANGES+READ_RANGES},
                sources={n:digest(Path(__file__).with_name(n).read_bytes()) for n in
                         ('trace_preentry_banks.py','emulate_application_reset_chain.py','emulate_receive_preparation.py',
                          'emulate_application_authorization.py','emulate_application_boot.py')},
                hardware_access=False,live_read_enabled=False,live_upload_enabled=False,live_execution_enabled=False,
                live_write_enabled=False,pre_entry_physical_acquisition_verified=False,
                limits=['Pinned historical firmware and bank fixture; synthetic ring, guard, application context and MMIO.',
                        'One synthetic RX record supplied per invocation, not a physical session boundary or transport completion.',
                        'Native dequeue, service lookup, descriptor callback, read handler and formatter execute.',
                        'Programming control stops before the erase primitive; subsystem helpers remain intercepted.',
                        'No IRQ/FIFO, physical response scheduling, peripheral timing or live read is qualified.'])
    (output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--full-reference',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--complete',action='store_true')
    args=parser.parse_args();image=args.full_reference.read_bytes()
    result=analyze(image[:0x20000],image[0x20000:],args.output,args.complete)
    print('PASS',len(result['cases']),'native pre-entry cases; live operations disabled')
