"""Observe stale response RAM at the pinned native reset-to-application boundary, offline only."""
import argparse
import hashlib
import json
from pathlib import Path
from emulate_flash_fault_recovery import experiment

FIELDS={'pending':(0xF3F,1),'tracked_index':(0xF46,2),'body':(0x2269,6),
        'rx_length':(0xF2C,2),'tx_count':(0x16E9,1),'ring':(0xEB6,54)}


def analyze(image):
    cases=[]
    for status,pattern in ((0x80,0xA5),(0x40,0x5A)):
        ram=bytearray([pattern]*0x3800);ram[:2]=bytes(2)
        ram[0xF3F]=0x10;ram[0xF46:0xF48]=(75).to_bytes(2,'big')
        ram[0x2269:0x226F]=bytes.fromhex('400011223344')
        ram[0xF2C:0xF2E]=(8).to_bytes(2,'big');ram[0x16E9]=10
        context=experiment(image[:0x20000],image[0x20000:],reset_status=status,retained_marker=0,
                           initial_ram=bytes(ram),probe_boot_request=False,retain_context=True)
        before={name:bytes(ram[a:a+n]).hex() for name,(a,n) in FIELDS.items()}
        after={name:context.cpu.mem_read(0xFF8000+a,n).hex() for name,(a,n) in FIELDS.items()}
        assert context.report['stop']=='application_transfer_boundary'
        assert all(after[name]=='aa'*n for name,(a,n) in FIELDS.items())
        assert bytes(context.cpu.mem_read(0x4000,0x4000))==image[0x4000:0x8000]
        cases.append(dict(reset_status=status,initial_pattern=pattern,before=before,at_application_boundary=after,
                          banks_unchanged=True,native_boot=context.report,application_startup_executed=False))
    return dict(schema='al5-offline-reset-response-state-v1',cases=cases,
                input_sha256=hashlib.sha256(image).hexdigest(),
                sources={name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in
                         ('trace_resident_startup_state.py','emulate_flash_fault_recovery.py','emulate_calibration_marker.py')},
                hardware_access=False,physical_reset_status_semantics_verified=False,session_boundary_proven=False,
                live_read_enabled=False,live_upload_enabled=False,live_execution_enabled=False,live_write_enabled=False,
                limits=['Exact pinned firmware, synthetic reset/status and dirty RAM, declared 24-bit alias model.',
                        'Boot stops before application startup; the separate CRT trace is not a continuous CPU/peripheral handoff.',
                        'Reset/status values are not identified as physical cold/warm-reset causes.',
                        'No adapter/USB drain, real reset retention or physical first-response freshness is proven.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--full-reference',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('New output file required')
    result=analyze(args.full_reference.read_bytes())
    result['input_reference']=dict(selected=str(args.full_reference),resolved=str(args.full_reference.resolve()))
    with args.output.open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2)
    print('PASS two native reset-to-application RAM witnesses; physical freshness unqualified')
