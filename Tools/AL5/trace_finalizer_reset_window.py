"""Native finalizer through its marker/park tail; all flash/MMIO stores suppressed."""
import argparse
import hashlib
import json
from pathlib import Path
from emulate_loader_finalize import experiment,fixture


def analyze(code,full_reference=None):
    if full_reference is not None:
        from emulate_calibration_marker import validate_source
        validate_source(full_reference[:0x20000],full_reference[0x20000:])
    good=fixture() if full_reference is None else full_reference[0x8000:0x15FD8]
    bad=bytearray(good);bad[0x100]^=1
    cases=[]
    for name,image,options in [
        ('success_to_reset_store',good,dict(reset_tail='trap_store')),
        ('modeled_marker_reaches_park',good,dict(reset_tail='model_marker_store')),
        ('bad_sum_also_reaches_reset_store',bytes(bad),dict(reset_tail='trap_store')),
        ('marker_failure_returns_to_receive',good,dict(readback='mismatch',reset_tail='trap_store')),
    ]:
        cases.append(dict(case=name,**experiment(code,image,**options)))
    boot=[]
    if full_reference is not None:
        from emulate_flash_fault_recovery import experiment as boot_experiment
        retained=next(row for row in cases if row['case']=='modeled_marker_reaches_park')['observed']['modeled_retained_marker']
        for status in (0,0x20,0x40,0x80):
            boot.append(boot_experiment(full_reference[:0x20000],full_reference[0x20000:],reset_status=status,retained_marker=int(retained,16),probe_boot_request=False))
    return dict(schema='al5-finalizer-reset-window-v1',cases=cases,conditional_boot_cases=boot,
        conditional_boot_uses_separate_contexts=True,full_reference_sha256=None if full_reference is None else hashlib.sha256(full_reference).hexdigest(),
        loader_sha256=hashlib.sha256(code).hexdigest(),
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependencies_sha256={name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                             for name in ('emulate_loader_finalize.py','emulate_loader_parser.py','al5_segment.py','checksum.py','emulate_calibration_marker.py','emulate_flash_fault_recovery.py')},
        hardware_access=False,physical_reset_verified=False,host_verification_window_proven=False,
        live_upload_enabled=False,live_execution_enabled=False,live_write_enabled=False,ready_to_flash=False,
        limits=['Native checksum/status/reset-tail control flow with synthetic flash-marker readback and stubbed sender/watchdog.',
                'The two delay loops execute but do not establish elapsed physical time.',
                'Every flash/MMIO store is suppressed; optional D0C2 RAM-marker storage uses a declared host-modeled 24-bit alias.',
                'The retained marker is not identified as a hardware reset register. No actual reset mechanism or time is verified.',
                'Optional boot cases use separate CPU contexts with the saved flash and hypothesized marker retention/status; no reset is delivered.',
                'Status construction and park-loop reach do not prove wire transmission, physical reset or post-reset state.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--loader',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--full-reference',type=Path)
    args=parser.parse_args()
    if args.output.exists():parser.error('New output required')
    result=analyze(args.loader.read_bytes(),None if args.full_reference is None else args.full_reference.read_bytes());result['input_reference']=dict(selected=str(args.loader),resolved=str(args.loader.resolve()))
    result['full_reference_input']=None if args.full_reference is None else dict(selected=str(args.full_reference),resolved=str(args.full_reference.resolve()))
    with args.output.open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2)
    print(json.dumps([(case['case'],case['observed']['stop']) for case in result['cases']]))
