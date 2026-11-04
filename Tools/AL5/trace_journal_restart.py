"""Conditional native startup journal epochs, with every flash effect host modeled.

Separate CPU contexts do not deliver the finalizer's reset. The prepared banks
come from the existing bounded preparation model, not a measured controller.
"""
import argparse
import hashlib
import json
from pathlib import Path
from trace_resident_main_startup import trace
from emulate_preparation_statuses import StatusTrace


def digest(data):return hashlib.sha256(data).hexdigest()


def replay(banks,operations):
    if type(banks) is not bytes or len(banks)!=0x4000:raise ValueError('Complete saved banks required')
    result=bytearray(banks)
    for row in operations:
        address=row['destination'];before=bytes.fromhex(row['before']);after=bytes.fromhex(row['after'])
        if row['implementation_executed'] is not False or len(before)!=len(after) or row['bytes']!=len(after):
            raise ValueError('Only explicit same-length atomic modeled programs are supported')
        if type(address) is not int or not 0x4000<=address<address+len(after)<=0x8000:
            raise ValueError('Operation escaped banks')
        offset=address-0x4000
        if result[offset:offset+len(before)]!=before:raise ValueError('Operation does not own its before bytes')
        if any((a&b)!=b for a,b in zip(before,after)):raise ValueError('Program requires an unmodeled erase')
        result[offset:offset+len(after)]=after
    return bytes(result)


def run(image,output):
    # Validation in the existing producer precedes any emulator context creation.
    from emulate_calibration_marker import validate_source
    validate_source(image[:0x20000],image[0x20000:])
    if output.exists():raise ValueError('New output directory required')
    directory=Path(__file__).parent
    inputs=json.loads((directory/'Fixtures/resident_startup_scheduler_mmio.json').read_text())
    sites=json.loads((directory/'Fixtures/resident_scheduler_sites.json').read_text())
    output.mkdir(parents=True,exist_ok=False)
    model=StatusTrace(image[:0x20000],image[0x20000:],'success')
    preparation=model.trace()
    prepared=bytes(model.uc.mem_read(0x4000,0x4000))
    (output/'modeled_prepared_banks.bin').write_bytes(prepared)
    (output/'preparation.json').write_text(json.dumps(preparation,indent=2)+'\n')
    cases=[]
    for name,banks in [('historical_restart',image[0x4000:0x8000]),('prepared_restart',prepared),('second_prepared_restart',None)]:
        if banks is None:banks=after
        observed=trace(image,mmio_inputs=inputs,model_bank_programs=True,scheduled_ticks=320,mmio_site_inputs=sites,saved_banks=banks)
        after=replay(banks,observed['synthetic_bank_programs'])
        if digest(after)!=observed['bank_comparison']['final_sha256']:raise ValueError('Ordered programs do not reproduce final bank state')
        (output/(name+'.before.bin')).write_bytes(banks)
        (output/(name+'.after.bin')).write_bytes(after)
        case=dict(case=name,bank_source='historical_saved' if name=='historical_restart' else 'host_modeled_separate_epoch',observed=observed)
        cases.append(case)
        # Retain completed evidence if a later bounded case stops or fails.
        (output/(name+'.json')).write_text(json.dumps(case,indent=2)+'\n')
        print(name,observed['stop'],len(observed['synthetic_bank_programs']),observed['bank_comparison']['changed_addresses'],flush=True)
    dependencies=['trace_journal_restart.py','trace_resident_main_startup.py','emulate_preparation_statuses.py',
        'emulate_application_reset_chain.py','emulate_receive_preparation.py','emulate_calibration_marker.py',
        'emulate_storage_recovery.py','emulate_storage_selection.py','emulate_application_boot.py','checksum.py','al5_segment.py',
        'Fixtures/resident_startup_scheduler_mmio.json','Fixtures/resident_scheduler_sites.json']
    report=dict(schema='al5-native-journal-restart-v1',reference_sha256=digest(image),preparation=preparation,cases=cases,
        dependencies_sha256={name:digest((directory/name).read_bytes()) for name in dependencies},
        hardware_access=False,physical_reset_verified=False,physical_journal_transition_verified=False,
        host_verification_window_proven=False,live_upload_enabled=False,live_execution_enabled=False,live_write_enabled=False,ready_to_flash=False,
        limits=['Separate CPU contexts with a pinned saved image and explicit 16 KiB bank overlays.',
                'Preparation bypasses the existing declared subsystem helpers; bank programs are atomic host effects.',
                '320 synthetic timer-body calls do not establish real elapsed time or physical interrupt delivery.',
                'Successful bounded observations are diagnostic predictions, not permission to ignore bank differences.'])
    (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--full-reference',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();run(args.full_reference.read_bytes(),args.output)
