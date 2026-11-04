"""Conditional watchdog inheritance and native reset-to-application validation.

Reset/application and reset/native-upload each retain one CPU/RAM context.
The captured loader copy stops before its first instruction. All physical
qualification and live-operation flags remain false.
"""
import argparse
import hashlib
import json
from pathlib import Path
from al5_watchdog_configuration import ConditionalWatchdogConfiguration
from emulate_calibration_marker import validate_source
from emulate_flash_fault_recovery import experiment


def analyze(image,loader):
    validate_source(image[:0x20000],image[0x20000:])
    low,high=image[:0x20000],image[0x20000:]
    bad=bytearray(image[0x8000:0x15FD8]);bad[0x100]^=1
    compensation=bytearray(image[0x8000:0x15FD8]);compensation[-1]^=1
    scenarios=[('watchdog_retained',{}),('power_retained',dict(reset_status=0x40)),('external_retained',dict(reset_status=0x80)),
        ('calibration_crc_corrupt',dict(calibration_overlay=bytes(bad))),('calibration_compensation_corrupt',dict(calibration_overlay=bytes(compensation))),
        ('calibration_marker_missing',dict(calibration_marker=0xFFFF)),('retained_marker_lost',dict(retained_marker=0)),
        ('os_checksum_fault',dict(window='os_check_to_reject'))]
    cases=[]
    for name,options in scenarios:
        args=dict(reset_status=0x20,retained_marker=0xD0C2,probe_boot_request=False,post_reset_checks=True,instruction_limit=8000000);args.update(options)
        observed=experiment(low,high,**args)
        model=ConditionalWatchdogConfiguration(fresh_reset=True)
        for row in observed['watchdog_control_attempts']:model.observe(pc=row['pc'],phase=row['phase'],value=row['value'])
        cases.append(dict(case=name,observed=observed,conditional_configuration=model.snapshot(),
            same_reset_to_application_context=True,physical_reset_delivered=False,
            calibration_overlay_sha256=None if 'calibration_overlay' not in options else hashlib.sha256(options['calibration_overlay']).hexdigest()))
    context=experiment(low,high,reset_status=0x20,retained_marker=0xBFC1,retain_context=True)
    before=dict(stop=context.report['stop'],watchdog_control_attempts=[dict(row) for row in context.report['watchdog_control_attempts']])
    copied=context.copy_captured_loader_offline(loader)
    model=ConditionalWatchdogConfiguration(fresh_reset=True)
    for row in copied['watchdog_control_attempts']:model.observe(pc=row['pc'],phase=row['phase'],value=row['value'])
    handoff=dict(before_copy=before,upload=copied,conditional_configuration=model.snapshot(),
        reset_to_upload_same_context=True,boot_upload_to_loader_entry_same_context=True,
        first_loader_instruction_executed=False,programming_marker_is_synthetic_input=True)
    dependencies=['trace_watchdog_inheritance.py','al5_watchdog_configuration.py','emulate_flash_fault_recovery.py',
        'emulate_calibration_marker.py','emulate_boot_loader_handoff.py','emulate_boot_receive_session.py','emulate_boot_receive_isr.py',
        'emulate_boot_session.py','emulate_loader_error_sender.py','emulate_loader_erase_failures.py','emulate_loader_entry.py','emulate_loader_parser.py']
    directory=Path(__file__).parent
    return dict(schema='al5-watchdog-inheritance-post-reset-v1',reference_sha256=hashlib.sha256(image).hexdigest(),
        loader_sha256=hashlib.sha256(loader).hexdigest(),dependencies_sha256={name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in dependencies},
        cases=cases,reset_to_captured_loader=handoff,
        manufacturer_reference=dict(url='https://www.nxp.com/docs/en/user-guide/MC68336376UMD.pdf',sections=['D.2.12','D.2.15'],actual_mcu_identified=False),
        hardware_access=False,physical_watchdog_configuration_verified=False,physical_reset_verified=False,
        independent_readback_verified=False,host_verification_window_proven=False,live_upload_enabled=False,live_execution_enabled=False,live_write_enabled=False,ready_to_flash=False,
        limits=['Synthetic reset status/retention and declared 24-bit aliases; peripheral values remain inert-model assumptions.',
                'Native boot and application checks share a CPU/RAM context; execution stops at rejection or first calibration-check return before ordinary startup/storage.',
                'CRC/marker fixtures alter only the declared calibration span/marker; OS address-alias fault uses the existing bounded fault model.',
                'Write-once interpretation is conditional on the manufacturer family, not an identified AL5 MCU or measured effective register.',
                'The reset-to-upload path uses a synthetic BFC1 marker and scripted FIFO/IRQ entry; no physical interrupt or reset is delivered, and execution stops before loader entry.',
                'Native application acceptance is not a complete preservation comparison, independent acquisition or verified host readback boundary.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('full-reference','loader','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('New output required')
    result=analyze(args.full_reference.read_bytes(),args.loader.read_bytes())
    result['inputs']={name:dict(selected=str(path),resolved=str(path.resolve())) for name,path in [('reference',args.full_reference),('loader',args.loader)]}
    with args.output.open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2)
    print(json.dumps([(row['case'],row['observed']['stop']) for row in result['cases']]))
