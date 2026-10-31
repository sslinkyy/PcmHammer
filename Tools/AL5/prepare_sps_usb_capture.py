"""Prepare a GT-only USBPcap plan. Never launches capture, SPS or an adapter."""
import argparse
import json
from pathlib import Path
import re


def plan(hub=None,address=None):
    if (hub is None)!=(address is None):raise ValueError('Supply both current hub and USB address')
    if hub is not None and not re.fullmatch(r'\\\\\.\\USBPcap[1-9][0-9]*',hub):
        raise ValueError('Expected an explicit USBPcap control device')
    if address is not None and (type(address) is not int or not 1<=address<=127):
        raise ValueError('USB address must be 1..127')
    args=None if hub is None else ['-d',hub,'--devices',str(address),
                                 '-s','1048576','-b','16777216','-o','-']
    return dict(capture_executable=r'C:\Program Files\USBPcap\USBPcapCMD.exe',
                proposed_capture_arguments=args,plan_only=True,launch_performed=False,
                topology_identity_verified=False,vin_coverage_verified=False,
                flashing_authorized=False,serial_port_open=False,
                capture_supervisor='LocalOnly/usb_capture_setup_20261030/usbpcap_pipe_supervisor.py',
                supervisor_launch='pythonw.exe with DETACHED_PROCESS; not python.exe with CREATE_NO_WINDOW',
                stop_method='Write receipt.stop_request to receipt.stop_path; supervisor drains and closes its owned pipe.',
                obsolete_supervisor='Do not launch usbpcap_console_supervisor.py; shared definitions only.',
                capture_arguments_scope='Child arguments only: stdout must be the supervisor-owned duplex pipe, not a terminal.',
                prerequisites=['Verify current GT USB identity, hub and device address immediately before capture.',
                               'Do not use all-device capture or reuse an old address after reconnect.',
                               'Use a fresh output directory and confirm capture is writing before SPS communication.',
                               'SPS alone owns the GT; do not run PcmHammer or the GT serial listener concurrently.',
                               'Keep capture running through the documented programming shutdown if later authorized.'],
                analysis_limits=['USB capture is host-to-adapter evidence, not independent lossless bus monitoring.',
                                 'Decode the actual J2534 driver traffic; do not assume prior DVI byte windows apply.',
                                 'A completed SPS event does not establish full-chip coverage or recovery.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hub');parser.add_argument('--address',type=int)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=plan(args.hub,args.address)
    with args.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(result,f,indent=2);f.write('\n')
    print('Prepared plan only; no process, adapter or capture started.')
