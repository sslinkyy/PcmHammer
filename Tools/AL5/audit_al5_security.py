"""Offline security-profile audit: pinned native handlers, saved calibration selectors and captured pairs."""
import argparse,hashlib,json,contextlib,io
from pathlib import Path
from emulate_application_authorization import Authorization,run_cases

def analyze(low,high,os_module,calibrations):
    with contextlib.redirect_stdout(io.StringIO()):report=run_cases(low,high)
    if not report['all_pass']:raise ValueError('Native authorization regression failed')
    data=low+high
    # Bind current SPS handler code to the historical profile without pretending
    # that a captured OS module independently reads back the boot/selector state.
    ranges=((0x9820C,0x984EC),(0x85438,0x854B8),(0x85560,0x85580))
    matches=all(os_module[a-0x20000:b-0x20000]==data[a:b] for a,b in ranges)
    if not matches:raise ValueError('SPS security handler differs from pinned native profile')
    selectors=[]
    for path in calibrations:
        cal=path.read_bytes()
        if len(cal)!=57304:raise ValueError('Exact calibration segment required')
        selectors.append(dict(path=str(path),sha256=hashlib.sha256(cal).hexdigest(),selector=cal[0x10954-0x8000]))
    samples=[]
    for seed in (0,1,0x1234,0x9CE5,0xFFFF):
        observed=Authorization(low,high).transform(seed)
        samples.append(dict(seed=seed,native_selector_one_key=int(observed['key_low_word'],16)))
    return dict(schema='al5-offline-security-support-audit-v1',low_sha256=report['low_sha256'],high_sha256=report['high_sha256'],
                generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependencies_sha256={n:hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in
                                     ('emulate_application_authorization.py','emulate_application_boot.py')},
                native_authorization=report,sps_handler_matches_pinned_code=matches,saved_calibration_selectors=selectors,
                native_selector_one_samples=samples,general_fresh_seed_support_verified=False,
                live_security_submission_enabled=False,live_upload_enabled=False,live_execution_enabled=False,live_write_enabled=False,
                limits=['Saved selector-zero native path uses fixed boot words; one matching pair does not identify an algorithm.',
                        'Selector-one transform is isolated; fresh seed generation and physical acceptance are not emulated.',
                        'Current boot words, lockout timing and session authorization require separate evidence.',
                        'Generic PcmHammer security protocol targets PCM 0x10; AL5 is 0x18.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('low','high','sps-os','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--calibration',type=Path,action='append',required=True)
    a=p.parse_args()
    if a.output.exists():p.error('New output required')
    r=analyze(a.low.read_bytes(),a.high.read_bytes(),a.sps_os.read_bytes(),a.calibration)
    with a.output.open('x') as f:json.dump(r,f,indent=2)
    print('PASS native authorization audit; general fresh-seed support remains unverified')
