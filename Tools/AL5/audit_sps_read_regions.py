"""Offline permission coverage for pinned SPS OS; never emits live requests."""
import argparse
import hashlib
import json
from pathlib import Path
from emulate_mode23_coverage import Probe
OS_HASH='145d0dde8c4de88e3145b5693685ab28958d1dda70743c589cc0c7deaa4b45e7'
EXCLUDED=((0x3FD8,0x3FDC),(0xC4C66,0xC4C68))
REGIONS=(('boot',0,0x4000),('persistent',0x4000,0x8000),('calibration',0x8000,0x15FD8),
         ('lower_tail',0x15FD8,0x20000),('os',0x20000,0xC5F94),('upper_tail',0xC5F94,0x100000))

def permission(address):
    return 0<=address and address+4<=0x100000 and not any(address<end and address+4>start for start,end in EXCLUDED)

def layout():
    result=[]
    for name,start,end in REGIONS:
        holes=[(max(start,a),min(end,b)) for a,b in EXCLUDED if start<b and end>a]
        aligned_holes=[a for a in range(start,end,4) if not permission(a)]
        result.append(dict(region=name,start=start,end_exclusive=end,bytes=end-start,
            permission_excluded_bytes=sum(b-a for a,b in holes),excluded_ranges=holes,
            aligned_dwords=(end-start)//4,aligned_dwords_rejected=aligned_holes,
            source_bytes_acquired=False,physical_readability_proven=False))
    return result

def analyze(module, native=False):
    if len(module)!=679828 or hashlib.sha256(module).hexdigest()!=OS_HASH:raise ValueError('SPS OS identity changed')
    from emulate_mode23_coverage import RANGES
    code={hex(a):hashlib.sha256(module[a-0x20000:b-0x20000]).hexdigest() for a,b in RANGES}
    # Bind this OS to the historical handler/helper evidence, not merely matching software IDs.
    expected={'0xbfda0':'4684fe33254165f6a3c4dbb2df71b6c9ebd5401c4f4f57546f7181fe032d966c',
      '0xc00e8':'88313f19e7fb20ad03aa1ba31bcd795205d600d6af3f8559c4ec10029074bedd',
      '0xc2f88':'b12a584ff7212033e1e9c64e226569286b335c83b1b3a924327ddb3dfe8d408d',
      '0xc2fd0':'ed1c6b76f093ce6fcf2da3ec186adf1311336f7c24c05c1e9484455bfa8b4ef8'}
    if code!=expected:raise ValueError('Mode 23 helper identity mismatch')
    addresses=sorted({a for _,s,e in REGIONS for a in (s,e-4)} | {0x3FD4,0x3FD5,0x3FD8,0x3FDC,0xC4C60,0xC4C62,0xC4C63,0xC4C64,0xC4C66,0xC4C68,0xFFFFC,0xFFFFD})
    samples=[]
    if native:
        p=Probe(module,source='sps_os')
        for a in addresses:
            actual=p.permission(a)
            if actual!=permission(a):raise ValueError('Native permission/model disagreement at '+hex(a))
            samples.append(dict(address=a,accepted=actual))
    return dict(sps_os_sha256=OS_HASH,code_sha256=code,regions=layout(),native_permission_samples=samples,
        permission_excluded_bytes=6,aligned_dword_scan_missing_bytes=8,
        overlap_candidate=dict(address=0xC4C62,bytes_recoverable=[0xC4C64,0xC4C65],
            physical_read_qualified=False),
        limits=['Native samples use synthetic RAM/peripheral-free execution; unknown flash tail is synthetic zero memory.',
            'Static permission coverage does not establish dispatcher/session eligibility, wire freshness or physical readability.',
            'Replies echo only low 16 address bits. Repeated echoes across banks or retries remain ambiguous.',
            'No new live ranges, timeout retries, adapter operations or writer permissions are enabled.'],
        live_read_enabled=False,live_write_enabled=False,session_boundary_proven=False)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--sps-os',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--native',action='store_true');a=p.parse_args()
    if a.output.exists():p.error('Choose a new output')
    if a.sps_os.stat().st_size!=679828:p.error('Exact SPS OS required')
    r=analyze(a.sps_os.read_bytes(),a.native)
    with a.output.open('x') as f:json.dump(r,f,indent=2)
    print(json.dumps(r))
