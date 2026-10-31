"""Extract selected saved observations for offline replay; never a send plan."""
import argparse
import json
from pathlib import Path
from al5_segment import sha256
from decode_trace_containers import decode, records
from inspect_autocal_read_gap import frame


def extract(source):
    selected=[];loader_hashes=[];excluded=0
    for ordinal,r in enumerate(records(decode(source))):
        if r['kind']!=0x42:continue
        f=frame(r['payload'],r['channel']);m=f['payload']
        vpw=f['command']==0x8a00 if f['direction']==1 else f['raw'][2:6]==bytes.fromhex('18000000')
        if not vpw:excluded+=1;continue
        # Preserve every VPW payload in this wrapper context. Unknown exchanges must reach the replay validator.
        selected.append((ordinal,'T' if f['direction']==1 else 'R',m))
        if m.startswith(bytes.fromhex('6d18f03680')):loader_hashes.append(sha256(m[10:-2]))
    if len(loader_hashes)!=1:raise ValueError('Expected exactly one captured loader transfer')
    return selected,dict(source_sha256=sha256(source),loader_sha256=loader_hashes[0],
                        selected_frames=len(selected),excluded_binary_records=excluded,
                        scope='All VPW payloads in observed AL5 wrapper context; adapter-local setup remains excluded',
                        live_write_enabled=False,security_authorization_proven=False)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('trace','private-corpus','report'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();frames,report=extract(a.trace.read_bytes())
    a.private_corpus.write_text('\n'.join(d+' '+m.hex() for _,d,m in frames)+'\n',encoding='ascii')
    report['records']=[dict(ordinal=o,direction=d,bytes=len(m),sha256=sha256(m)) for o,d,m in frames]
    a.report.write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    print(json.dumps({k:v for k,v in report.items() if k!='records'}))
