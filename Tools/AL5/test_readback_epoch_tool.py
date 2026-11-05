"""Actual compiled exporter with bounded synthetic transcripts; no transport."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from test_saved_backup_tool import transcript


def run(tool, full_reference, loader, template, output):
    if output.exists():
        raise ValueError('New evidence directory required')
    tool=tool.resolve(strict=True)
    reference=bytearray(full_reference.read_bytes())
    if len(reference)!=0x100000:
        raise ValueError('Complete saved reference required')
    raw=template.read_text(encoding='utf-8')
    for line in raw.splitlines():
        frame=bytes.fromhex(line[2:])
        if line[0]=='T' and len(frame)>12 and frame[3:5]==b'\x36\x00':
            address=int.from_bytes(frame[7:10],'big')
            reference[address:address+len(frame)-12]=frame[10:-2]
    reference[0x1fffe:0x20000]=bytes.fromhex('4afc')
    output.mkdir(parents=True)
    (output/'original.fixture.bin').write_bytes(reference)
    (output/'prepared.fixture.bin').write_bytes(reference[0x4000:0x8000])
    (output/'lifecycle.fixture.txt').write_text(raw,encoding='utf-8')
    nonces=('0102030405060708','1112131415161718','2122232425262728')

    def write_trace(name,start,length,nonce,data):
        p=output/(name+'.txt')
        p.write_text('\n'.join(transcript(start,length,bytes.fromhex(nonce),data))+'\n',encoding='ascii')
        return p

    before=write_trace('before',0x4000,0x4000,nonces[0],reference)
    middle=write_trace('image',0,0x100000,nonces[1],reference)
    after=write_trace('after',0x4000,0x4000,nonces[2],reference)
    changed=bytearray(reference);changed[0x4001]^=1
    changed_before=write_trace('changed_before',0x4000,0x4000,nonces[0],changed)
    changed_middle=write_trace('changed_image',0,0x100000,nonces[1],changed)
    changed_after=write_trace('changed_after',0x4000,0x4000,nonces[2],changed)
    compensation=bytearray(reference);compensation[0x15fd7]^=1
    compensation_middle=write_trace('compensation_image',0,0x100000,nonces[1],compensation)
    partial=output/'partial.txt';partial.write_text('\n'.join(middle.read_text().splitlines()[:-2])+'\n')
    lifecycle_lines=raw.splitlines()
    final_index=next(i for i,line in enumerate(lifecycle_lines) if line[0]=='T' and bytes.fromhex(line[2:])==bytes.fromhex('6c18f036ff'))
    incomplete=output/'incomplete_lifecycle.txt';incomplete.write_text('\n'.join(lifecycle_lines[:final_index])+'\n')
    (output/'short_original.bin').write_bytes(reference[:0x80000])
    (output/'short_prepared.bin').write_bytes(reference[0x4000:0x7fff])
    (output/'oversized_loader.bin').write_bytes(loader.read_bytes()+b'\0')
    cases=[('complete',before,middle,after,nonces,output/'lifecycle.fixture.txt','strict_saved_comparison_matched'),
           ('unstable_after',before,middle,changed_after,nonces,output/'lifecycle.fixture.txt','unstable_saved_observations'),
           ('observed_banks_not_self_baseline',changed_before,changed_middle,changed_after,nonces,output/'lifecycle.fixture.txt','strict_saved_comparison_failed'),
           ('compensation_failure',before,compensation_middle,after,nonces,output/'lifecycle.fixture.txt','strict_saved_comparison_failed'),
           ('partial_image',before,partial,after,nonces,output/'lifecycle.fixture.txt',None),
           ('same_nonce',before,middle,after,(nonces[0],nonces[0],nonces[2]),output/'lifecycle.fixture.txt',None),
           ('wrong_stage',after,middle,before,nonces,output/'lifecycle.fixture.txt',None),
           ('missing_cleanup',before,middle,after,nonces,incomplete,None),
           *[(name,before,middle,after,nonces,output/'lifecycle.fixture.txt',None)
             for name in ('short_original','short_prepared','oversized_loader')]]
    results=[];complete_command=None
    for name,pre,image,post,ns,life,outcome in cases:
        dest=output/name
        command=['dotnet',str(tool),'--readback-epoch',str(output/'original.fixture.bin'),str(output/'prepared.fixture.bin'),
                 str(loader.resolve()),str(life),str(pre),str(image),str(post),*ns,'declared-startup','fixture-'+name,str(dest)]
        if name=='short_original':command[3]=str(output/'short_original.bin')
        if name=='short_prepared':command[4]=str(output/'short_prepared.bin')
        if name=='oversized_loader':command[5]=str(output/'oversized_loader.bin')
        r=subprocess.run(command,capture_output=True,text=True)
        if outcome is None:
            assert r.returncode!=0 and not dest.exists(),(name,r.stdout,r.stderr)
        else:
            assert r.returncode==0,(name,r.stdout,r.stderr)
            report=json.loads((dest/'epoch.json').read_text());a=report['assessment']
            assert report['outcome']==outcome,(name,report['outcome'])
            for field in ('SnapshotCoherenceVerified','ReaderEntryEffectsVerified','PhysicalReadbackVerified','PhysicalResetVerified','PreservationVerified','StartupHistoryPhysicallyVerified','LiveUploadEnabled','LiveExecutionEnabled','LiveWriteEnabled','ReadyToFlash'):
                assert a[field] is False,(name,field)
            assert a['MatchedReplies']==33792
            if name=='complete':
                assert (dest/'readback.observed.saved.bin').read_bytes()==bytes(reference)
                complete_command=command
            elif name=='unstable_after':
                assert not a['SavedComparisonAttempted'] and a['RawImageMatchesExpectedSavedImage'] is True
            else:
                assert a['SavedComparisonAttempted'] and not a['StrictSavedComparisonMatched']
        results.append(dict(case=name,passed=True,exit_code=r.returncode,expected_outcome=outcome,stdout=r.stdout,stderr=r.stderr))
    retained=(output/'complete/epoch.json').read_bytes()
    r=subprocess.run(complete_command,capture_output=True,text=True)
    assert r.returncode!=0 and (output/'complete/epoch.json').read_bytes()==retained
    results.append(dict(case='existing_output_retained',passed=True,exit_code=r.returncode))
    report=dict(schema='al5-readback-epoch-export-tests-v1',cases=results,passed=True,hardware_access=False,
                library_sha256=hashlib.sha256((tool.parent/'PcmLibrary.dll').read_bytes()).hexdigest(),
                source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                original_fixture_sha256=hashlib.sha256(reference).hexdigest(),
                fixture_provenance='historical full image with explicit captured-sector overlay; not a spare backup',
                live_write_enabled=False)
    (output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS',len(results),'compiled readback-epoch exporter cases; no physical epoch claim.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('tool','full-reference','loader','template','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();run(a.tool,a.full_reference,a.loader,a.template,a.output)
