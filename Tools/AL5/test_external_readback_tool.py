"""Compiled external readback route, using saved fixtures only. Never opens a programmer."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def run(tool,reference,prepared,loader,lifecycle,output):
    if output.exists():raise ValueError('New evidence directory required')
    tool=tool.resolve(strict=True);output.mkdir(parents=True)
    image=reference.read_bytes();assert len(image)==0x100000
    original_a=output/'original_a.bin';original_b=output/'original_b.bin'
    original_a.write_bytes(image);original_b.write_bytes(image)
    imported=output/'original_import'
    target='synthetic-spare-A'
    original_command=['dotnet',str(tool),'--external-chip',str(original_a),str(original_b),'cpu-bytes','original-fixture',str(imported),'--target-id',target]
    result=subprocess.run(original_command,capture_output=True,text=True)
    assert result.returncode==0,(result.stdout,result.stderr)
    assert json.loads((imported/'backup.json').read_text())['target_id']==target
    variants={'cpu':image,'swapped':b''.join(image[i:i+2][::-1] for i in range(0,len(image),2)),
              'blank':b'\xff'*len(image),'zero':bytes(len(image)),'short':image[:57304]}
    for name,address in [('boot_corrupt',0),('compensation_corrupt',0x15fd7),('bank_changed',0x4001)]:
        raw=bytearray(image);raw[address]^=1;variants[name]=bytes(raw)
    paths={}
    for name,data in variants.items():
        a=output/(name+'_a.bin');b=output/(name+'_b.bin');a.write_bytes(data);b.write_bytes(data);paths[name]=(a,b)
    history=output/'operator_history.txt';history.write_text('Synthetic file-only fixture. No controller or programmer was accessed; no power history was observed.\n')
    empty_history=output/'empty_history.txt';empty_history.write_bytes(b'')
    results=[];matched_command=None
    cases=[('matched','cpu','cpu','cpu-bytes','strict_saved_comparison_matched'),
           ('shutdown_declared','cpu','cpu','cpu-bytes','strict_saved_comparison_matched'),
           ('archived_original_sources','cpu','cpu','cpu-bytes','strict_saved_comparison_matched'),
           ('swapped','swapped','swapped','swap16','strict_saved_comparison_matched'),
           ('wrong_selected_order','swapped','swapped','cpu-bytes','strict_saved_comparison_failed'),
           ('boot_corrupt','boot_corrupt','boot_corrupt','cpu-bytes','strict_saved_comparison_failed'),
           ('compensation_corrupt','compensation_corrupt','compensation_corrupt','cpu-bytes','strict_saved_comparison_failed'),
           ('bank_changed','bank_changed','bank_changed','cpu-bytes','strict_saved_comparison_failed'),
           ('blank_failure_retained','blank','blank','cpu-bytes','strict_saved_comparison_failed'),
           ('zero_failure_retained','zero','zero','cpu-bytes','strict_saved_comparison_failed'),
           ('mismatched_pair','cpu','boot_corrupt','cpu-bytes',None),('partial_image','short','short','cpu-bytes',None),
           ('unknown_order','cpu','cpu','auto',None),('same_path','cpu','cpu','cpu-bytes',None),
           ('original_artifact_alias','cpu','cpu','cpu-bytes',None),('original_source_alias','cpu','cpu','cpu-bytes',None),
           ('wrong_target','cpu','cpu','cpu-bytes',None),('empty_history','cpu','cpu','cpu-bytes',None),
           ('promoted_original_flag','cpu','cpu','cpu-bytes',None),('changed_original_artifact','cpu','cpu','cpu-bytes',None),
           ('untagged_original','cpu','cpu','cpu-bytes',None),('unknown_power_epoch','cpu','cpu','cpu-bytes',None)]
    for name,first,second,order,outcome in cases:
        original=imported
        if name in ('promoted_original_flag','changed_original_artifact','untagged_original','archived_original_sources'):
            original=output/(name+'_original');shutil.copytree(imported,original)
            if name=='changed_original_artifact':
                p=original/'original.canonical.saved.bin';data=bytearray(p.read_bytes());data[0]^=1;p.write_bytes(data)
            else:
                p=original/'backup.json';v=json.loads(p.read_text())
                if name=='promoted_original_flag':v['physical_recovery_verified']=True
                elif name=='untagged_original':v.pop('target_id')
                else:
                    for field in ('raw_first','raw_second'):v[field]['resolved']=str((output/('missing_'+field+'.bin')).resolve())
                p.write_text(json.dumps(v))
        a=paths[first][0];b=paths[second][1]
        if name=='same_path':b=a
        if name=='original_artifact_alias':a=imported/'first.raw.saved.bin'
        if name=='original_source_alias':a=original_a
        dest=output/(name+'_review')
        command=['dotnet',str(tool),'--external-readback',str(original),str(prepared.resolve()),str(loader.resolve()),str(lifecycle.resolve()),
                 str(a),str(b),order,'power-history-unobserved','wrong-target' if name=='wrong_target' else target,
                 str(empty_history if name=='empty_history' else history),'readback-'+name,str(dest)]
        if name=='shutdown_declared':command[10]='shutdown-declared'
        if name=='unknown_power_epoch':command[10]='assumed-safe'
        before=[hashlib.sha256(p.read_bytes()).hexdigest() for p in (a,b)]
        r=subprocess.run(command,capture_output=True,text=True)
        assert before==[hashlib.sha256(p.read_bytes()).hexdigest() for p in (a,b)]
        if outcome is None:assert r.returncode!=0 and not dest.exists(),(name,r.stdout,r.stderr)
        else:
            assert r.returncode==0,(name,r.stdout,r.stderr)
            report=json.loads((dest/'readback.json').read_text());assessment=report['assessment'];assert report['outcome']==outcome,(name,report['outcome'])
            for flag in ('OperatorTargetContinuityVerified','IndependentPhysicalReadsVerified','PhysicalPowerStateVerified','SnapshotCoherenceVerified','PhysicalReadbackVerified','PreservationVerified','RecoveryVerified','LiveUploadEnabled','LiveExecutionEnabled','LiveWriteEnabled','ReadyToFlash'):
                assert assessment[flag] is False,(name,flag)
            assert assessment['ExperimentalReaderUploadRequired'] is False
            expected=variants[first]
            if order=='swap16':expected=b''.join(expected[i:i+2][::-1] for i in range(0,len(expected),2))
            assert (dest/'readback.canonical.saved.bin').read_bytes()==expected
            assert (dest/'readback.first.raw.saved.bin').read_bytes()==a.read_bytes()
            assert (dest/'readback.second.raw.saved.bin').read_bytes()==b.read_bytes()
            if name=='matched':matched_command=command
            if name=='blank_failure_retained':assert assessment['ReadbackAllFF'] and not assessment['StrictSavedComparisonMatched']
            if name=='bank_changed':assert assessment['ChangedPersistentBankBytes']==1
        results.append(dict(case=name,passed=True,expected_outcome=outcome,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr))
    saved=(output/'matched_review/readback.json').read_bytes();r=subprocess.run(matched_command,capture_output=True,text=True)
    assert r.returncode!=0 and (output/'matched_review/readback.json').read_bytes()==saved
    results.append(dict(case='existing_output_retained',passed=True,exit_code=r.returncode))
    for name,variant,case_target in [('capture_blank_without_lifecycle','blank',target),
                                     ('capture_damaged_without_lifecycle','boot_corrupt',target),
                                     ('capture_wrong_target','cpu','different-target')]:
        a,b=paths[variant];dest=output/name
        command=['dotnet',str(tool),'--capture-external-readback',str(imported),str(a),str(b),'cpu-bytes',
                 'power-history-unobserved',case_target,str(history),'capture-'+name,str(dest)]
        r=subprocess.run(command,capture_output=True,text=True)
        if case_target!=target:assert r.returncode!=0 and not dest.exists()
        else:
            assert r.returncode==0,(name,r.stdout,r.stderr)
            report=json.loads((dest/'readback.json').read_text())
            assert report['outcome']=='captured_saved_pair_comparison_unavailable'
            assert not report['comparison_performed'] and report['strict_saved_comparison_matched'] is None
            for field in ('physical_power_state_verified','snapshot_coherence_verified','preservation_verified','recovery_verified','live_write_enabled','ready_to_flash'):
                assert report[field] is False
            assert 'expected_image_sha256' not in report
            assert (dest/'readback.canonical.saved.bin').read_bytes()==variants[variant]
        results.append(dict(case=name,passed=True,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr))
    receipt=dict(schema='al5-external-readback-export-tests-v1',passed=True,cases=results,fixture_only=True,hardware_access=False,
                 library_sha256=hashlib.sha256((tool.parent/'PcmLibrary.dll').read_bytes()).hexdigest(),source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 reference_sha256=hashlib.sha256(image).hexdigest(),live_write_enabled=False,ready_to_flash=False)
    (output/'result.json').write_text(json.dumps(receipt,indent=2)+'\n');print('PASS',len(results),'external readback exporter cases; no hardware, reader upload or recovery claim.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('tool','reference','prepared','loader','lifecycle','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();run(a.tool,a.reference,a.prepared,a.loader,a.lifecycle,a.output)
