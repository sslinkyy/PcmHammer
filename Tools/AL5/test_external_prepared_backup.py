"""External-file original plus correlated prepared epoch through the actual exporter."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from test_saved_backup_tool import transcript


def run(tool,external,output):
    if output.exists():raise ValueError('New evidence directory required')
    image=(external/'original.canonical.saved.bin').read_bytes();prepared=bytearray(image);prepared[0x4000]^=1;prepared[0x6001]^=1
    nonce='0807060504030201';lines=transcript(0x4000,0x4000,bytes.fromhex(nonce),prepared,stale=True)
    output.mkdir(parents=True);results=[]
    for name in ('complete','partial','wrong_nonce','raw_tamper','canonical_tamper','promoted_flag','missing_entry'):
        case=output/name;case.mkdir();source=case/'external';shutil.copytree(external,source)
        if name in ('raw_tamper','canonical_tamper'):
            path=source/('first.raw.saved.bin' if name=='raw_tamper' else 'original.canonical.saved.bin');data=bytearray(path.read_bytes());data[100]^=1;path.write_bytes(data)
        if name=='promoted_flag':
            path=source/'backup.json';report=json.loads(path.read_text());report['pre_entry_physical_acquisition_verified']=True;path.write_text(json.dumps(report))
        selected=case/'prepared.fixture.txt';selected.write_text('\n'.join(lines[:-2] if name=='partial' else lines)+'\n')
        destination=case/'export';command=['dotnet',str(tool),'--external-prepared',str(source),str(selected),
            '1111111111111111' if name=='wrong_nonce' else nonce,'fixture-only-'+name,
            '--not-recorded' if name=='missing_entry' else '--entry-boundary-recorded',str(destination)]
        process=subprocess.run(command,text=True,capture_output=True);success=name=='complete'
        if (process.returncode==0)!=success:raise AssertionError((name,process.stdout,process.stderr))
        if success:
            assert (destination/'original.saved.bin').read_bytes()==image
            assert (destination/'original_banks.saved.bin').read_bytes()==image[0x4000:0x8000]
            assert (destination/'prepared_banks.saved.bin').read_bytes()==prepared[0x4000:0x8000]
            report=json.loads((destination/'backup.json').read_text());assert report['prepared_matched_replies']==512 and report['prepared_unrelated_replies']==1
            assert report['preparation_changed_bytes']==2 and report['original_source_kind']=='ExternalSavedImage'
            for key in ('physical_security_verified','pre_entry_physical_acquisition_verified','physical_address_mapping_verified',
                        'snapshot_coherence_verified','physical_recovery_verified','hardware_access','live_upload_enabled','live_execution_enabled','live_write_enabled','ready_to_flash'):
                assert report[key] is False
            repeat=subprocess.run(command,text=True,capture_output=True);assert repeat.returncode!=0
        else:assert not destination.exists(),name
        results.append(dict(case=name,passed=True,exit_code=process.returncode,stdout=process.stdout,stderr=process.stderr))
    report=dict(schema='al5-external-prepared-export-tests-v1',cases=results,fixture_only=True,
        tool_sha256=hashlib.sha256(tool.read_bytes()).hexdigest(),library_sha256=hashlib.sha256(tool.with_name('PcmLibrary.dll').read_bytes()).hexdigest(),
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),hardware_access=False,live_operations_enabled=False)
    (output/'results.json').write_text(json.dumps(report,indent=2));return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('tool','external','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();result=run(args.tool,args.external,args.output);print('PASS',len(result['cases']),'external-original/prepared exporter cases; no hardware')
