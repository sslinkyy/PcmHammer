"""Exercise the actual file-only C# diagnostic against saved native restart cases."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess


def run(tool,reference,native_directory,output):
    if output.exists():raise ValueError('New output directory required')
    image=reference.read_bytes();native=json.loads((native_directory/'report.json').read_text())
    assert hashlib.sha256(image).hexdigest()==native['reference_sha256']
    output.mkdir(parents=True);results=[]
    names=[row['case'] for row in native['cases']]
    cases=names+['changed_address_corruption','other_bank_corruption','outside_bank_corruption','wrong_prepared',
        'wrong_original','promoted_flag','reordered','wrong_before','wrong_caller','outside_layout','native_effect_claim',
        'wrong_final_digest','partial_readback','partial_banks','missing_case','duplicate_case']
    for name in cases:
        directory=output/name;directory.mkdir();selected=name if name in names else 'prepared_restart'
        report=copy.deepcopy(native);row=next(row['observed'] for row in report['cases'] if row['case']==selected)
        before=(native_directory/(selected+'.before.bin')).read_bytes();after=(native_directory/(selected+'.after.bin')).read_bytes()
        readback=bytearray(image);readback[0x4000:0x8000]=after
        if name=='changed_address_corruption':readback[row['bank_comparison']['changed_addresses'][0]]^=1
        if name=='other_bank_corruption':readback[0x4005]^=1
        if name=='outside_bank_corruption':readback[0]^=1
        if name=='wrong_prepared':before=image[0x4000:0x8000]
        if name=='wrong_original':report['reference_sha256']='0'*64
        if name=='promoted_flag':report['physical_journal_transition_verified']=True
        if name=='reordered':row['synthetic_bank_programs'].reverse()
        if name=='wrong_before':row['synthetic_bank_programs'][0]['before']='0000'
        if name=='wrong_caller':row['synthetic_bank_programs'][0]['caller_return']+=2
        if name=='outside_layout':row['synthetic_bank_programs'][0]['destination']=0x7000
        if name=='native_effect_claim':row['synthetic_bank_programs'][0]['implementation_executed']=True
        if name=='wrong_final_digest':row['bank_comparison']['final_sha256']='0'*64
        if name=='partial_readback':readback=readback[:-1]
        if name=='partial_banks':before=before[:-1]
        if name=='missing_case':selected='absent'
        if name=='duplicate_case':report['cases'].append(copy.deepcopy(next(row for row in report['cases'] if row['case']==selected)))
        bank_path=directory/'prepared.fixture.bin';bank_path.write_bytes(before)
        read_path=directory/'readback.fixture.bin';read_path.write_bytes(readback)
        trace_path=directory/'native.fixture.json';trace_path.write_text(json.dumps(report))
        command=['dotnet',str(tool),'--startup-bank-review',str(reference),str(bank_path),str(read_path),str(trace_path),selected,'fixture-only-'+name,str(directory/'export')]
        process=subprocess.run(command,text=True,capture_output=True)
        accepted=name in names or name in ('changed_address_corruption','other_bank_corruption','outside_bank_corruption')
        assert (process.returncode==0)==accepted,(name,process.stdout,process.stderr)
        if accepted:
            actual=json.loads((directory/'export/review.json').read_text())
            assert actual['MatchesSavedPrediction']==(name not in ('changed_address_corruption','other_bank_corruption'))
            assert actual['DifferencesFromPrediction']==(1 if name in ('changed_address_corruption','other_bank_corruption') else 0)
            assert (directory/'export/predicted_banks.offline.bin').read_bytes()==after
            for flag in ('preservation_verified','physical_transition_verified','snapshot_coherence_verified','hardware_access','live_upload_enabled','live_execution_enabled','live_write_enabled','ready_to_flash'):assert actual[flag] is False
            assert subprocess.run(command,capture_output=True).returncode!=0
        else:assert not (directory/'export').exists()
        results.append(dict(case=name,passed=True,input_accepted=accepted,exit_code=process.returncode,stdout=process.stdout,stderr=process.stderr))
    result=dict(schema='al5-startup-bank-review-tests-v1',cases=results,
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),tool_sha256=hashlib.sha256(tool.read_bytes()).hexdigest(),
        library_sha256=hashlib.sha256(tool.with_name('PcmLibrary.dll').read_bytes()).hexdigest(),
        native_report_sha256=hashlib.sha256((native_directory/'report.json').read_bytes()).hexdigest(),
        fixture_only=True,hardware_access=False,live_operations_enabled=False)
    (output/'results.json').write_text(json.dumps(result,indent=2)+'\n');return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('tool','reference','native-directory','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();result=run(args.tool,args.reference,args.native_directory,args.output)
    print('PASS',len(result['cases']),'compiled saved-bank diagnostic cases; no hardware')
