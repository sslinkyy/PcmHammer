"""Exercise the real file-only external-chip importer; fixtures are never hardware backups."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def swapped(data):
    result=bytearray(data);result[0::2]=data[1::2];result[1::2]=data[0::2];return bytes(result)


def run(tool,reference,intel_readback,output):
    if output.exists():raise ValueError('New evidence directory required')
    image=reference.read_bytes()
    if len(image)!=0x100000:raise ValueError('Exact full historical fixture required')
    output.mkdir(parents=True);results=[]
    variants={
        'cpu':image,'swapped':swapped(image),'blank':b'\xff'*len(image),'zero':bytes(len(image)),
        'oversized':image+b'\x00','short_intel':intel_readback.read_bytes(),
    }
    for name,offset in [('bad_boot',0x100),('bad_os',0x20000),('bad_cal',0x8100),('different',0x4000)]:
        changed=bytearray(image);changed[offset]^=1;variants[name]=bytes(changed)
    paths={}
    for name,data in variants.items():
        paths[name]=[]
        for index in (1,2):
            path=output/f'{name}_{index}.fixture.bin';path.write_bytes(data);paths[name].append(path)
    cases=[('cpu_order','cpu','cpu','cpu-bytes',True),('explicit_swap','swapped','swapped','swap16',True),
           ('wrong_order','cpu','cpu','swap16',False),('wrong_order_swapped','swapped','swapped','cpu-bytes',False),
           ('mismatch','cpu','different','cpu-bytes',False),('blank','blank','blank','cpu-bytes',False),
           ('zero','zero','zero','cpu-bytes',False),('oversized','oversized','oversized','cpu-bytes',False),
           ('intel_not_al5','short_intel','short_intel','cpu-bytes',False),('bad_boot','bad_boot','bad_boot','cpu-bytes',False),
           ('bad_os','bad_os','bad_os','cpu-bytes',False),('bad_cal','bad_cal','bad_cal','cpu-bytes',False),
           ('unknown_order','cpu','cpu','auto',False),('same_path','cpu','cpu','cpu-bytes',False)]
    for name,first,second,order,success in cases:
        a=paths[first][0];b=a if name=='same_path' else paths[second][1];destination=output/(name+'_export')
        before=[hashlib.sha256(path.read_bytes()).hexdigest() for path in (a,b)]
        command=['dotnet',str(tool),'--external-chip',str(a),str(b),order,'fixture-only-'+name,str(destination)]
        process=subprocess.run(command,text=True,capture_output=True)
        if (process.returncode==0)!=success:raise AssertionError((name,process.stdout,process.stderr))
        assert before==[hashlib.sha256(path.read_bytes()).hexdigest() for path in (a,b)]
        if success:
            report=json.loads((destination/'backup.json').read_text());assert report['raw_saved_files_match']
            assert (destination/'original.canonical.saved.bin').read_bytes()==image
            assert (destination/'original_banks.saved.bin').read_bytes()==image[0x4000:0x8000]
            assert (destination/'first.raw.saved.bin').read_bytes()==a.read_bytes()
            assert (destination/'second.raw.saved.bin').read_bytes()==b.read_bytes()
            assert report['explicit_adjacent_pair_conversion']==(order=='swap16')
            for flag in ('chip_identity_verified','physical_data_lane_mapping_verified','pre_entry_physical_acquisition_verified',
                         'physical_recovery_verified','hardware_access','live_upload_enabled','live_execution_enabled','live_write_enabled','ready_to_flash'):
                assert report[flag] is False
            again=subprocess.run(command,text=True,capture_output=True);assert again.returncode!=0
            assert (destination/'original.canonical.saved.bin').read_bytes()==image
        else:assert not destination.exists(),name
        results.append(dict(case=name,passed=True,exit_code=process.returncode,stdout=process.stdout,stderr=process.stderr))
    report=dict(schema='al5-external-chip-import-tests-v1',cases=results,fixture_only=True,
        reference_sha256=hashlib.sha256(image).hexdigest(),intel_readback_sha256=hashlib.sha256(variants['short_intel']).hexdigest(),
        tool_sha256=hashlib.sha256(tool.read_bytes()).hexdigest(),library_sha256=hashlib.sha256(tool.with_name('PcmLibrary.dll').read_bytes()).hexdigest(),
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        hardware_access=False,live_operations_enabled=False,ready_to_flash=False)
    (output/'results.json').write_text(json.dumps(report,indent=2));return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('tool','reference','intel-readback','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();report=run(args.tool,args.reference,args.intel_readback,args.output)
    print('PASS',len(report['cases']),'actual external-import cases; all inputs are saved files/fixtures, no hardware')
