"""Verify v7 EFILive report against a known stock segment; never modifies a BIN."""
import argparse
import json
from pathlib import Path
from al5_segment import START, LENGTH, CHECKSUM, validate, sha256
from checksum import native_field, checksum_valid

CASES = [('D5000',0x11D0C,128,16,17),('D5120',0x823A,32,14,15),
         ('D5194',0x159E2,64,89,88)]


def reconstruct(stock, changes, allowed=None):
    data = bytearray(stock)
    seen = set()
    for b in changes:
        a = b['address']
        if a in seen or not START <= a < START+LENGTH or (allowed is not None and a not in allowed):
            raise ValueError('duplicate/out-of-range/unexpected changed byte')
        seen.add(a)
        if b['before']!=stock[a-START] or not 0 <= b['after'] <= 255 or b['before']==b['after']:
            raise ValueError('changed byte does not match stock')
        data[a-START] = b['after']
    return bytes(data)


def verify(report, stock):
    if validate(stock) or not checksum_valid(stock):
        raise ValueError('invalid stock reference')
    if report.get('tool')!='AL5-offline-enum-checksum-evidence-0.7':
        raise ValueError('unexpected tool')
    if (report.get('controller'),report.get('operating_system'),report.get('transmission')) != ('AL5',15184109,15183960):
        raise ValueError('wrong controller context')
    for key in ('completed','secondary_closed'):
        if report.get(key) is not True: raise ValueError('incomplete pass: '+key)
    for key in ('vehicle_io','gui_descriptor_modified','secondary_saved','flash_ready'):
        if report.get(key) is not False: raise ValueError('invalid flag: '+key)
    for key in ('secondary_baseline_equals_gui','native_stock_finalization_preserves_baseline','gui_raw_unchanged'):
        if report.get('validation',{}).get(key) is not True: raise ValueError('missing validation: '+key)
    if report.get('error') or report.get('close_error'):
        raise ValueError('report contains an error')
    if report.get('baseline_checksum')!=stock[-4:].hex().upper():
        raise ValueError('wrong baseline checksum')
    if len(report['checksum_cases'])!=3 or len(report['enum_cases'])!=2:
        raise ValueError('case count mismatch')
    result={'stock_sha256':sha256(stock),'checksum_variants':[],'enum_candidates':[],
            'flash_ready':False,'vehicle_io':False}
    for record,(id,address,factor,before,target) in zip(report['checksum_cases'],CASES):
        m=record['marker']
        if (m['id'],m['column'],m['row'],m['before'],m['requested'])!=(id,0,0,before,target):
            raise ValueError('numeric marker mismatch')
        if record.get('restored') is not True or record.get('checksum_finalization_called') is not True:
            raise ValueError('numeric finalization/restoration missing')
        if abs(m['readback']-target)>=.001:
            raise ValueError('numeric readback mismatch')
        word_addresses={address,address+1}
        if int.from_bytes(stock[address-START:address-START+2],'big') != before*factor:
            raise ValueError('numeric baseline word mismatch')
        expected=bytearray(stock)
        expected[address-START:address-START+2]=int(target*factor).to_bytes(2,'big')
        marked=reconstruct(stock,record['marked_changed_bytes'],word_addresses | set(range(CHECKSUM,CHECKSUM+4)))
        finalized=reconstruct(stock,record['finalized_changed_bytes'],word_addresses | set(range(CHECKSUM,CHECKSUM+4)))
        if marked[:-4]!=expected[:-4] or finalized[:-4]!=expected[:-4]:
            raise ValueError('payload differs from isolated marker')
        if record['marked_checksum']!=marked[-4:].hex().upper() or record['finalized_checksum']!=finalized[-4:].hex().upper():
            raise ValueError('reported field disagrees with reconstructed bytes')
        computed=native_field(finalized)
        result['checksum_variants'].append({'id':id,'candidate_sha256':sha256(finalized),
            'native_finalized_field':finalized[-4:].hex().upper(),
            'computed_field':computed.hex().upper(),'match':finalized[-4:]==computed})
    for record,id in zip(report['enum_cases'],('D5053','D5054')):
        m=record['marker']
        if (m['id'],m['column'],m['row'],m['before'],m['requested'],m['readback'])!=(id,0,0,'Enable','Disable','Disable'):
            raise ValueError('enum marker mismatch')
        if record.get('restored') is not True or record.get('checksum_update_called') is not False:
            raise ValueError('enum restoration/finalization mismatch')
        changes=record['changed_bytes']
        if not changes or record['changed_byte_count']!=len(changes):
            raise ValueError('empty/inconsistent enum changes')
        marked=reconstruct(stock,changes)
        covered=set()
        for diff in record['diff_ranges']:
            start,end=diff['context_start'],diff['context_end']
            if not START <= start <= end < START+LENGTH:
                raise ValueError('enum context outside segment')
            if bytes.fromhex(diff['before_hex'])!=stock[start-START:end-START+1] or bytes.fromhex(diff['after_hex'])!=marked[start-START:end-START+1]:
                raise ValueError('enum context mismatch')
            covered.update(b['address'] for b in changes if start <= b['address'] <= end)
        if covered!={b['address'] for b in changes}: raise ValueError('enum context does not cover changes')
        result['enum_candidates'].append({'id':id,'changed_bytes':changes,
            'note':'Named text differential only; field width/bit ownership needs review before XDF assignment.'})
    result['all_checksums_match']=all(c['match'] for c in result['checksum_variants'])
    result['status']='pass' if result['all_checksums_match'] else 'checksum_mismatch'
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('stock','report','output'): p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    r=verify(json.loads(a.report.read_text()),a.stock.read_bytes())
    r['report_sha256']=sha256(a.report.read_bytes())
    a.output.write_text(json.dumps(r,indent=2)+'\n')
    print(r['status'])
    raise SystemExit(0 if r['all_checksums_match'] else 2)
