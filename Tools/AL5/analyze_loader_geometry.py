"""Offline saved finalization pointers and conditional datasheet geometry; no writes."""
import argparse
import json
from pathlib import Path
from al5_segment import sha256, word_sum
from checksum import checksum_valid

DATASHEET='https://www.batronix.com/files/Datenblaetter/29__/AM29F800B.pdf'
STATIC_EVIDENCE = Path(__file__).resolve().parents[2] / 'Docs/AL5/CAPTURED_LOADER_STATIC.json'


def finalize_sum_matches(image):
    if not image or len(image)%2:raise ValueError('nonempty even-length image required')
    return word_sum(image)==0


def analyze(low,high):
    if len(low)!=0x20000 or len(high)!=0xE0000:raise ValueError('unexpected saved dump sizes')
    start=int.from_bytes(high[0x46:0x4A],'big')
    last=int.from_bytes(high[0x4A:0x4E],'big')
    if start%2 or last%2!=1 or not 0<=start<last<len(low):raise ValueError('unsupported finalization pointer bounds')
    image=low[start:last+1]
    # Conditional AMD bottom-boot geometry in CPU byte-address coordinates.
    intervals=[(0x8000,0x10000),(0x10000,0x20000)]
    sectors=[]
    for a,b in intervals:
        overlap=max(0,min(b,last+1)-max(a,start))
        sectors.append({'start':hex(a),'end_exclusive':hex(b),'bytes':b-a,
                        'calibration_bytes':overlap,'outside_calibration_bytes':b-a-overlap})
    collateral_start=last+1
    return {'scope':'Saved-image pointer/checksum observations plus conditional published sector geometry; no live identification or flash action.',
            'static_evidence':'Docs/AL5/CAPTURED_LOADER_STATIC.json',
            'static_evidence_sha256':sha256(STATIC_EVIDENCE.read_bytes()),
            'source_low_sha256':sha256(low),'source_high_sha256':sha256(high),
            'finalization':{'pointer_table':'0x20046','start':hex(start),'inclusive_last_byte':hex(last),
                            'final_word_address':hex(last-1),'bytes':len(image),'image_sha256':sha256(image),
                            'be16_sum':hex(word_sum(image)),'sum_guard_matches':finalize_sum_matches(image),
                            'native_checksum_valid_in_saved_image':checksum_valid(image),
                            'loader_recomputes_native_crc':False,
                            'completion_marker_address':'0x1fffe','saved_marker_word':low[0x1FFFE:0x20000].hex(),
                            'marker_proves_current_controller_state':False},
            'conditional_geometry':{'datasheet_url':DATASHEET,'datasheet_author':'AMD',
                                    'document':'Am29F800B 21504E5, November 2, 2006; Table 3 and Table 9',
                                    'manufacturer_word':'0x0001','device_word':'0x2258',
                                    'candidate':'Am29F800BB bottom boot, x16 word interface mapped to CPU byte addresses',
                                    'sectors':sectors,'total_bytes':sum(b-a for a,b in intervals),
                                    'outside_calibration_bytes':sum(s['outside_calibration_bytes'] for s in sectors),
                                    'collateral_start':hex(collateral_start),'collateral_end_exclusive':'0x20000',
                                    'saved_collateral_sha256':sha256(low[collateral_start:0x20000]),
                                    'physical_chip_identity_verified':False,'physical_sector_geometry_verified':False,
                                    'current_collateral_backup_verified':False},
            'limits':'Datasheet corroboration is conditional on the actual chip and mapping. Saved editor data is not a current backup. Finalize sum does not prove native CRC, programming completion or recovery.',
            'ready_to_flash':False,'live_write_enabled':False,'erase_scope':None,'would_send':[]}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('low','high','output'):p.add_argument('--'+name,type=Path,required=True)
    args=p.parse_args();result=analyze(args.low.read_bytes(),args.high.read_bytes())
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'finalization_bytes':result['finalization']['bytes'],'conditional_erase_bytes':result['conditional_geometry']['total_bytes'],'physical_sector_geometry_verified':False}))
