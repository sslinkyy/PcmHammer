"""Pinned offline AL5 reset-cause/retained-marker routing. No device I/O."""
import argparse
import hashlib
import json
from pathlib import Path
from emulate_calibration_marker import validate_source
from emulate_flash_fault_recovery import experiment

MARKERS=(0,0xD0C2,0x6124,0xBFC1,0x30D4,0x8C9B,0xA004,0xCC8B,0x9515,0x9372,0x0595,0x2FE6)
MANUAL='https://www.nxp.com/docs/en/user-guide/MC68336376UMD.pdf'

def static_evidence(low,high):
    validate_source(low,high)
    from capstone import Cs,CS_ARCH_M68K,CS_MODE_M68K_020,CS_MODE_BIG_ENDIAN
    decoder=Cs(CS_ARCH_M68K,CS_MODE_M68K_020|CS_MODE_BIG_ENDIAN)
    windows=[]
    for start,end in ((0x4E6,0x4EC),(0x7C2,0x7C8),(0x7E0,0x806),(0x890,0x97C),(0xA78,0xA8C)):
        rows=[dict(pc=i.address,size=i.size,mnemonic=i.mnemonic,operands=i.op_str)
              for i in decoder.disasm(low[start:end],start)]
        if sum(i['size'] for i in rows)!=end-start:raise ValueError('Incomplete declared instruction window')
        windows.append(dict(start=start,end_exclusive=end,sha256=hashlib.sha256(low[start:end]).hexdigest(),instructions=rows))
    by_pc={i['pc']:i for w in windows for i in w['instructions']}
    for pc,expected in ((0x7EA,'#$7, $fa07.w'),(0x7F2,'#$6, $fa07.w')):
        if by_pc[pc]['mnemonic']!='btst.b' or by_pc[pc]['operands']!=expected:raise ValueError('Reset gate changed')
    return dict(windows=windows,coverage='Only declared reset/retained-marker windows, not all firmware references',
                conditional_register_interpretation=dict(manual_url=MANUAL,section='D.2.4',register='RSR',address=0xFFFA07,
                    bit7='EXT external reset',bit6='POW power-up reset',bit5='SW software watchdog reset',bit4='HLT halt monitor reset',bit1='SYS RESET instruction',
                    writable=False,actual_mcu_identified=False))

def analyze(low,high):
    evidence=static_evidence(low,high)
    cases=[experiment(low,high,reset_status=0,retained_marker=m) for m in MARKERS]
    cases.extend(experiment(low,high,window='os_check_to_reject',reset_status=0,retained_marker=m)
                 for m in (0xD0C2,0x6124))
    cases.extend(experiment(low,high,reset_status=status,retained_marker=m)
                 for status in (2,0x10,0x20) for m in (0xD0C2,0x2FE6))
    return dict(schema='al5-offline-a12-reset-routing-v1',static=evidence,cases=cases,
                low_sha256=hashlib.sha256(low).hexdigest(),high_sha256=hashlib.sha256(high).hexdigest(),
                generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                emulator_sha256=hashlib.sha256(Path(__file__).with_name('emulate_flash_fault_recovery.py').read_bytes()).hexdigest(),
                ready_to_flash=False,recovery_verified=False,live_upload_enabled=False,live_execution_enabled=False,live_write_enabled=False,would_send=[],
                limits=['Reset status and retained marker are synthetic initial inputs, not observed power-cycle states.',
                        'RAM marker preservation is native code execution under the existing explicit alias/memory assumptions.',
                        'Read-only RSR semantics are a conditional CPU-family interpretation; writes stop the model.',
                        'Synthetic interrupt/FIFO events and software TX do not prove physical recovery or wire traffic.',
                        'No altered instructions, uploaded code or exception returns are executed.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('low','high','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():p.error('Output must be new')
    result=analyze(a.low.read_bytes(),a.high.read_bytes())
    with a.output.open('x',encoding='utf-8') as f:json.dump(result,f,indent=2)
    for c in result['cases']:
        print(hex(c['reset_status']),hex(c['retained_marker']),c['window'],c['stop'],hex(c.get('reset_marker',0)),c['software_tx_frames'])
