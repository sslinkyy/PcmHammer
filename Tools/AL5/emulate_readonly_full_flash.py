"""Full historical flash through compiled polling runtime; no devices or live operations."""
import argparse
import binascii
import hashlib
import json
import time
from pathlib import Path
from emulate_calibration_marker import validate_source
from emulate_readonly_runtime import Runtime
from emulate_readonly_core import request
from readonly_ram_layout import FIXED

SIZE=0x100000

def run(low,high,code,receipt,output_dir,boot_handoff=True,reset_context=False,preparation_context=False,input_paths=None):
    validate_source(low,high)
    flash=low+high
    dependency_names=('emulate_readonly_runtime.py','emulate_readonly_handoff.py','emulate_readonly_core.py','readonly_ram_layout.py',
                      'emulate_flash_fault_recovery.py','emulate_calibration_marker.py','emulate_boot_receive_session.py',
                      'emulate_boot_receive_isr.py','emulate_boot_session.py','emulate_readonly_native_controls.py','al5_segment.py',
                      'emulate_preparation_statuses.py','emulate_application_reset_chain.py','emulate_receive_preparation.py',
                      'emulate_application_authorization.py','emulate_application_boot.py','emulate_storage_recovery.py','emulate_storage_selection.py','checksum.py')
    source_bytes={name:Path(__file__).with_name(name).read_bytes() for name in dependency_names}
    source_bytes[Path(__file__).name]=Path(__file__).read_bytes()
    identities={name:hashlib.sha256(data).hexdigest() for name,data in source_bytes.items()}
    native_context_report=None;preparation_report=None;initial_ram=None;persistent_banks=None
    if preparation_context:
        from emulate_preparation_statuses import StatusTrace
        preparation=StatusTrace(low,high,'success');preparation_report=preparation.trace()
        if preparation_report['stop_pc']!='0xbe78c' or preparation_report['marker']!='0xbfc1':raise ValueError('Atomic preparation did not reach accepted park')
        initial_ram=bytes(preparation.uc.mem_read(0xFF8000,0x3800));persistent_banks=bytes(preparation.uc.mem_read(0x4000,0x4000))
        preparation_report['post_banks_sha256']=hashlib.sha256(persistent_banks).hexdigest()
        preparation_report['pre_banks_sha256']=hashlib.sha256(low[0x4000:0x8000]).hexdigest()
        flash=low[:0x4000]+persistent_banks+low[0x8000:]+high
        reset_context=True
    if reset_context:
        from emulate_flash_fault_recovery import experiment
        context=experiment(low,high,reset_status=0x20,retained_marker=0xBFC1,retain_context=True,initial_ram=initial_ram,initial_persistent_banks=persistent_banks)
        native_context_report=context.copy_readonly_runtime(code,receipt)
        if native_context_report['stop']!='before_offline_runtime_entry':raise ValueError('Reset-derived copy did not reach reader entry')
        r=Runtime(code,receipt,flash_image=flash,trace_detail='summary',inherited_cpu=context.cpu)
        native_handoff=context.attach_runtime(r)
        r.entry_steps=0;r.u.emu_start(receipt['entry'],0x1000000,count=100000)
    elif boot_handoff:
        from emulate_readonly_handoff import Handoff
        from emulate_boot_receive_session import frame_events
        r=Handoff(low,code,receipt,flash_image=flash,trace_detail='summary')
        r.interrupt(frame_events(bytes.fromhex('6d18f034')));r.entry_steps=0;r.transfer()
        if r.phase!='runtime' or not r.handoff:raise ValueError('No native-copy runtime entry')
    else:r=Runtime(code,receipt,flash_image=flash,trace_detail='summary')
    output_dir=Path(output_dir);output_dir.mkdir(parents=True,exist_ok=False)
    with (output_dir/'input_receipt.json').open('x',encoding='utf-8') as f:
        json.dump(dict(low_sha256=hashlib.sha256(low).hexdigest(),high_sha256=hashlib.sha256(high).hexdigest(),code_sha256=receipt['code_sha256'],source='atomic_post_preparation_fixture' if preparation_context else 'pinned_historical_flash_fixture',input_paths=input_paths,live_operations_enabled=False),f,indent=2)
    source_dir=output_dir/'source_snapshot';source_dir.mkdir()
    for name,data_bytes in source_bytes.items():(source_dir/name).write_bytes(data_bytes)
    with (output_dir/'build_receipt.json').open('x',encoding='utf-8') as f:json.dump(receipt,f,indent=2)
    (output_dir/'readonly_kernel.offline.bin').write_bytes(code)
    with (output_dir/'fixture.offline.bin').open('xb') as f:f.write(flash)
    baseline=bytes(r.u.mem_read(0xFF8000,0x4000));data=bytearray();began=time.monotonic();frames=0
    from unicorn.m68k_const import UC_M68K_REG_PC
    try:
        with (output_dir/'frames.jsonl').open('x',encoding='utf-8') as log:
            for sequence,address in enumerate(range(0,SIZE,32),1):
                wire=bytes.fromhex('6d18f0b1')+request(address,32,sequence=sequence)
                r.fifo.extend((0x20,b) for b in wire);r.fifo.append((0xE0,0));r.entry_steps=100
                pc=receipt['entry'] if sequence==1 and not boot_handoff and not reset_context else r.u.reg_read(UC_M68K_REG_PC)
                r.u.emu_start(pc,0x1000000,count=1000000)
                if r.entry_steps!=-1 or r.fifo or len(r.frames)!=sequence:raise ValueError('Persistent runtime/request boundary failed')
                reply=r.frames[-1]
                if reply[:4]!=bytes.fromhex('6df018f1') or reply[4:24]!=b'ar\x01\0'+wire[8:24] or reply[24:-2]!=flash[address:address+32] or binascii.crc_hqx(reply[4:-2],0xFFFF)!=int.from_bytes(reply[-2:],'big'):
                    raise ValueError('Compiled response correlation/content/CRC mismatch')
                data.extend(reply[24:-2]);frames+=1
                log.write(json.dumps(dict(address=address,count=32,vpw_request_hex=wire.hex(),vpw_reply_hex=reply.hex()),separators=(',',':'))+'\n')
                if sequence%1024==0:print(f'PROGRESS {sequence}/32768 requests; {len(data)}/{SIZE} bytes; {time.monotonic()-began:.1f}s',flush=True)
        if bytes(data)!=flash or r.flash_read_count!=SIZE or r.flash_read_first!=0 or r.flash_read_next!=SIZE or not r.flash_read_contiguous:raise ValueError('Full exact-once sequential coverage failed')
        quiesce=r.quiesce_from_saved_loop()
        before=(r.tx_count,r.flash_read_count)
        queued=bytes.fromhex('6d18f0b1')+request(0x4000,32,sequence=32769)
        r.fifo.extend((0x20,b) for b in queued);r.fifo.append((0xE0,0));r.entry_steps=5
        r.u.emu_start(r.u.reg_read(UC_M68K_REG_PC),0x1000000,count=100000)
        if before!=(r.tx_count,r.flash_read_count) or len(r.fifo)!=27:raise ValueError('Parked runtime accepted more work')
        r.validate_watchdog();after=bytes(r.u.mem_read(0xFF8000,0x4000));checked=0
        for offset,old in enumerate(baseline):
            address=0xFF8000+offset
            if r.base<=address<r.end or any(a<=address<b for _,a,b in FIXED):continue
            if after[offset]!=old:raise ValueError('Unowned RAM canary changed')
            checked+=1
        if bytes(r.u.mem_read(0,SIZE))!=flash:raise ValueError('Flash fixture was changed')
        with (output_dir/'readback.offline.bin').open('xb') as f:f.write(data)
        dependencies=dependency_names
        result=dict(schema='al5-offline-full-flash-campaign-v1',complete=True,bytes=len(data),request_count=frames,
                    flash_sha256=hashlib.sha256(flash).hexdigest(),readback_sha256=hashlib.sha256(data).hexdigest(),
                    low_sha256=hashlib.sha256(low).hexdigest(),high_sha256=hashlib.sha256(high).hexdigest(),code_sha256=receipt['code_sha256'],
                    bank_sha256={hex(a):hashlib.sha256(data[a:a+0x10000]).hexdigest() for a in range(0,SIZE,0x10000)},
                    generator_sha256=identities[Path(__file__).name],
                    dependency_sha256={n:identities[n] for n in dependencies},
                    persistent_cpu_ram_session=True,actual_assembly_entry_runs=1,
                    fixture_origin='atomic_post_preparation' if preparation_context else 'historical_flash',preparation_context=preparation_report,
                    startup_context='application_atomic_preparation_reset_native_copy' if preparation_context else 'reset_vector_native_copy' if reset_context else 'synthetic_boot_native_copy' if boot_handoff else 'preloaded_runtime',
                    native_reset_context=native_context_report,native_boot_handoff=native_handoff if reset_context else None if not boot_handoff else r.handoff,
                    inherited_boot_watchdog_skips=0 if reset_context or not boot_handoff else r.boot_watchdog_skips,
                    flash_read_count=r.flash_read_count,exact_once_sequential_coverage=True,watchdog_pairs=r.watchdog_count//2,
                    unowned_ram_canary_bytes_checked=checked,local_quiesce=quiesce,queued_rx_left_unprocessed=27,
                    trace_detail='summary',elapsed_seconds=time.monotonic()-began,
                    flash_writes=0,physical_readback_verified=False,physical_address_mapping_verified=False,recovery_verified=False,
                    live_upload_enabled=False,live_execution_enabled=False,live_write_enabled=False,ready_to_flash=False,
                    limits=['All bytes come from historical fixtures, not a controller readback. Peripheral/FIFO inputs are synthetic.',
                            'Reset context uses synthetic reset cause/retained marker, MMIO/FIFO and ISR entry. Legacy native-copy context also supplies stack/flag state and skips boot watchdog instructions.',
                            'No physical IRQ, exception return, TX completion, SRAM ownership, watchdog deadline or hardware exit is qualified.',
                            'Optional preparation uses atomic host effects and stubbed subsystems; its post-entry fixture is not the original pre-entry backup.'])
        with (output_dir/'result.json').open('x',encoding='utf-8') as f:json.dump(result,f,indent=2)
        return result
    except Exception as error:
        with (output_dir/'failure.json').open('x',encoding='utf-8') as f:json.dump(dict(complete=False,matched_frames=frames,bytes=len(data),error=str(error),live_operations_enabled=False),f,indent=2)
        raise

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('low','high','build_dir','output_dir'):p.add_argument('--'+name.replace('_','-'),dest=name,type=Path,required=True)
    p.add_argument('--preparation-context',action='store_true',help='Carry successful atomic preparation bank/RAM state into reset and native reader copy')
    p.add_argument('--reset-context',action='store_true',help='Start at pinned reset vectors and retain that same CPU through native copy/runtime')
    p.add_argument('--without-native-handoff',action='store_true')
    a=p.parse_args()
    if (a.reset_context or a.preparation_context) and a.without_native_handoff:p.error('Choose one startup context')
    r=run(a.low.read_bytes(),a.high.read_bytes(),(a.build_dir/'readonly_kernel.offline.bin').read_bytes(),json.loads((a.build_dir/'build_receipt.json').read_text()),a.output_dir,not a.without_native_handoff,a.reset_context,a.preparation_context,{n:dict(selected=str(getattr(a,n)),resolved=str(getattr(a,n).resolve())) for n in ('low','high','build_dir')})
    print('PASS full flash fixture',r['bytes'],'bytes',r['request_count'],'requests',r['fixture_origin'],flush=True)
