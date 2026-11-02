"""Pinned boot/SPS startup and terminal control paths. All peripheral values are scripted; no devices."""
import argparse
import hashlib
import json
from pathlib import Path
from emulate_boot_session import EXPECTED_LOW
from readonly_ram_layout import FIXED

SPS_SHA = '4a03452ef44e85d1874f6b519f8b3e7fd3c2bca7332ecf11fb1aaaa1b6372d80'
BASE = 0xFF9006


def spans(addresses):
    result = []
    for a in sorted(addresses):
        if result and result[-1][1] == a:
            result[-1][1] += 1
        else:
            result.append([a, a+1])
    return result


def run(low, loader, mode, statuses, seed=0xA5, poll_limit=12):
    if len(low) != 0x20000 or hashlib.sha256(low).hexdigest() != EXPECTED_LOW:
        raise ValueError('Unrecognized LOW evidence')
    if len(loader) != 3858 or hashlib.sha256(loader).hexdigest() != SPS_SHA:
        raise ValueError('Unrecognized SPS loader')
    if mode not in ('sps_init', 'sps_timeout', 'boot_flush') or not statuses or any(type(s) is not int or not 0<=s<=255 for s in statuses):
        raise ValueError('Invalid scripted control context')
    from unicorn import Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_EXEC
    from unicorn.m68k_const import UC_CPU_M68K_M68020, UC_M68K_REG_A7, UC_M68K_REG_A6, UC_M68K_REG_SR, UC_M68K_REG_PC
    u = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
    u.ctl_set_cpu_model(UC_CPU_M68K_M68020)
    u.mem_map(0, 0x5000); u.mem_write(0, low[:0x5000]); u.mem_protect(0, 0x5000, UC_PROT_READ|UC_PROT_EXEC)
    u.mem_map(0xFF8000, 0x4000); u.mem_write(0xFF8000, bytes([seed])*0x4000); u.mem_write(BASE, loader)
    u.mem_protect(0xFF9000, 0x1000, UC_PROT_READ|UC_PROT_EXEC)
    u.mem_map(0xFFE000, 0x1000); u.mem_map(0xFFF000, 0x1000)
    u.mem_map(0x200000, 0x10000); u.mem_map(0x300000, 0x1000)
    u.reg_write(UC_M68K_REG_SR, 0x2000); u.reg_write(UC_M68K_REG_A6, 0x11223344)
    u.reg_write(UC_M68K_REG_A7, 0xFFA7F8 if mode=='boot_flush' else 0x208000)
    u.mem_write(0xFFA7F8, (0x300000).to_bytes(4, 'big'))
    observed = dict(mode=mode, scripted_statuses=statuses, stop=None, sender_calls=0, status_reads=0,
                    register_writes=[], watchdog_writes=[], ram_writes=[], flash_writes=0)
    touched = set()

    def instruction(machine, pc, size, unused):
        if pc == 0x300000:
            if mode!='boot_flush':raise ValueError('Unexpected native return')
            observed['stop']='returned';machine.emu_stop();return
        if pc == 0xFF91A0:
            observed['sender_calls'] += 1
            observed['initialized_reply_hex']=bytes(machine.mem_read(0xFFA201, 6)).hex()
            if mode=='sps_init':
                observed['stop']='before_sender';machine.emu_stop();return
            sp=machine.reg_read(UC_M68K_REG_A7)
            if int.from_bytes(machine.mem_read(sp,4),'big')!=0xFF9A00:raise ValueError('Unexpected sender caller')
            # Synthetic callback and near-threshold counter avoid inventing a physical timeout.
            machine.mem_write(0xFFA238,(0xF617).to_bytes(4,'big'))
            machine.reg_write(UC_M68K_REG_A7,sp+4);machine.reg_write(UC_M68K_REG_PC,0xFF9A00);return
        if pc == 0xFF9194:
            observed['stop']='terminal_self_branch';machine.emu_stop();return
        ranges=((0x2D30,0x2D50),(0x2D98,0x2E2E)) if mode=='boot_flush' else ((BASE,0xFF9020),(0xFF9910,0xFF9A3C),(0xFF9124,0xFF9196))
        if not any(a<=pc and pc+size<=b for a,b in ranges):raise ValueError('Native control PC escaped '+hex(pc))

    def read(machine, access, a, size, value, unused):
        if a==0xFFE800 and size==1:
            observed['status_reads']+=1
            if observed['status_reads']>poll_limit:
                observed['stop']='synthetic_poll_budget';machine.emu_stop()
            machine.mem_write(a,bytes([statuses[min(observed['status_reads']-1,len(statuses)-1)]]));return
        if (0<=a and a+size<=0x5000 or 0xFFA200<=a and a+size<=0xFFA240 or
            0xFFA700<=a and a+size<=0xFFA800 or 0x207E00<=a and a+size<=0x208000):return
        raise ValueError('Native control read outside selected ownership '+hex(a))

    def write(machine, access, a, size, value, unused):
        if a==0xFFE800 and size==1 and value in (3,0xE0,0x40) or a==0xFFE801 and size==1 and value==0:
            observed['register_writes'].append(dict(address=a,size=size,value=value));return
        if (a==0xFFFA26 and size==2 or a==0xFFFA27 and size==1) and value in (0x55,0xAA):
            observed['watchdog_writes'].append(dict(address=a,size=size,value=value));return
        if (0xFFA200<=a and a+size<=0xFFA240 or 0xFFA700<=a and a+size<=0xFFA800 or
            0x207E00<=a and a+size<=0x208000 or mode=='sps_timeout' and a==0xFF8000 and size==2 and value==0xD0C2):
            touched.update(range(a,a+size));observed['ram_writes'].append(dict(address=a,size=size,value=value));return
        raise ValueError('Native control write outside selected ownership '+hex(a))

    u.hook_add(UC_HOOK_CODE,instruction);u.hook_add(UC_HOOK_MEM_READ,read);u.hook_add(UC_HOOK_MEM_WRITE,write)
    u.emu_start(0x2D98 if mode=='boot_flush' else BASE,0x1000000,count=100000)
    if observed['stop'] is None:raise ValueError('Native control instruction budget exhausted')
    observed.update(final_pc=u.reg_read(UC_M68K_REG_PC),final_sp=u.reg_read(UC_M68K_REG_A7),sr=u.reg_read(UC_M68K_REG_SR),
                    written_ram_ranges=spans(touched),candidate_ram_overlaps={name:len(touched.intersection(range(a,b))) for name,a,b in FIXED},
                    transport_used=False,physical_reset_verified=False,live_upload_enabled=False,live_execution_enabled=False,live_write_enabled=False)
    return observed


def analyze(low,loader):
    cases=[run(low,loader,'sps_init',[0],seed=s) for s in (0xA5,0x5A)]
    for r in cases:
        assert r['stop']=='before_sender' and not r['register_writes'] and not r['watchdog_writes']
        assert r['initialized_reply_hex']=='6cf018768073' and r['sr']&0x700==0x700
        assert all(r['candidate_ram_overlaps'][n]==0 for n in ('state','receive','transmit','request','reply'))
    for status in (0,8,1):
        r=run(low,loader,'sps_timeout',[status]);cases.append(r)
        assert len(r['watchdog_writes'])==2
        if status==1:
            assert r['stop']=='synthetic_poll_budget' and not r['register_writes']
            assert not any(w['address']==0xFF8000 for w in r['ram_writes'])
        else:
            assert r['stop']=='terminal_self_branch' and any(w['address']==0xFF8000 and w['value']==0xD0C2 for w in r['ram_writes'])
            assert [(w['address'],w['value']) for w in r['register_writes']]==([(0xFFE800,0xE0),(0xFFE801,0)] if status==8 else [])+[(0xFFE800,0x40),(0xFFE801,0)]
    for statuses in ([0],[0xE0],[0xA0],[0x20,0],[0x20]):
        r=run(low,loader,'boot_flush',statuses);cases.append(r)
        assert [(w['address'],w['value']) for w in r['register_writes']]==[(0xFFE800,3),(0xFFE801,0)]
        assert r['stop']==('synthetic_poll_budget' if statuses==[0x20] else 'returned')
        if statuses==[0x20,0]:assert [(w['address'],w['size'],w['value']) for w in r['watchdog_writes']]==[(0xFFFA27,1,0x55),(0xFFFA27,1,0xAA)]
    return dict(schema='al5-offline-native-startup-exit-v1',low_sha256=EXPECTED_LOW,sps_loader_sha256=SPS_SHA,cases=cases,
                generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                peripheral_initialization_proven=False,safe_exit_proven=False,physical_ram_ownership_proven=False,
                live_upload_enabled=False,live_execution_enabled=False,live_write_enabled=False,
                limits=['Selected native paths only; all register status values are synthetic.',
                        'SPS sender callback is intercepted; near-threshold counter is a test input, not measured time.',
                        'Writing D0C2 to FF8000 is a RAM store here, not proof of physical reset.',
                        'Opcode values 03/E0/40 are observed; physical mode/speed semantics remain unknown.',
                        'A terminal self-branch is not a returning restore procedure; no safe reader exit is implemented.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('low','loader','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():p.error('New output required')
    result=analyze(a.low.read_bytes(),a.loader.read_bytes())
    with a.output.open('x',encoding='utf-8') as f:json.dump(result,f,indent=2)
    print('PASS',len(result['cases']),'native initialization/terminal/flush cases; safe exit unqualified')
