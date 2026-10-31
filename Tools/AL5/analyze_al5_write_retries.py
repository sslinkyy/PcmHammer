"""Correlate saved AL5 host attempts with USB wrappers and GT observations only."""
import argparse
from collections import Counter
import json
from pathlib import Path

from al5_segment import sha256
from analyze_trace_transfers import transfer_contract
from compare_vpw_read_capture import crc8_j1850
from decode_trace_containers import decode, records
from inspect_autocal_read_gap import frame

PREFIX = bytes.fromhex('6d18f03600')
ACK = bytes.fromhex('6df0187600')


def correlate(trace, gt_text, usb):
    cycles, pending, replay = [], [], []
    usb_counts = {d: Counter(x['wrapper_hex'] for x in usb[d]) for d in ('tx', 'rx')}
    usb_missing = Counter()
    for ordinal, row in enumerate(records(decode(trace))):
        if row['kind'] != 0x42:
            continue
        f = frame(row['payload'], row['channel'])
        msg = f['payload']
        tx = f['command'] == 0x8a00 and msg.startswith(PREFIX)
        rx = f['direction'] == 2 and f['raw'][2:6] == bytes.fromhex('18000000') and msg.startswith(ACK) and len(msg) == 6
        if not (tx or rx):
            continue
        direction = 'tx' if tx else 'rx'
        raw = f['raw'].hex()
        if usb_counts[direction][raw]: usb_counts[direction][raw] -= 1
        else: usb_missing[direction] += 1
        event = dict(record_ordinal=ordinal, time_ms=row['date']*86400000,
                     kind='request' if tx else msg[3:].hex(), sha256=sha256(msg))
        if tx:
            contract = transfer_contract(msg)
            if not contract['length_matches'] or not contract['byte_sum_matches']:
                raise ValueError('Malformed host program request')
            event.update(address=int.from_bytes(msg[7:10], 'big'), bytes=len(msg), prefix11=msg[:11].hex())
            replay.append('T '+msg.hex())
        else:
            replay.append('R '+msg[3:].hex())
        pending.append(event)
        if not tx and msg[-1] == 0x73:
            requests = [x for x in pending if x['kind']=='request']
            if not requests or len({x['sha256'] for x in requests}) != 1:
                raise ValueError('Unpaired or ambiguous host positive reply')
            start = pending[0]['time_ms']
            for e in pending: e['elapsed_ms'] = round(e.pop('time_ms')-start, 3)
            cycles.append(dict(address=requests[0]['address'], request_sha256=requests[0]['sha256'],
                               prefix11=requests[0]['prefix11'], events=pending))
            pending = []
    gt_events = []
    crc_layout_confirmed = False
    preconfiguration_network_frames = 0
    for line_number, line in enumerate(gt_text.splitlines(), 1):
        row = json.loads(line)
        if row.get('kind') == 'capture_started':
            if row.get('crc_in_payload') is not True:
                raise ValueError('GT capture does not establish physical CRC layout')
            crc_layout_confirmed = True
        if row.get('kind') != 'network': continue
        if not crc_layout_confirmed:
            preconfiguration_network_frames += 1
            continue
        raw = bytes.fromhex(row['payload_hex'])
        if len(raw) < 2: continue
        msg = raw[:-1]
        if not (msg.startswith(PREFIX) or (msg.startswith(ACK) and len(msg)==6)): continue
        e = dict(line=line_number, bytes=len(msg), sha256=sha256(msg),
                 crc_valid=crc8_j1850(msg)==raw[-1], kind='request' if msg.startswith(PREFIX) else msg[3:].hex())
        if msg.startswith(PREFIX):
            if len(msg)<10: raise ValueError('GT request too short for address')
            e.update(address=int.from_bytes(msg[7:10],'big'), prefix11=msg[:11].hex())
        gt_events.append(e)
    if not crc_layout_confirmed:
        raise ValueError('GT capture lacks explicit CRC-layout evidence')
    gt_cycles, group = [], []
    for event in gt_events:
        group.append(event)
        if event['kind']=='760073': gt_cycles.append(group); group=[]
    if len(gt_cycles) != len(cycles): raise ValueError('Host and GT cycle counts differ')
    for host, bus in zip(cycles, gt_cycles):
        requests = [e for e in bus if e['kind']=='request']
        if not requests or any(e['address'] != host['address'] for e in requests):
            raise ValueError('Host/GT address ordering differs')
        if requests[-1]['sha256'] != host['request_sha256']:
            raise ValueError('Final GT request differs from full host request')
        host['gt_events'] = bus
        host['short_frames_match_host_prefix'] = all(e['prefix11']==host['prefix11'] for e in requests if e['bytes']==11)
        del host['prefix11']  # report does not disclose calibration bytes
        for e in host['events']+bus: e.pop('prefix11',None)
    patterns = Counter(' -> '.join(e['kind'] for e in c['events']) for c in cycles)
    return dict(schema='al5-write-retry-correlation-v1',trace_sha256=sha256(trace),
                gt_sha256=sha256(gt_text.encode()), cycles=cycles, patterns=dict(patterns),
                usb_program_wrapper_occurrences_missing=dict(usb_missing),
                gt_short_program_frames=sum(e['kind']=='request' and e['bytes']==11 for e in gt_events),
                preconfiguration_network_frames_excluded=preconfiguration_network_frames,
                gt_relevant_crc_failures=sum(not e['crc_valid'] for e in gt_events),
                trailing_host_events=len(pending), trailing_gt_events=len(group),
                physical_cause_proven=False, retry_authorized=False, live_write_enabled=False), replay


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('trace','gt','usb-envelopes','output','private-replay'):
        p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    report,replay=correlate(a.trace.read_bytes(),a.gt.read_bytes().decode('utf8'),json.loads(a.usb_envelopes.read_text()))
    report['usb_envelopes_sha256']=sha256(a.usb_envelopes.read_bytes())
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    a.private_replay.write_text('\n'.join(replay)+'\n',encoding='ascii')
    print(json.dumps({k:v for k,v in report.items() if k!='cycles'}))
