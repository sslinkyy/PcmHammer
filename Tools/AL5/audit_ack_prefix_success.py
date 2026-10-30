"""Offline audit of the first fixed acknowledged-prefix bench experiment."""
import json
from pathlib import Path
from inspect_autocal_read_gap import frame, is_vpw, pin
from compare_autocal_gt_prefix import audit_gt
from al5_segment import sha256

ROOT = Path(__file__).resolve().parents[2]

def inspect():
    folder = ROOT / 'LocalOnly/AutoCalBackendProbe'
    receipt = folder / 'e54_read_prefix_ack_gt_01.json'
    journal = Path(str(receipt) + '.journal.jsonl')
    capture = folder / 'gt_e54_read_prefix_ack_1x_01.jsonl'
    readback = Path(str(receipt) + '.readback.bin')
    paths = [receipt, journal, capture, readback]
    raw = [p.read_bytes() for p in paths]
    r = json.loads(raw[0]); rows = [json.loads(x) for x in raw[1].splitlines()]
    assert r['kernel_result']['Success'] and r['recorded_cleanup_accepted']
    assert r['kernel_result']['ExitAcknowledged'] and r['kernel_result']['PostExitIdentityVerified']
    assert r['identity_reply_scope'] == 'post-exit' and r['operating_system'] == 15189044
    assert r['transport_disposed'] and r['retained_native_owners'] == 0
    assert r['failure'] is None and r['channel_fault'] is None
    assert len(raw[3]) == 64 and sha256(raw[3]) == '5b20a24c0d5c5618de617dd929c4baffe7ba4cf151648398f68f0105bd43a5d9'
    rx, pending, tx = [], bytearray(), []
    for row in rows:
        if row['kind'] == 'write_attempt':
            tx.append(frame(bytes.fromhex(row['data']['hex']), 1))
        if row['kind'] != 'read_completed':
            continue
        chunk = bytes.fromhex(row['data']['hex']); assert len(chunk) == row['data']['count']
        pending.extend(chunk)
        while len(pending) >= 12:
            extent = int.from_bytes(pending[10:12], 'little') + 15
            if len(pending) < extent: break
            item = frame(bytes(pending[:extent]), 2); item['elapsed_ms'] = row['elapsed_ms']
            rx.append(item); del pending[:extent]
    assert not pending
    vpw = [x for x in rx if is_vpw(x)]
    ack = [x for x in vpw if x['payload'] == bytes.fromhex('6df010750154')]
    data = [x for x in vpw if x['payload'].startswith(bytes.fromhex('6df01036000040000000'))]
    assert len(ack) == len(data) == 1 and vpw.index(ack[0]) < vpw.index(data[0])
    b = data[0]['payload']; assert len(b) == 76 and b[10:-2] == raw[3]
    assert sum(b[4:-2]) & 65535 == int.from_bytes(b[-2:], 'big')
    network, messages, gt = audit_gt(capture, raw[2])
    positions, cursor = [], 0
    for item in vpw:
        cursor = messages.index(item['payload'], cursor); positions.append(cursor); cursor += 1
    assert len(positions) == 13
    assert all(p.read_bytes() == v for p, v in zip(paths, raw))
    return {'schema': 'autocal-ack-prefix-success-v1', 'inputs': [pin(p,v) for p,v in zip(paths,raw)],
        'implementation': pin(__file__, Path(__file__).read_bytes()), 'gt': gt,
        'application_tx': len(tx), 'application_rx': len(rx), 'ordered_shared_vpw_replies': len(positions),
        'gt_reply_ordinals': positions, 'ack_elapsed_ms': ack[0]['elapsed_ms'], 'data_elapsed_ms': data[0]['elapsed_ms'],
        'readback_length':64, 'readback_sha256':sha256(raw[3]), 'raw_block_checksum_valid':True,
        'exit_and_post_exit_os_verified':True, 'host_cleanup_verified':True,
        'full_image_verified':False, 'flashing_enabled':False,
        'limits':['One fixed prefix experiment; no full-image, 4x, losslessness, flash or recovery qualification.',
                  'Supports the preliminary acknowledgement hypothesis; does not establish internal AutoCal firmware logic.']}

if __name__ == '__main__':
    result = inspect()
    output = ROOT / 'Docs/AL5/AUTOCAL_E54_ACK_PREFIX_SUCCESS_20261030.json'
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2); stream.write('\n')
    print(json.dumps({k: result[k] for k in ('application_tx','application_rx','ordered_shared_vpw_replies','ack_elapsed_ms','data_elapsed_ms')}))
