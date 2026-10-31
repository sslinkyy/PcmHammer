"""Offline audit of fixed acknowledged prefix and full-transfer bench experiments."""
import json
from pathlib import Path
from inspect_autocal_read_gap import frame, is_vpw, pin
from compare_autocal_gt_prefix import audit_gt
from al5_segment import sha256

ROOT = Path(__file__).resolve().parents[2]

def inspect(full=False):
    folder = ROOT / 'LocalOnly/AutoCalBackendProbe'
    receipt = folder / ('e54_full_ack_gt_01.json' if full else 'e54_read_prefix_ack_gt_01.json')
    journal = Path(str(receipt) + '.journal.jsonl')
    capture = folder / ('gt_e54_full_ack_1x_01.jsonl' if full else 'gt_e54_read_prefix_ack_1x_01.jsonl')
    readback = Path(str(receipt) + '.readback.bin')
    paths = [receipt, journal, capture, readback]
    raw = [p.read_bytes() for p in paths]
    r = json.loads(raw[0]); rows = [json.loads(x) for x in raw[1].splitlines()]
    failed_crc = full and not r['kernel_result']['Success']
    if failed_crc:
        policy, result = r['kernel_policy'], r['kernel_result']
        assert policy['CurrentPhase'] == 'ReadCrcReply'
        assert policy['ReadBlockAttempts'] == policy['ReadBlockReplies'] == 128
        assert policy['CrcQueryAttempts'] == 2 and policy['VerifiedCrcRanges'] == 0
        assert policy['BaselineShaMatched'] and not policy['IsImageVerified']
        assert result['BenchPowerCycleRequired'] and not result['ExitAcknowledged']
        assert not result['PostExitIdentityVerified'] and not result['FlashWriteEnabled']
        assert r['channel_fault'] and r['cleanup_exception'] is None and not raw[3]
    if not failed_crc:
        assert r['kernel_result']['Success'] and r['recorded_cleanup_accepted']
    if not failed_crc: assert r['kernel_result']['ExitAcknowledged'] and r['kernel_result']['PostExitIdentityVerified']
    assert r['operating_system'] == 15189044
    if not failed_crc: assert r['identity_reply_scope'] == 'post-exit'
    assert r['transport_disposed'] and r['retained_native_owners'] == 0
    if not failed_crc: assert r['failure'] is None and r['channel_fault'] is None
    expected_length = 524288 if full else 64
    expected_hash = 'a3b010af7e04df03be699198920aac26ba0645c2ad608e72eacf0bc3970beb58' if full else '5b20a24c0d5c5618de617dd929c4baffe7ba4cf151648398f68f0105bd43a5d9'
    if not failed_crc: assert len(raw[3]) == expected_length and sha256(raw[3]) == expected_hash
    if full:
        if not failed_crc: assert r['kernel_result']['ReadbackCrcVerified'] and r['kernel_policy']['VerifiedCrcRanges'] == 7
        assert r['kernel_policy']['ReadAcknowledgementCount'] == 128
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
    data = [x for x in vpw if x['payload'].startswith(bytes.fromhex('6df0103600'))]
    count, size = (128, 4096) if full else (1, 64)
    assert len(ack) == len(data) == count
    blocks = []
    for i, (a, d) in enumerate(zip(ack, data)):
        assert vpw.index(a) < vpw.index(d)
        if i: assert vpw.index(data[i-1]) < vpw.index(a)
        b = d['payload']; assert len(b) == size + 12
        assert int.from_bytes(b[5:7], 'big') == size and int.from_bytes(b[7:10], 'big') == i*size
        assert sum(b[4:-2]) & 65535 == int.from_bytes(b[-2:], 'big')
        blocks.append(b[10:-2])
    assembled = b''.join(blocks)
    assert len(assembled) == expected_length and sha256(assembled) == expected_hash
    if not failed_crc: assert assembled == raw[3]
    network, messages, gt = audit_gt(capture, raw[2])
    crc_replies = [m for m in messages if m.startswith(bytes.fromhex('6cf0107d02'))]
    if failed_crc:
        expected_crc = bytes.fromhex('6cf0107d02020000060000d6703728')
        assert crc_replies == [expected_crc, expected_crc]
        assert not any(x['payload'].startswith(bytes.fromhex('6cf0107d02')) for x in vpw)
    positions, cursor = [], 0
    for item in vpw:
        cursor = messages.index(item['payload'], cursor); positions.append(cursor); cursor += 1
    assert len(positions) == len(vpw) and len(vpw) >= (265 if failed_crc else 274 if full else 13)
    assert all(p.read_bytes() == v for p, v in zip(paths, raw))
    return {'schema': 'autocal-ack-full-crc-gap-v1' if failed_crc else 'autocal-ack-full-success-v1' if full else 'autocal-ack-prefix-success-v1', 'inputs': [pin(p,v) for p,v in zip(paths,raw)],
        'implementation': pin(__file__, Path(__file__).read_bytes()), 'gt': gt,
        'application_tx': len(tx), 'application_rx': len(rx), 'ordered_shared_vpw_replies': len(positions),
        'gt_reply_ordinals': positions, 'ack_elapsed_ms': ack[0]['elapsed_ms'], 'data_elapsed_ms': data[0]['elapsed_ms'],
        'readback_length':expected_length, 'verified_data_blocks':count, 'readback_sha256':sha256(assembled), 'saved_file_bytes':len(raw[3]), 'controller_crc_ranges_verified':r['kernel_policy']['VerifiedCrcRanges'], 'gt_crc_replies':[m.hex() for m in crc_replies], 'raw_block_checksum_valid':True,
        'exit_and_post_exit_os_verified':not failed_crc, 'host_cleanup_verified':True,
        'session_success':r['kernel_result']['Success'], 'bench_power_cycle_required':r['kernel_result']['BenchPowerCycleRequired'], 'adapter_protocol_cleanup_accepted':r['recorded_cleanup_accepted'], 'receive_channel_faulted':r['channel_fault'] is not None, 'full_image_verified':full and not failed_crc, 'complete_data_matches_baseline':True, 'flashing_enabled':False,
        'limits':['One fixed read experiment; no 4x, losslessness, flash or recovery qualification.',
                  'Supports the preliminary acknowledgement hypothesis; does not establish internal AutoCal firmware logic.']}

if __name__ == '__main__':
    import sys
    full = sys.argv[1:] == ["--full"]
    if sys.argv[1:] and not full: raise ValueError("Only --full is supported")
    result = inspect(full)
    output = ROOT / ('Docs/AL5/AUTOCAL_E54_ACK_FULL_CRC_GAP_20261030.json' if full else 'Docs/AL5/AUTOCAL_E54_ACK_PREFIX_SUCCESS_20261030.json')
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2); stream.write('\n')
    print(json.dumps({k: result[k] for k in ('application_tx','application_rx','ordered_shared_vpw_replies','ack_elapsed_ms','data_elapsed_ms')}))
