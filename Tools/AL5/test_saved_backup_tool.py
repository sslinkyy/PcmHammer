"""Exercise the compiled file-only backup tool using synthetic correlated replies, never hardware."""
import argparse
import binascii
import json
from pathlib import Path
import subprocess


def crc(data):
    return data + binascii.crc_hqx(data, 0xFFFF).to_bytes(2, 'big')


def transcript(start, length, nonce, data, stale=False):
    lines = []
    for sequence, address in enumerate(range(start, start + length, 32), 1):
        count = min(32, start + length - address)
        tail = nonce + sequence.to_bytes(4, 'big') + address.to_bytes(3, 'big') + bytes([count])
        request = bytes.fromhex('6d18f0b1') + crc(bytes.fromhex('41520101') + tail)
        reply = bytes.fromhex('6df018f1') + crc(bytes.fromhex('61720100') + tail + data[address:address + count])
        lines.append('T ' + request.hex())
        if stale and sequence == 1:
            payload = bytearray(reply[4:-2])
            payload[4] ^= 1
            lines.append('R ' + (reply[:4] + crc(payload)).hex())
        lines.append('R ' + reply.hex())
    return lines


def run(tool, output):
    if output.exists():
        raise ValueError('New output directory required; existing evidence is retained')
    tool = tool.resolve(strict=True)
    output.mkdir(parents=True, exist_ok=False)
    original = bytes((i ^ (i >> 8)) & 255 for i in range(0x100000))
    prepared = bytearray(original)
    prepared[0x4000] ^= 1
    prepared[0x7FFF] ^= 2
    first_nonce, second_nonce = '0102030405060708', '0807060504030201'
    original_lines = transcript(0, len(original), bytes.fromhex(first_nonce), original)
    prepared_lines = transcript(0x4000, 0x4000, bytes.fromhex(second_nonce), prepared, stale=True)
    cases = [
        ('complete', original_lines, prepared_lines, first_nonce, True),
        ('partial_original', original_lines[:-2], prepared_lines, first_nonce, False),
        ('partial_prepared', original_lines, prepared_lines[:-2], first_nonce, False),
        ('wrong_nonce', original_lines, prepared_lines, '1111111111111111', False),
        ('duplicate_request', [original_lines[0]] + original_lines, prepared_lines, first_nonce, False),
        ('unowned_reply', original_lines + [original_lines[-1]], prepared_lines, first_nonce, False),
    ]
    results = []
    positive_command = None
    for name, first, second, nonce, valid in cases:
        selected = output / name
        selected.mkdir()
        original_path, prepared_path = selected / 'original.txt', selected / 'prepared.txt'
        original_path.write_text('\n'.join(first) + '\n', encoding='utf-8')
        prepared_path.write_text('\n'.join(second) + '\n', encoding='utf-8')
        destination = selected / 'export'
        command = ['dotnet', str(tool), str(original_path), str(prepared_path), nonce,
                   second_nonce, 'synthetic-' + name, str(destination)]
        process = subprocess.run(command, capture_output=True, text=True)
        if (process.returncode == 0) != valid:
            raise AssertionError((name, process.stdout, process.stderr))
        if valid:
            report = json.loads((destination / 'backup.json').read_text(encoding='utf-8'))
            assert (destination / 'original.saved.bin').read_bytes() == original
            assert (destination / 'original_banks.saved.bin').read_bytes() == original[0x4000:0x8000]
            assert (destination / 'prepared_banks.saved.bin').read_bytes() == prepared[0x4000:0x8000]
            assert report['preparation_changed_bytes'] == 2 and report['prepared_unrelated_replies'] == 1
            assert report['original_matched_replies'] == 32768 and report['prepared_matched_replies'] == 512
            for flag in ('hardware_access', 'pre_entry_physical_acquisition_verified', 'physical_address_mapping_verified',
                         'live_upload_enabled', 'live_execution_enabled', 'live_write_enabled', 'ready_to_flash'):
                assert report[flag] is False
            positive_command = command
        else:
            assert not destination.exists(), 'Invalid transcript produced output: ' + name
        results.append(dict(name=name, command=command, passed=True, exit_code=process.returncode,
                            stdout=process.stdout, stderr=process.stderr))
    process = subprocess.run(positive_command, capture_output=True, text=True)
    assert process.returncode != 0
    results.append(dict(name='existing_output_refused', passed=True, exit_code=process.returncode))
    receipt = dict(schema='al5-saved-backup-tool-tests-v1', cases=results,
                   stimuli='Synthetic image and modeled correlated reader responses only',
                   hardware_access=False, live_write_enabled=False, ready_to_flash=False)
    with (output / 'results.json').open('x', encoding='utf-8') as stream:
        json.dump(receipt, stream, indent=2)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tool', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.tool, args.output)
    print('PASS', len(result['cases']), 'file-only backup cases; no hardware')
