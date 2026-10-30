"""Audit one fixed, in-memory E54 ACK+zero-submode experiment; never export a BIN.

SPDX-License-Identifier: GPL-3.0-only
Original kernel attribution: (c)2026 pcmhacking.net, Antus / Gampy collaboration.
The source and source asset remain unchanged. This is not a general patcher.
"""
import argparse
import hashlib
import importlib
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
KERNEL_PATH = Path(r'C:\Codex Projects\Car Tuning\To tune\My Original Stock Tunes\iMob Racing MultiMap OS\PcmHammer_E54_RAM_Survey_Bench_v0_1\Kernel-E54.bin')
CAPSTONE_ROOT = Path(r'C:\Codex Projects\Car Tuning\private_builds\e54_offline_python_20261015')
TRACE_PATH = ROOT / 'LocalOnly/usb_capture_setup_20261030/e54_usb_read_01/crc_retained_E54_R.htx'
BASE = 0xFF9100
LENGTH = 2027
BASE_SHA = '8294b899c153b513cd1307ac4c6654c2720832779f40c19aac7100a4b864929a'
ZERO_SHA = '17a351715bbdd366cf77e33ad5d0b801fa0747f2d31c57478ad3bb409ee58fe3'
ACK_SHA = 'eca54a2661baa317c02f96cd19a4e4bdac5a79a4c264f5154662e12e1c519664'
TRACE_SHA = '49e0b14e2e5deb3581baca6c00f8ac29e264e2006d999aa017e4c736c448987f'
EFILIVE_KERNEL_SHA = 'e2726849cc006ee7602c3391e7c39182627639edbb98d99f1392642ed5bee2a6'
SOURCE_COMMIT = 'fe8e3a9804c42e236e3326fb46e5555af27e5f3b'
SOURCE_PINS = {
    'Kernels/68k-VPW-Asm/Kernel.S': '582eeb77dcf703c1398ad63999e3f4d8304312fb23a60bb963992ebba8055d1f',
    'Kernels/68k-VPW-Asm/Common-Assembly.h': '53acc2ae5e7de4ca20f7651f894bc0e2b9d4fdfea4e495b21d47f4c11f8f2790',
    'Kernels/68k-VPW-Asm/Kernel.ld': 'e0bc65744327fea2eaa62df770e385b16ac7471ce6849abd0f042433587146d3',
    'Kernels/Build.cmd': '0e050029ecc80adedb4b8a0dc15aab9d6bf734b977b8265bc53b5f9314dc3ab6',
}
PATCHES = (
    (0x90, bytes.fromhex('67000448'), bytes.fromhex('67000702')),
    (0x794, b'(c)2026 pcmhacking.net', bytes.fromhex('41fa000c70066100fe4c6000fd3a6df0107501544e71')),
    (0x7AE, b'\x01', b'\x00'),
)
ACK = bytes.fromhex('6df010750154')
EFILIVE_WINDOWS = (
    ('accepted_read_status54', 0xFF9488, '103c0054', 'move.b #0x54,d0'),
    ('mode75_payload_builder', 0xFF9566, '31fc750191d0', 'move.w #0x7501,0x91D0.w'),
    ('data_send_branch_after_ack', 0xFF9588, '6600ff0c', 'bne.w 0xFF9496 after D7.bit0 test'),
    ('zero_submode_load', 0xFF94AE, '103c0000', 'move.b #0,d0'),
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pin(path, data):
    return {'path': str(Path(path).resolve()), 'bytes': len(data), 'sha256': sha(data)}


def branch_word(data, offset, opcode):
    if data[offset:offset + 2] != bytes.fromhex(opcode):
        raise ValueError('Unexpected fixed branch opcode')
    return BASE + offset + 2 + int.from_bytes(data[offset + 2:offset + 4], 'big', signed=True)


def validate_effective(data):
    if len(data) != LENGTH or sha(data) != ACK_SHA:
        raise ValueError('Effective kernel does not match the exact ACK+zero pin')
    targets = {
        'mode35_dispatch': branch_word(data, 0x90, '6700'),
        'ack_data': branch_word(data, 0x794, '41fa'),
        'existing_vpw_send': branch_word(data, 0x79A, '6100'),
        'original_mode35': branch_word(data, 0x79E, '6000'),
    }
    if targets != {'mode35_dispatch': 0xFF9894, 'ack_data': 0xFF98A2,
                   'existing_vpw_send': 0xFF96E8, 'original_mode35': 0xFF95DA}:
        raise ValueError('Fixed trampoline targets differ')
    if (data[0x798:0x79A] != bytes.fromhex('7006') or data[0x7A2:0x7A8] != ACK
            or data[0x7A8:0x7AA] != bytes.fromhex('4e71')
            or data[0x7AA:0x7B4] != bytes.fromhex('6df01036000000000000')):
        raise ValueError('Fixed ACK length, payload, NOP fill or data template differs')
    return targets


def upload(image, copy):
    header = bytes.fromhex('6d10f03600010bff97e0' if copy else '6d10f0368006e0ff9100')
    raw = header + (image[1760:] if copy else image[:1760])
    return raw + (sum(raw[4:]) & 0xFFFF).to_bytes(2, 'big')


def derive(source):
    """Return owned bytes and metadata; reject every input except the original pin."""
    if len(source) != LENGTH or sha(source) != BASE_SHA:
        raise ValueError('Source kernel does not match the exact original asset')
    result = bytearray(source)
    for offset, before, after in PATCHES:
        if len(before) != len(after) or bytes(result[offset:offset + len(before)]) != before:
            raise ValueError('Fixed patch old bytes or extent differ')
        result[offset:offset + len(before)] = after
    effective = bytes(result)
    targets = validate_effective(effective)
    control = bytearray(source); control[0x7AE] = 0
    if sha(control) != ZERO_SHA:
        raise ValueError('Zero-only control pin differs')
    return effective, {
        'source_sha256': BASE_SHA, 'zero_only_control_sha256': ZERO_SHA,
        'effective_sha256': ACK_SHA, 'length': LENGTH,
        'changed_bytes_vs_original': sum(a != b for a, b in zip(source, effective)),
        'changed_bytes_vs_zero_only_control': sum(a != b for a, b in zip(control, effective)),
        'patches': [{'file_offset': o, 'ram_address': BASE + o, 'length': len(a),
                     'old_hex': a.hex(), 'new_hex': b.hex()} for o, a, b in PATCHES],
        'derived_targets': targets,
        'stub_code_bytes': 14, 'ack_data_bytes': 6, 'trailing_nop_fill_bytes': 2,
        'ack_payload_hex': ACK.hex(), 'expected_read_reply_submode': 0,
        'message_buffer_address_unchanged': 0xFF98EB,
        'kernel_end_exclusive_unchanged': BASE + LENGTH,
        'uploaded_ram_extents_unchanged': [{'start': 0xFF97E0, 'bytes': 267}, {'start': BASE, 'bytes': 1760}],
        'effective_ram_messages': [{'operation': 'copy' if c else 'execute', 'bytes': len(upload(effective, c)),
                                   'sha256': sha(upload(effective, c)), 'block_checksum_hex': upload(effective, c)[-2:].hex()}
                                  for c in (True, False)],
        'source_file_modified': False, 'binary_output_supported': False,
    }


def decode_audit(source, effective, capstone_root):
    if capstone_root is not None:
        sys.path.insert(0, str(Path(capstone_root).resolve()))
    cs = importlib.import_module('capstone')
    decoder = cs.Cs(cs.CS_ARCH_M68K, cs.CS_MODE_BIG_ENDIAN | cs.CS_MODE_M68K_020)
    code = list(decoder.disasm(source[:0x792], BASE))
    if sum(x.size for x in code) != 0x792 or len(code) != 516 or any(x.mnemonic == 'dc.w' for x in code):
        raise ValueError('Original executable text was not fully decoded')
    direct = []
    for ins in code:
        for token in re.findall(r'\$([0-9a-f]+)', ins.op_str):
            value = int(token, 16)
            # Include signed absolute-short aliases conservatively; dynamic
            # register-derived pointers are explicitly outside this scan.
            if 0x8000 <= value <= 0xFFFF:
                value |= 0xFF0000
            value &= 0xFFFFFF
            if 0xFF9894 <= value < 0xFF98AA:
                direct.append({'instruction_address': ins.address, 'operand_address': value})
    if direct:
        raise ValueError('Existing decoded literal operand refers to the proposed metadata space')
    stub = list(decoder.disasm(effective[0x794:0x7A2], BASE + 0x794))
    expected = [('lea.l', '$ff98a2(pc), a0'), ('moveq', '#$6, d0'),
                ('bsr.w', '$ff96e8'), ('bra.w', '$ff95da')]
    if [(x.mnemonic, x.op_str) for x in stub] != expected:
        raise ValueError('Independent decoder disagrees with fixed trampoline')
    library = Path(cs._cs._name)
    return {'decoder': 'Capstone M68K020 (covers the original CPU32 long branch)', 'version': cs.__version__,
            'python_module': pin(cs.__file__, Path(cs.__file__).read_bytes()),
            'native_decoder': pin(library, library.read_bytes()),
            'original_executable_bytes': 0x792, 'decoded_instructions': len(code),
            'undecoded_words': 0, 'literal_address_references_to_metadata': direct,
            'alignment_bytes_excluded_from_instruction_scan': {'offset': 0x792, 'hex': source[0x792:0x794].hex()},
            'stub': [{'address': x.address, 'bytes_hex': x.bytes.hex(), 'mnemonic': x.mnemonic, 'operands': x.op_str} for x in stub],
            'reference_scope': 'All decoded literal operands/branch targets; not a proof about arbitrary runtime-derived pointers.'}


def source_audit(repo):
    evidence = []
    for path, expected in SOURCE_PINS.items():
        data = subprocess.check_output(['git', '-C', str(repo), 'show', SOURCE_COMMIT + ':' + path])
        if sha(data) != expected:
            raise ValueError('Pinned source blob changed: ' + path)
        evidence.append({'git_commit': SOURCE_COMMIT, 'path': path, 'bytes': len(data), 'sha256': sha(data)})
    return evidence


def trace_audit(path):
    from decode_trace_containers import decode, records
    from inspect_autocal_read_gap import frame, is_vpw
    source = Path(path).read_bytes()
    if sha(source) != TRACE_SHA:
        raise ValueError('EFILive comparison trace does not match its pin')
    frames = []
    for ordinal, row in enumerate(records(decode(source))):
        if row['kind'] == 0x42:
            item = frame(row['payload'], row['channel']); item['ordinal'] = ordinal; frames.append(item)
    requests = [i for i, f in enumerate(frames) if f['direction'] == 1 and f['command'] == 0x8A00
                and f['payload'].startswith(bytes.fromhex('6d10f03501'))]
    triples, intervening_tx = [], 0
    for n, start in enumerate(requests):
        stop = requests[n + 1] if n + 1 < len(requests) else len(frames)
        part = frames[start + 1:stop]
        acks = [i for i, f in enumerate(part) if f['direction'] == 2 and is_vpw(f) and f['payload'] == ACK]
        data = [i for i, f in enumerate(part) if f['direction'] == 2 and is_vpw(f)
                and f['payload'].startswith(bytes.fromhex('6df0103600'))]
        if len(acks) != 1 or len(data) != 1 or acks[0] >= data[0]:
            raise ValueError('Recorded ACK/data ordering differs')
        intervening_tx += sum(f['direction'] == 1 for f in part[acks[0] + 1:data[0]])
        triples.append([frames[start]['ordinal'], part[acks[0]]['ordinal'], part[data[0]]['ordinal']])
    kernel = next(f['payload'][10:-2] for f in frames if f['ordinal'] == 125)
    if len(triples) != 128 or intervening_tx != 0 or sha(kernel) != EFILIVE_KERNEL_SHA:
        raise ValueError('Recorded EFILive read/kernel evidence differs')
    windows = []
    for name, address, expected, meaning in EFILIVE_WINDOWS:
        offset = address - 0xFF9200
        if kernel[offset:offset + len(expected) // 2] != bytes.fromhex(expected):
            raise ValueError('Recorded EFILive instruction window differs: ' + name)
        windows.append({'role': name, 'ram_address': address, 'uploaded_kernel_offset': offset,
                        'bytes_hex': expected, 'instruction': meaning})
    return {'input': pin(path, source), 'ordered_request_ack_data_triplets': len(triples),
            'host_commands_between_ack_and_data': intervening_tx,
            'first_triplet_record_ordinals': triples[0], 'last_triplet_record_ordinals': triples[-1],
            'uploaded_kernel_bytes': len(kernel), 'uploaded_kernel_sha256': sha(kernel),
            'uploaded_kernel_address': 0xFF9200,
            'checked_instruction_windows': windows,
            'firmware_requires_ack': 'unknown', 'raw_kernel_or_tune_exported': False}


def inspect(kernel_path=KERNEL_PATH, repo=ROOT, trace_path=TRACE_PATH, capstone_root=CAPSTONE_ROOT):
    helpers = ('derive_autocal_ack_kernel.py', 'decode_trace_containers.py', 'inspect_autocal_read_gap.py',
               'audit_trace_wrappers.py', 'checksum.py', 'al5_segment.py', 'inspect_trace_containers.py')
    implementation = {Path(__file__).with_name(n): Path(__file__).with_name(n).read_bytes() for n in helpers}
    if Path(kernel_path).stat().st_size != LENGTH:
        raise ValueError('Source kernel extent differs')
    source = Path(kernel_path).read_bytes()
    effective, derivation = derive(source)
    result = {'schema': 'autocal-e54-ack-kernel-derivation-v1', 'source_kernel': pin(kernel_path, source),
              'derivation': derivation, 'decoder_audit': decode_audit(source, effective, capstone_root),
              'source_provenance': source_audit(repo), 'recorded_efilive_evidence': trace_audit(trace_path),
              'attribution_preserved': '(c)2026 pcmhacking.net; Antus / Gampy collaboration; GPL-3.0-only source.',
              'register_and_stack_reasoning': [
                  'Dispatch uses BEQ, not BSR; entering the metadata stub adds no return address.',
                  'Stub overwrites A0/D0 and existing VPWSend/WaitForTXFIFO clobber A0/D0/D2.',
                  'VPWSend tail-branches to its existing completion flush, whose RTS balances the stub BSR.',
                  'Final stub BRA enters original ProcessMode35 with no pending stub frame.',
                  'ProcessMode35 clears D0 and reloads absolute MessageBuffer address/length into A0/D0.',
                  'VPWSendBlock initializes D1 and clears D2 before calculating the data checksum.',
                  'ACK send and data send occur sequentially, reusing existing nested call depth and stack location.',
              ],
              'limits': [
                  'Offline byte derivation and decode only; this variant has not been executed by this tool.',
                  'The original asset was not rebuilt. Source commit is pinned provenance corroborated by decoded bytes, not a reproducible-build claim.',
                  'Only the metadata and dispatch spans are repurposed; no new RAM region, buffer relocation or image-length change.',
                  'The preliminary54 reply precedes request parsing and is scoped to the one policy-pinned64-byte,address-zero request. No arbitrary-request negative-response implementation is claimed.',
                  'No extra guessed delay is added. Existing VPWSend FIFO/completion waits remain hardware-dependent and are not made bounded by this patch.',
                  'EFILive also uses its own timing and kernel implementation. Observed ACK ordering does not prove AutoCal firmware requires it.',
                  'The unchanged version reply cannot distinguish the variant. Exact upload hashes and observed ACK/data wire sequence are required evidence.',
                  'Live host-policy, parser and native-boundary integration require separate review; no write or recovery qualification is established.',
              ],
              'adapter_opened': False, 'kernel_executed': False, 'binary_exported': False,
              'flash_programming_enabled': False, 'ready_to_flash': False}
    if Path(kernel_path).read_bytes() != source:
        raise ValueError('Source kernel changed during audit')
    if any(path.read_bytes() != data for path, data in implementation.items()):
        raise ValueError('Analysis implementation changed during audit')
    result['implementation'] = [pin(path, data) for path, data in implementation.items()]
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, default=KERNEL_PATH)
    parser.add_argument('--repo', type=Path, default=ROOT)
    parser.add_argument('--trace', type=Path, default=TRACE_PATH)
    parser.add_argument('--capstone-root', type=Path, default=CAPSTONE_ROOT)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.output is not None and args.output.exists():
            raise ValueError('Output already exists; no evidence overwrite')
        result = inspect(args.kernel, args.repo, args.trace, args.capstone_root)
        encoded = json.dumps(result, indent=2) + '\n'
        if args.output is None:
            print(encoded, end='')
        else:
            with args.output.open('x', encoding='utf-8', newline='\n') as stream:
                stream.write(encoded)
            print(json.dumps({'output': str(args.output), 'sha256': sha(encoded.encode()),
                              'effective_kernel_sha256': ACK_SHA, 'binary_exported': False}))
    except (ValueError, OSError, ImportError, subprocess.CalledProcessError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
