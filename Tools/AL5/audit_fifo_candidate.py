"""Compare saved code with a conditional MC68HC58/SIM register interpretation.

File/emulator only. Candidate semantics are never substituted into live code.
"""
import argparse
import json
from pathlib import Path
from al5_segment import sha256
from emulate_loader_receive import experiment, frame_events

ROOT = Path(__file__).resolve().parents[2]
STARTUP = ROOT / 'Docs/AL5/STARTUP_CONTEXT_STATIC_EVIDENCE.json'
STATIC = ROOT / 'Docs/AL5/CAPTURED_LOADER_STATIC.json'
SOURCES = [
    {'url': 'https://datasheet4u.com/pdf-down/M/C/6/MC68HC58_Motorola.pdf',
     'sections': '4.2 parallel interface; 5.1 commands; 5.3 status; 5.4 completion'},
    {'url': 'https://www.nxp.com/docs/en/user-guide/MC68336376UMD.pdf',
     'sections': 'D.2.19 CSBAR; D.2.21 CSOR'},
]


def instructions(report):
    return {int(i['address'], 16): i for w in report['windows'] for i in w['instructions']}


def conditional_window(base_word, option_word):
    """Generic SIM decode, not identification of the fitted MCU or bus wiring."""
    sizes = (2048, 8192, 16384, 65536, 131072, 262144, 524288, 1048576)
    size = sizes[base_word & 7]
    base = ((base_word & 0xFFF8) << 8) & ~(size - 1)
    return {'start': hex(base), 'end_exclusive': hex(base + size), 'bytes': size,
            'mode': (option_word >> 15) & 1,
            'byte': (option_word >> 13) & 3,
            'read_write': (option_word >> 11) & 3,
            'strobe': (option_word >> 10) & 1,
            'dsack': (option_word >> 6) & 15,
            'space': (option_word >> 4) & 3,
            'ipl': (option_word >> 1) & 7, 'avec': option_word & 1}


def run(code):
    startup_bytes, static_bytes = STARTUP.read_bytes(), STATIC.read_bytes()
    startup, static = json.loads(startup_bytes), json.loads(static_bytes)
    if sha256(code) != static['payload_sha256']:
        raise ValueError('captured loader hash mismatch')
    si, li = instructions(startup), instructions(static)
    # Exact saved startup stores; never infer them from a convenient model.
    for pc, raw in ((0xC5CA6, '33fcffe800fffa54'), (0xC5CAE, '33fcd82000fffa56')):
        if si[pc]['bytes'] != raw:
            raise ValueError('saved startup register store changed')
    for pc, operands in ((0xFF952E, '#$14, $e800.w'),
                         (0xFF95BE, '#$4, $e800.w'),
                         (0xFF95B2, '#$c, $e800.w'),
                         (0xFF9086, '$e801.w, (a0)+'),
                         (0xFF9096, '$e801.w, d3')):
        if li[pc]['mnemonic'] != 'move.b' or li[pc]['operands'] != operands:
            raise ValueError('saved loader register access changed')
    body = b'\x6d\x18\xf0\x3c\x05'
    control = experiment(code, frame_events(body))
    # Literal, isolated parallel FIFO: data with completion queued, then completion.
    # No invented valid byte is supplied after completion; exhaustion is diagnostic.
    isolated = [(2, b) for b in body] + [(7, 0)]
    try:
        experiment(code, isolated)
    except RuntimeError as error:
        if str(error) != 'data read exhausted synthetic events':
            raise
        isolated_stop = 'read_after_supplied_completion'
    else:
        raise RuntimeError('isolated candidate unexpectedly completed')
    # If another frame follows, the second read consumes its first byte as flags.
    following = experiment(code, [(2, b) for b in body] + [(6, 0), (2, 0x6D)])
    return {
        'scope': 'Saved startup/loader comparison and bounded hypothetical FIFO events only.',
        'payload_sha256': sha256(code),
        'generator_sha256': sha256(Path(__file__).read_bytes()),
        'startup_evidence_sha256': sha256(startup_bytes),
        'loader_static_evidence_sha256': sha256(static_bytes),
        'sources': SOURCES,
        'conditional_sim_window': conditional_window(0xFFE8, 0xD820),
        'transmit_candidate_matches': {'first': '0x14', 'middle': '0x04', 'last': '0x0c',
                                      'busy_mask': '0x03', 'exit_control': '0x40'},
        'completion_masks': {'error_or_overrun': '0xc0', 'transmitter_involved': '0x30'},
        'receive_comparison': {
            'synthetic_control': control,
            'isolated_literal_candidate': {'stop': isolated_stop},
            'following_frame_literal_candidate': following,
            'completion_order_resolved': False},
        'limits': 'Not chip identification. CS timing, status latching, bus width, address aliasing and fitted hardware remain unknown. Existing synthetic receive cases are software branch evidence only; the literal candidate does not establish a physical firmware defect.',
        'physical_fifo_contract_verified': False, 'physical_address_aliasing_verified': False,
        'physical_mcu_identified': False, 'physical_fifo_identified': False,
        'ready_to_flash': False, 'live_write_enabled': False, 'erase_scope': None,
        'would_send': [], 'erase_packets': [], 'program_packets': []}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--loader', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.loader.resolve() == args.output.resolve():
        parser.error('output must not overwrite the loader')
    report = run(args.loader.read_bytes())
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'comparison_generated': True, 'physical_fifo_contract_verified': False}))
