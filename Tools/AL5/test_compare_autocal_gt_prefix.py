"""Paired analyzer regressions through real framing/replay with generated data."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import compare_autocal_gt_prefix as tool
import obdx_capture
from test_obdx_capture import CounterPort, network
from test_autocal_read_gap import wrapper


BASELINE = bytes(range(256)) * 2048
ANCHOR = bytes.fromhex('6cf0107c0a00e7c434444e')
KERNEL_ANCHOR = bytes.fromhex('6cf0107d006ab178ec36')
FLASH_ANCHOR = bytes.fromhex('6cf0107d0100894471')


def response(body=BASELINE[:64], submode=1, bad_sum=False):
    result = bytearray(tool.REPLY_HEADER)
    result[4] = submode
    result.extend(body)
    checksum = (sum(result[4:]) + bool(bad_sum)) & 0xffff
    return bytes(result) + checksum.to_bytes(2, 'big')


def gt_log(messages, *, speed='1x', bad_physical_crc=False):
    port = CounterPort()
    rows = [{'kind': 'transport', 'api': 'dvi'}]
    def emit(row):
        rows.append(row)
        if row['kind'] == 'capture_started':
            raw = b''
            for i, message in enumerate(messages):
                crc = tool.crc8_j1850(message)
                if bad_physical_crc and i == len(messages) - 1: crc ^= 1
                raw += network(message + bytes([crc]), stamp=bytes(4))
            port.replies.append(raw)
    session = obdx_capture.Session(port, emit)
    session.connect('dvi')
    session.capture(speed, .005, source_id=0x10, vpw_error_counters=True)
    rows.append({'kind': 'result', 'success': True})
    return rows


def auto_log(delivered=None, recorded=False):
    plan = {'profile': tool.PROFILES[1 if recorded else 0], 'flash_programming_enabled': False,
            'live_kernel_execution_enabled': True, 'full_baseline_read_enabled': False,
            'baseline_prefix_read_enabled': True, 'recorded_read_setup_experiment': recorded}
    result = {'VpwTransmissions': 4 if recorded else 2,
              'VpwReceivedFrames': (3 if recorded else 1) + bool(delivered),
              'Success': False, 'FlashWriteEnabled': False, **{k: recorded for k in tool.RECORDED_FLAGS}}
    receipt = {'plan': plan, 'kernel_result': result, 'vpw_payload_commands_completed': result['VpwTransmissions'],
               'setup_accepted': True, 'recorded_cleanup_accepted': False,
               'late_transfer': {'Operation': 'read', 'RequestedByteCount': 4096, 'ReturnedByteCount': 0,
                                 'IsCompleted': True, 'hex': '', 'error': None}}
    rows = [{'kind': 'plan', 'data': plan}]
    def transfer(request, reply):
        time = len(rows) * 100
        rows.extend([{'kind': 'write_attempt', 'elapsed_ms': time,
                      'data': {'offset': 0, 'count': len(request), 'hex': request.hex()}},
                     {'kind': 'write_completed', 'elapsed_ms': time + 1, 'data': {'count': len(request)}},
                     {'kind': 'read_completed', 'elapsed_ms': time + 20,
                      'data': {'count': len(reply), 'hex': reply.hex()}}])
    def local(spec):
        command, payload, reply = spec
        transfer(wrapper(payload, command=command, metadata=0), wrapper(reply, 2, metadata=command))
    for spec in tool.ORDINARY_SETUP: local(spec)
    transfer(wrapper(bytes.fromhex('6c10f03c0a')), wrapper(ANCHOR, 2))
    if recorded:
        for spec in tool.RECORDED_SETUP[:2]: local(spec)
        transfer(wrapper(bytes.fromhex('6c10f03d00')), wrapper(KERNEL_ANCHOR, 2))
        local(tool.RECORDED_SETUP[2])
        transfer(wrapper(bytes.fromhex('6c10f03d01')), wrapper(FLASH_ANCHOR, 2))
    transfer(wrapper(tool.REQUEST), wrapper(delivered, 2) if delivered else b'')
    rows.extend([{'kind': 'read_completed', 'elapsed_ms': len(rows) * 100, 'data': {'count': 0, 'hex': ''}},
                 {'kind': 'kernel_result', 'data': result}])
    return receipt, rows


def rx_row(journal, payload):
    return next(r for r in journal if r['kind'] == 'read_completed' and r['data']['hex'] == wrapper(payload, 2).hex())


def replace_transfer(journal, index, request, reply):
    """Replace one generated transaction without damaging CRC/extent/time."""
    row = journal[index]
    row['data'] = {'offset': 0, 'count': len(request), 'hex': request.hex()}
    journal[index + 1]['data'] = {'count': len(request)}
    journal[index + 2]['data'] = {'count': len(reply), 'hex': reply.hex()}


def lines(rows):
    return ('\n'.join(json.dumps(r) for r in rows) + '\n').encode()


class PairedPrefixTests(unittest.TestCase):
    def run_case(self, gt=None, delivered=None, mutate_auto=None, recorded=False):
        gt = gt_log(([ANCHOR, KERNEL_ANCHOR, FLASH_ANCHOR] if recorded else [ANCHOR]) + [response()]) if gt is None else gt
        receipt, journal = auto_log(delivered, recorded)
        if mutate_auto: mutate_auto(receipt, journal)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'gt.jsonl'; source = lines(gt); path.write_bytes(source)
            with patch.object(tool, 'BASELINE_SHA', tool.sha256(BASELINE)), patch.object(tool, 'PREFIX_SHA', tool.sha256(BASELINE[:64])):
                return tool.compare_data(json.dumps(receipt).encode(), lines(journal), path, source, BASELINE)

    def test_valid_gt_only_reply_is_proven_without_exporting_data(self):
        result = self.run_case()
        self.assertTrue(result['comparison']['valid_prefix_observed_by_gt_but_not_delivered_to_autocal_host'])
        self.assertEqual(1, result['comparison']['common_reply_count'])
        self.assertEqual(2, result['gt']['network_frames'])
        self.assertEqual(87, result['gt']['adapter_tx_frames'])
        self.assertEqual(77, result['data_candidates'][0]['physical_vpw_bytes'])
        self.assertTrue(result['data_candidates'][0]['block_additive_checksum_valid'])
        self.assertTrue(result['data_candidates'][0]['within_checked_gt_capture_context'])
        self.assertNotIn(BASELINE[:64].hex(), json.dumps(result))
        self.assertNotIn(response().hex(), json.dumps(result))

    def test_auto_received_reply_is_not_called_delivery_gap(self):
        result = self.run_case(delivered=response())
        self.assertFalse(result['comparison']['valid_prefix_observed_by_gt_but_not_delivered_to_autocal_host'])
        self.assertTrue(result['data_candidates'][0]['same_message_in_autocal_rx'])
        self.assertFalse(result['autocal']['post_request_native_reads']['all_returned_zero'])

    def test_recorded_profile_requires_three_exact_acknowledged_extra_commands(self):
        result = self.run_case(recorded=True)
        lifecycle = result['autocal']['setup_lifecycle']
        self.assertEqual(tool.PROFILES[1], result['autocal']['profile'])
        self.assertEqual(3, lifecycle['recorded_extra_commands'])
        self.assertTrue(lifecycle['recorded_preparation_and_restore_boundaries_verified'])
        self.assertEqual(2, lifecycle['local_command_counts']['8604:000000000000'])
        self.assertEqual(1, lifecycle['local_command_counts']['8603:0100f401'])
        self.assertEqual(1, lifecycle['local_command_counts']['8604:010010000000'])
        self.assertTrue(result['comparison']['valid_prefix_observed_by_gt_but_not_delivered_to_autocal_host'])
        self.assertFalse(lifecycle['configuration_effect_on_firmware_or_physical_receive_path_proven'])

    def test_profile_and_plan_result_flags_must_agree_exactly(self):
        for recorded in (False, True):
            changes = [('profile', 'arbitrary-profile'), ('recorded_read_setup_experiment', not recorded),
                       ('full_baseline_read_enabled', True), ('baseline_prefix_read_enabled', False)]
            for key, value in changes:
                with self.subTest(recorded=recorded, key=key):
                    def alter(receipt, journal): receipt['plan'][key] = value
                    with self.assertRaises(ValueError): self.run_case(recorded=recorded, mutate_auto=alter)
            for key in tool.RECORDED_FLAGS:
                with self.subTest(recorded=recorded, result=key):
                    def alter(receipt, journal): receipt['kernel_result'][key] = not recorded
                    with self.assertRaisesRegex(ValueError, 'flags disagree'):
                        self.run_case(recorded=recorded, mutate_auto=alter)
            def flash_enabled(receipt, journal): receipt['kernel_result']['FlashWriteEnabled'] = True
            with self.assertRaisesRegex(ValueError, 'disable flash'):
                self.run_case(recorded=recorded, mutate_auto=flash_enabled)

    def test_only_all_absent_ordinary_legacy_flags_are_accepted(self):
        def omit_all(receipt, journal):
            del receipt['plan']['recorded_read_setup_experiment']
            for k in tool.RECORDED_FLAGS: del receipt['kernel_result'][k]
        result = self.run_case(mutate_auto=omit_all)
        self.assertTrue(result['autocal']['setup_lifecycle']['legacy_ordinary_flags_absent'])
        with self.assertRaisesRegex(ValueError, 'flags disagree'):
            self.run_case(recorded=True, mutate_auto=omit_all)
        def omit_one(receipt, journal): del receipt['kernel_result'][tool.RECORDED_FLAGS[0]]
        with self.assertRaisesRegex(ValueError, 'flags disagree'):
            self.run_case(mutate_auto=omit_one)

    def test_missing_extra_command_or_ack_fails_exact_count(self):
        for count in (1, 3):
            def remove(receipt, journal):
                index = next(i for i, r in enumerate(journal) if r['kind'] == 'write_attempt'
                             and tool.frame(bytes.fromhex(r['data']['hex']), 1)['command'] == 0x8603)
                if count == 1: del journal[index + 2]
                else: del journal[index:index + 3]
            with self.subTest(removed_rows=count), self.assertRaisesRegex(ValueError, 'lifecycle counts'):
                self.run_case(recorded=True, mutate_auto=remove)

    def test_recorded_commands_wrong_payload_or_reply_fail_despite_valid_crc(self):
        for corrupt_reply in (False, True):
            def change(receipt, journal):
                index = next(i for i, r in enumerate(journal) if r['kind'] == 'write_attempt'
                             and tool.frame(bytes.fromhex(r['data']['hex']), 1)['command'] == 0x8603)
                request = wrapper(bytes.fromhex('0100f401') if corrupt_reply else bytes(4), command=0x8603, metadata=0)
                reply = wrapper(b'wrong' if corrupt_reply else b'', 2, metadata=0x8603)
                replace_transfer(journal, index, request, reply)
            with self.subTest(corrupt_reply=corrupt_reply), self.assertRaisesRegex(ValueError, 'lifecycle differs'):
                self.run_case(recorded=True, mutate_auto=change)

    def test_recorded_restore_before_kernel_verification_fails(self):
        def reorder(receipt, journal):
            index = next(i for i, r in enumerate(journal) if r['kind'] == 'write_attempt'
                         and tool.frame(bytes.fromhex(r['data']['hex']), 1)['payload'] == bytes.fromhex('6c10f03d00'))
            first = [copy.deepcopy(r['data']) for r in journal[index:index + 3]]
            second = [copy.deepcopy(r['data']) for r in journal[index + 3:index + 6]]
            for row, data in zip(journal[index:index + 6], second + first): row['data'] = data
        with self.assertRaisesRegex(ValueError, 'identity/kernel boundaries'):
            self.run_case(recorded=True, mutate_auto=reorder)

    def test_late_transfer_bytes_remain_private(self):
        def late(receipt, journal):
            receipt['late_transfer'] = {'Operation': 'read', 'ReturnedByteCount': 64,
                                       'RequestedByteCount': 4096, 'IsCompleted': True,
                                       'hex': BASELINE[:64].hex(), 'error': None}
        result = self.run_case(mutate_auto=late)
        self.assertNotIn(BASELINE[:64].hex(), json.dumps(result))
        self.assertEqual(tool.sha256(BASELINE[:64]), result['autocal']['reported_late_transfer']['data_sha256'])
        self.assertFalse(result['autocal']['reported_late_transfer']['raw_bytes_exported'])
        self.assertFalse(result['comparison']['valid_prefix_observed_by_gt_but_not_delivered_to_autocal_host'])
        self.assertFalse(result['comparison']['autocal_late_read_coverage_complete'])

    def test_complete_prefix_frame_in_late_read_blocks_delivery_gap_claim(self):
        def late(receipt, journal):
            raw = wrapper(response(), 2)
            receipt['late_transfer']['hex'] = raw.hex()
            receipt['late_transfer']['ReturnedByteCount'] = len(raw)
        result = self.run_case(mutate_auto=late)
        self.assertTrue(result['comparison']['known_kernel_prefix_reply_correlated_to_session'])
        self.assertFalse(result['comparison']['valid_prefix_observed_by_gt_but_not_delivered_to_autocal_host'])
        self.assertIn('nonempty_late_read_is_not_reconciled_with_journal',
                      result['autocal']['late_read_coverage']['qualification_blockers'])
        self.assertNotIn(response().hex(), json.dumps(result))

    def test_unknown_invalid_incomplete_or_errored_late_read_blocks_gap(self):
        variants = [('absent', None), ('null', None), ('nonobject', []),
                    ('IsCompleted', False), ('IsCompleted', None), ('error', 'native failure'),
                    ('missing_error', None), ('ReturnedByteCount', None), ('ReturnedByteCount', -1),
                    ('ReturnedByteCount', False), ('ReturnedByteCount', '0'), ('ReturnedByteCount', 1),
                    ('missing_returned_count', None), ('RequestedByteCount', None), ('RequestedByteCount', 0),
                    ('hex', None), ('hex', 'invalid'), ('hex', '00'), ('Operation', 'write')]
        for key, value in variants:
            def mutate(receipt, journal):
                if key == 'absent': del receipt['late_transfer']
                elif key in ('null', 'nonobject'): receipt['late_transfer'] = value
                elif key == 'missing_error': del receipt['late_transfer']['error']
                elif key == 'missing_returned_count': del receipt['late_transfer']['ReturnedByteCount']
                else: receipt['late_transfer'][key] = value
            with self.subTest(key=key, value=value):
                result = self.run_case(mutate_auto=mutate)
                self.assertFalse(result['comparison']['valid_prefix_observed_by_gt_but_not_delivered_to_autocal_host'])
                self.assertFalse(result['comparison']['autocal_late_read_coverage_complete'])
                self.assertTrue(result['autocal']['late_read_coverage']['qualification_blockers'])

    def test_recorded_identity_extent_is_exact_not_prefix_only(self):
        def malformed_identity(receipt, journal):
            row = rx_row(journal, ANCHOR)
            raw = wrapper(ANCHOR + b'\x00', 2)
            row['data'] = {'count': len(raw), 'hex': raw.hex()}
        with self.assertRaisesRegex(ValueError, 'exact identity'):
            self.run_case(recorded=True, mutate_auto=malformed_identity)

    def test_missing_data_is_retained_as_inconclusive(self):
        result = self.run_case(gt_log([ANCHOR]))
        self.assertTrue(result['comparison']['no_verified_prefix_reply_in_gt_capture'])
        self.assertFalse(result['comparison']['valid_prefix_observed_by_gt_but_not_delivered_to_autocal_host'])

    def test_stale_prefix_before_shared_anchor_is_not_current_delivery_gap(self):
        result = self.run_case(gt_log([response(), ANCHOR]))
        self.assertEqual(1, result['comparison']['matching_gt_prefix_reply_count'])
        self.assertEqual(0, result['comparison']['correlated_gt_prefix_reply_count'])
        self.assertFalse(result['comparison']['valid_prefix_observed_by_gt_but_not_delivered_to_autocal_host'])
        self.assertFalse(result['data_candidates'][0]['follows_last_common_autocal_reply_in_gt_order'])
        self.assertTrue(result['comparison']['valid_baseline_prefix_reply_observed_on_gt'])

    def test_prefix_without_shared_anchor_stays_uncorrelated(self):
        def no_replies(receipt, journal):
            journal.remove(rx_row(journal, ANCHOR))
            receipt['kernel_result']['VpwReceivedFrames'] = 0
        result = self.run_case(gt_log([response()]), mutate_auto=no_replies)
        self.assertEqual(0, result['comparison']['common_reply_count'])
        self.assertFalse(result['comparison']['nonempty_ordered_reply_anchors_present'])
        self.assertFalse(result['comparison']['all_autocal_vpw_replies_found_in_gt_order'])
        self.assertEqual(1, result['comparison']['matching_gt_prefix_reply_count'])
        self.assertEqual(0, result['comparison']['correlated_gt_prefix_reply_count'])
        self.assertFalse(result['comparison']['valid_prefix_observed_by_gt_but_not_delivered_to_autocal_host'])
        self.assertFalse(result['comparison']['known_kernel_prefix_reply_correlated_to_session'])

    def test_wrong_checksum_submode_or_baseline_never_qualifies(self):
        for data in (response(bad_sum=True), response(submode=0), response(bytes(64))):
            with self.subTest(data_hash=tool.sha256(data)):
                result = self.run_case(gt_log([ANCHOR, data]))
                self.assertEqual(0, result['comparison']['matching_gt_prefix_reply_count'])
                self.assertFalse(result['comparison']['valid_prefix_observed_by_gt_but_not_delivered_to_autocal_host'])

    def test_bad_gt_physical_crc_is_rejected_despite_valid_dvi_wrapper(self):
        with self.assertRaisesRegex(ValueError, 'physical CRC'):
            self.run_case(gt_log([ANCHOR, response()], bad_physical_crc=True))

    def test_stale_decoded_rows_cannot_create_a_match(self):
        gt = gt_log([ANCHOR])
        gt.insert(-1, {'kind': 'network', 'command': 8,
                       'payload_hex': (response() + bytes([tool.crc8_j1850(response())])).hex()})
        result = self.run_case(gt)
        self.assertEqual(1, result['gt']['network_frames'])
        self.assertEqual([], result['data_candidates'])

    def test_raw_speed_readback_cannot_be_overridden_by_label(self):
        gt = gt_log([ANCHOR, response()], speed='4x')
        next(r for r in gt if r.get('kind') == 'capture_started')['fixed_speed'] = '1x'
        with self.assertRaisesRegex(ValueError, 'context'):
            self.run_case(gt)

    def test_failed_or_unfinished_capture_does_not_qualify_cleanup(self):
        gt = gt_log([ANCHOR, response()])
        for changed in (gt[:-1], gt[:-1] + [{'kind': 'result', 'success': False}]):
            with self.assertRaisesRegex(ValueError, 'successful guarded replay'):
                self.run_case(changed)

    def test_host_guard_violation_is_rejected(self):
        gt = gt_log([ANCHOR, response()])
        gt.insert(-1, {'kind': 'adapter_tx', 'raw_hex': obdx_capture.packet(0x10, b'x').hex()})
        with self.assertRaisesRegex(ValueError, 'successful guarded replay'):
            self.run_case(gt)

    def test_missing_shared_anchor_is_not_fuzzy_matched(self):
        wrong = bytearray(ANCHOR); wrong[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'missing from the GT ordered'):
            self.run_case(gt_log([bytes(wrong), response()]))

    def test_autocal_fragmented_rx_is_reassembled_and_receipt_mismatch_fails(self):
        def split(receipt, journal):
            row = rx_row(journal, ANCHOR); raw = bytes.fromhex(row['data']['hex'])
            index = journal.index(row)
            row['data'] = {'count': 8, 'hex': raw[:8].hex()}
            journal.insert(index + 1, {'kind': 'read_completed', 'elapsed_ms': row['elapsed_ms'] + 1,
                              'data': {'count': len(raw) - 8, 'hex': raw[8:].hex()}})
        self.assertTrue(self.run_case(mutate_auto=split)['comparison']['valid_prefix_observed_by_gt_but_not_delivered_to_autocal_host'])
        receipt, journal = auto_log(); receipt = copy.deepcopy(receipt); receipt['kernel_result']['Success'] = True
        with self.assertRaisesRegex(ValueError, 'differs'):
            tool.autocal_audit(json.dumps(receipt).encode(), lines(journal))

    def test_cli_file_pins_exclusive_output_and_stability(self):
        receipt, journal = auto_log(); gt = gt_log([ANCHOR, response()])
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ('receipt.json', 'journal.jsonl', 'gt.jsonl', 'baseline.bin')]
            for path, raw in zip(paths, (json.dumps(receipt).encode(), lines(journal), lines(gt), BASELINE)):
                path.write_bytes(raw)
            output = Path(directory) / 'report.json'
            args = [v for name, path in zip(('receipt', 'journal', 'capture', 'baseline', 'output'), paths + [output]) for v in ('--' + name, str(path))]
            with patch.object(tool, 'BASELINE_SHA', tool.sha256(BASELINE)), patch.object(tool, 'PREFIX_SHA', tool.sha256(BASELINE[:64])):
                tool.main(args)
                self.assertEqual(tool.sha256(paths[2].read_bytes()), json.loads(output.read_text())['inputs']['gt_capture']['sha256'])
                with self.assertRaises(SystemExit): tool.main(args)
                original = tool.compare_data
                def mutate(*values):
                    result = original(*values); paths[0].write_bytes(b'changed'); return result
                with patch.object(tool, 'compare_data', side_effect=mutate):
                    with self.assertRaisesRegex(ValueError, 'changed'):
                        tool.inspect(*paths)

    def test_actual_private_completed_pair_when_available(self):
        root = Path(__file__).resolve().parents[2]
        paths = [root / p for p in (
            'LocalOnly/AutoCalBackendProbe/e54_read_prefix_gt_01.json',
            'LocalOnly/AutoCalBackendProbe/e54_read_prefix_gt_01.json.journal.jsonl',
            'LocalOnly/AutoCalBackendProbe/gt_e54_read_prefix_1x_01.jsonl',
            'LocalOnly/usb_capture_setup_20261030/e54_gt_pcmhammer_write_01/E54_before_test.bin')]
        if not all(p.is_file() for p in paths):
            self.skipTest('Private bench evidence is not distributed with source')
        result = tool.inspect(*paths)
        self.assertEqual(9, result['comparison']['common_reply_count'])
        self.assertEqual(1, result['comparison']['matching_gt_prefix_reply_count'])
        self.assertEqual(1, result['comparison']['correlated_gt_prefix_reply_count'])
        self.assertTrue(result['comparison']['valid_prefix_observed_by_gt_but_not_delivered_to_autocal_host'])
        self.assertEqual(477, result['autocal']['post_request_native_reads']['completion_count'])
        self.assertEqual(0, result['autocal']['post_request_native_reads']['returned_bytes'])
        self.assertEqual(832, result['gt']['network_frames'])
        self.assertEqual(831, result['data_candidates'][0]['gt_network_ordinal_zero_based'])
        self.assertEqual(tool.PREFIX_SHA, result['data_candidates'][0]['data_sha256'])

    def test_actual_private_recorded_setup_pair_when_available(self):
        root = Path(__file__).resolve().parents[2]
        paths = [root / p for p in (
            'LocalOnly/AutoCalBackendProbe/e54_read_prefix_recorded_gt_01.json',
            'LocalOnly/AutoCalBackendProbe/e54_read_prefix_recorded_gt_01.json.journal.jsonl',
            'LocalOnly/AutoCalBackendProbe/gt_e54_read_prefix_recorded_1x_01.jsonl',
            'LocalOnly/usb_capture_setup_20261030/e54_gt_pcmhammer_write_01/E54_before_test.bin')]
        if not all(p.is_file() for p in paths):
            self.skipTest('Private bench evidence is not distributed with source')
        result = tool.inspect(*paths)
        self.assertEqual(9, result['comparison']['common_reply_count'])
        self.assertEqual(1, result['comparison']['correlated_gt_prefix_reply_count'])
        self.assertTrue(result['comparison']['valid_prefix_observed_by_gt_but_not_delivered_to_autocal_host'])
        self.assertEqual(3, result['autocal']['setup_lifecycle']['recorded_extra_commands'])
        self.assertEqual(379, result['autocal']['post_request_native_reads']['completion_count'])
        self.assertEqual(0, result['autocal']['post_request_native_reads']['returned_bytes'])
        self.assertEqual(569, result['gt']['network_frames'])
        self.assertEqual(568, result['data_candidates'][0]['gt_network_ordinal_zero_based'])
        self.assertEqual(tool.PREFIX_SHA, result['data_candidates'][0]['data_sha256'])
        self.assertEqual(21, result['autocal']['application_tx_frames'])
        self.assertEqual(16, result['autocal']['application_rx_frames'])
        self.assertEqual(0, result['autocal']['receipt_observations']['retained_native_owners'])
        self.assertTrue(result['autocal']['receipt_observations']['transport_disposed'])
        self.assertEqual(0, result['autocal']['reported_late_transfer']['ReturnedByteCount'])


if __name__ == '__main__':
    unittest.main()
