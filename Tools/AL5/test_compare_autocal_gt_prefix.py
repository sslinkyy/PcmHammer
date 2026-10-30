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


def auto_log(delivered=None):
    plan = {'profile': 'e54-read-prefix', 'flash_programming_enabled': False}
    result = {'VpwTransmissions': 2, 'VpwReceivedFrames': 1 + bool(delivered), 'Success': False}
    receipt = {'plan': plan, 'kernel_result': result, 'vpw_payload_commands_completed': 2}
    rows = [{'kind': 'plan', 'data': plan}]
    for index, (request, reply) in enumerate(((bytes.fromhex('6c10f03c0a'), ANCHOR), (tool.REQUEST, delivered))):
        raw = wrapper(request)
        rows.extend([{'kind': 'write_attempt', 'elapsed_ms': index * 100,
                      'data': {'offset': 0, 'count': len(raw), 'hex': raw.hex()}},
                     {'kind': 'write_completed', 'elapsed_ms': index * 100 + 1, 'data': {'count': len(raw)}}])
        raw = wrapper(reply, 2) if reply else b''
        rows.append({'kind': 'read_completed', 'elapsed_ms': index * 100 + 20,
                     'data': {'count': len(raw), 'hex': raw.hex()}})
    rows.extend([{'kind': 'read_completed', 'elapsed_ms': 130, 'data': {'count': 0, 'hex': ''}},
                 {'kind': 'kernel_result', 'data': result}])
    return receipt, rows


def lines(rows):
    return ('\n'.join(json.dumps(r) for r in rows) + '\n').encode()


class PairedPrefixTests(unittest.TestCase):
    def run_case(self, gt=None, delivered=None, mutate_auto=None):
        gt = gt_log([ANCHOR, response()]) if gt is None else gt
        receipt, journal = auto_log(delivered)
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

    def test_missing_data_is_retained_as_inconclusive(self):
        result = self.run_case(gt_log([ANCHOR]))
        self.assertTrue(result['comparison']['no_verified_prefix_reply_in_gt_capture'])
        self.assertFalse(result['comparison']['valid_prefix_observed_by_gt_but_not_delivered_to_autocal_host'])

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
            row = journal[3]; raw = bytes.fromhex(row['data']['hex'])
            row['data'] = {'count': 8, 'hex': raw[:8].hex()}
            journal.insert(4, {'kind': 'read_completed', 'elapsed_ms': 21,
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
        self.assertTrue(result['comparison']['valid_prefix_observed_by_gt_but_not_delivered_to_autocal_host'])
        self.assertEqual(477, result['autocal']['post_request_native_reads']['completion_count'])
        self.assertEqual(0, result['autocal']['post_request_native_reads']['returned_bytes'])
        self.assertEqual(832, result['gt']['network_frames'])
        self.assertEqual(831, result['data_candidates'][0]['gt_network_ordinal_zero_based'])
        self.assertEqual(tool.PREFIX_SHA, result['data_candidates'][0]['data_sha256'])


if __name__ == '__main__':
    unittest.main()
