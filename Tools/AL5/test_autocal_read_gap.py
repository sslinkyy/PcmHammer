"""Production analyzer/CLI regressions; generated payloads, never a device."""
import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

from checksum import crc16
from decode_trace_containers import SIGNATURE
import inspect_autocal_read_gap as tool


def wrapper(payload, direction=1, command=0x8a00, metadata=0x10):
    if direction == 1:
        head = b'\x01\x54' + command.to_bytes(2, 'little') + b'\x07\x00' + metadata.to_bytes(4, 'little')
    else:
        head = b'\x01\x52' + metadata.to_bytes(4, 'little') + bytes(4)
    raw = head + len(payload).to_bytes(2, 'little') + payload
    return raw + crc16(raw, 0).to_bytes(2, 'little') + (b'\x19' if direction == 2 else b'')


def trace_bytes(rows):
    body = b''.join(struct.pack('<dBHHBI', 46000 + i / 86400, direction, 7, 2, 0x42, len(raw)) + raw
                    for i, (direction, raw) in enumerate(rows))
    decoded = SIGNATURE + bytes(1024 - len(SIGNATURE)) + body
    return bytes(((((b ^ 0xa5) >> 3) | ((b ^ 0xa5) << 5)) + 0x87) & 255 for b in zlib.compress(decoded))


def inputs(received=b'', tx_metadata=0x10):
    plan = {'profile': 'e54-read-baseline', 'flash_programming_enabled': False,
            'kernel': {'sha256': '0' * 64, 'length': 2027}}
    result = {'VpwTransmissions': 1, 'VpwReceivedFrames': bool(received) * 1,
              'Success': False, 'FlashWriteEnabled': False}
    receipt = {'plan': plan, 'kernel_result': result, 'vpw_payload_commands_completed': 1}
    setup = wrapper(bytes(6), command=0x8604, metadata=0)
    request = wrapper(tool.FIRST_READ, metadata=tx_metadata)
    journal = [{'kind': 'plan', 'data': plan},
               {'kind': 'write_attempt', 'elapsed_ms': 0, 'data': {'offset': 0, 'count': len(setup), 'hex': setup.hex()}},
               {'kind': 'write_completed', 'elapsed_ms': 1, 'data': {'count': len(setup)}},
               {'kind': 'write_attempt', 'elapsed_ms': 10, 'data': {'offset': 0, 'count': len(request), 'hex': request.hex()}},
               {'kind': 'write_completed', 'elapsed_ms': 11, 'data': {'count': len(request)}},
               {'kind': 'read_completed', 'elapsed_ms': 20, 'data': {'count': len(received), 'hex': received.hex()}},
               {'kind': 'read_completed', 'elapsed_ms': 30, 'data': {'count': 0, 'hex': ''}},
               {'kind': 'kernel_result', 'elapsed_ms': 31, 'data': result}]
    private = b'SYNTHETIC_KERNEL_BODY_NOT_FOR_EXPORT'
    data = bytes.fromhex('6df01036001000000000') + b'Z' * 4096 + bytes(2)
    saved = [(1, wrapper(bytes.fromhex('0100f401'), command=0x8603, metadata=0)),
             (1, wrapper(bytes.fromhex('6d10f03680') + private)),
             (1, setup), (1, wrapper(tool.FIRST_READ)),
             (2, wrapper(tool.SHORT_ACK, 2)), (2, wrapper(data, 2, metadata=0))]
    return receipt, journal, saved


def serialize(receipt, journal, saved):
    return (json.dumps(receipt).encode(), ('\n'.join(json.dumps(row) for row in journal) + '\n').encode(),
            trace_bytes(saved))


class AutoCalReadGapTests(unittest.TestCase):
    def test_complete_comparison_preserves_counts_and_limits_without_private_bodies(self):
        report = tool.compare(*serialize(*inputs()))
        self.assertTrue(report['comparison']['first_request_complete_outer_wrapper_equal'])
        self.assertTrue(report['comparison']['same_last_small_setup_command_and_payload'])
        self.assertFalse(report['comparison']['physical_setup_state_equivalence_proven'])
        self.assertEqual(2, report['actual']['after_first_request_native_reads']['completion_count'])
        self.assertTrue(report['actual']['after_first_request_native_reads']['every_completion_returned_zero'])
        phase = report['saved_efilive']['data_phase']
        self.assertEqual((1, 1, 1), (phase['request_35_count'], phase['short_75_count'], phase['data_36_count']))
        self.assertEqual({'4108': 1}, phase['data_vpw_length_counts'])
        self.assertFalse(report['actual']['after_first_request_native_reads']['bus_reply_absence_proven'])
        encoded = json.dumps(report)
        self.assertNotIn(b'SYNTHETIC_KERNEL_BODY_NOT_FOR_EXPORT'.hex(), encoded)
        self.assertNotIn((b'Z' * 4096).hex(), encoded)

    def test_equal_vpw_does_not_hide_different_outer_metadata(self):
        report = tool.compare(*serialize(*inputs(tx_metadata=0)))
        self.assertTrue(report['comparison']['first_request_vpw_equal'])
        self.assertFalse(report['comparison']['first_request_complete_outer_wrapper_equal'])

    def test_received_reply_prevents_zero_byte_claim(self):
        report = tool.compare(*serialize(*inputs(received=wrapper(tool.SHORT_ACK, 2))))
        window = report['actual']['after_first_request_native_reads']
        self.assertFalse(window['every_completion_returned_zero'])
        self.assertEqual(21, window['total_returned_bytes'])

    def test_native_rx_fragmentation_is_reassembled_and_counted(self):
        receipt, journal, saved = inputs(received=wrapper(tool.SHORT_ACK, 2))
        raw = bytes.fromhex(journal[5]['data']['hex'])
        journal[5]['data'] = {'count': 8, 'hex': raw[:8].hex()}
        journal.insert(6, {'kind': 'read_completed', 'elapsed_ms': 21,
                           'data': {'count': len(raw) - 8, 'hex': raw[8:].hex()}})
        report = tool.compare(*serialize(receipt, journal, saved))
        self.assertEqual(1, report['actual']['application_rx_count'])
        self.assertEqual(3, report['actual']['after_first_request_native_reads']['completion_count'])

    def test_bad_crc_and_partial_native_frames_are_rejected(self):
        receipt, journal, saved = inputs()
        raw = bytearray.fromhex(journal[3]['data']['hex']); raw[-1] ^= 1
        journal[3]['data']['hex'] = raw.hex()
        with self.assertRaisesRegex(ValueError, 'CRC'):
            tool.compare(*serialize(receipt, journal, saved))
        receipt, journal, saved = inputs(received=b'\x01\x52')
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            tool.compare(*serialize(receipt, journal, saved))
        receipt, journal, saved = inputs()
        direction, raw = saved[-1]; raw = bytearray(raw); raw[-2] ^= 1
        saved[-1] = direction, bytes(raw)
        with self.assertRaisesRegex(ValueError, 'CRC'):
            tool.compare(*serialize(receipt, journal, saved))

    def test_partial_writes_invalid_counts_and_bad_time_are_rejected(self):
        for index, field, value, pattern in ((4, 'count', 1, 'partial'),
                                             (5, 'count', 1, 'preserved')):
            receipt, journal, saved = inputs()
            journal[index]['data'][field] = value
            with self.assertRaisesRegex(ValueError, pattern):
                tool.compare(*serialize(receipt, journal, saved))
        receipt, journal, saved = inputs()
        journal[5]['elapsed_ms'] = 5
        with self.assertRaisesRegex(ValueError, 'monotonic'):
            tool.compare(*serialize(receipt, journal, saved))

    def test_receipt_mismatch_and_wrong_profile_are_rejected(self):
        receipt, journal, saved = inputs()
        receipt = copy.deepcopy(receipt); receipt['kernel_result']['Success'] = True
        with self.assertRaisesRegex(ValueError, 'differ'):
            tool.compare(*serialize(receipt, journal, saved))
        receipt, journal, saved = inputs()
        receipt['plan']['flash_programming_enabled'] = True
        with self.assertRaisesRegex(ValueError, 'profile'):
            tool.compare(*serialize(receipt, journal, saved))

    def test_inner_signatures_do_not_become_messages_and_poll_is_reported(self):
        receipt, journal, saved = inputs()
        saved.insert(0, (1, wrapper(tool.FIRST_READ, command=0x8415)))
        saved.insert(-1, (1, wrapper(b'opaque-local-operation', command=0x9999)))
        report = tool.compare(*serialize(receipt, journal, saved))
        phase = report['saved_efilive']['data_phase']
        self.assertEqual(1, phase['request_35_count'])
        self.assertEqual('9999', phase['nonbus_host_commands'][0]['command_hex'])
        self.assertFalse(phase['no_additional_nonbus_host_poll_observed'])
        self.assertNotIn(b'opaque-local-operation'.hex(), json.dumps(report))

    def test_cli_pins_exclusive_output_and_input_stability(self):
        source = serialize(*inputs())
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            paths = [directory / name for name in ('receipt.json', 'journal.jsonl', 'trace.htx')]
            for path, raw in zip(paths, source): path.write_bytes(raw)
            output = directory / 'report.json'
            args = ['--receipt', str(paths[0]), '--journal', str(paths[1]), '--trace', str(paths[2]),
                    '--output', str(output), '--input-sha256', *(tool.sha256(raw) for raw in source)]
            tool.main(args)
            report = json.loads(output.read_text())
            self.assertEqual(tool.sha256(source[2]), report['inputs']['trace']['sha256'])
            with self.assertRaises(SystemExit): tool.main(args)
            with self.assertRaisesRegex(ValueError, 'SHA256'):
                tool.inspect(*paths, expected_hashes=['0' * 64] * 3)
            original = tool.compare
            def mutate(*args):
                result = original(*args); paths[0].write_bytes(b'changed'); return result
            with patch.object(tool, 'compare', side_effect=mutate):
                with self.assertRaisesRegex(ValueError, 'changed'):
                    tool.inspect(*paths)

    def test_saved_actual_private_experiment_when_available(self):
        root = Path(__file__).resolve().parents[2]
        paths = [root / 'LocalOnly/AutoCalBackendProbe/e54_read_baseline_01.json',
                 root / 'LocalOnly/AutoCalBackendProbe/e54_read_baseline_01.json.journal.jsonl',
                 root / 'LocalOnly/usb_capture_setup_20261030/e54_usb_read_01/crc_retained_E54_R.htx']
        if not all(path.is_file() for path in paths):
            self.skipTest('Private actual evidence is not distributed with source')
        report = tool.inspect(*paths)
        self.assertTrue(report['comparison']['first_request_complete_outer_wrapper_equal'])
        self.assertEqual(158, report['saved_efilive']['first_request']['record_ordinal_zero_based'])
        self.assertEqual(475, report['actual']['after_first_request_native_reads']['completion_count'])
        self.assertEqual(0, report['actual']['after_first_request_native_reads']['total_returned_bytes'])
        self.assertEqual((14, 9), (report['actual']['vpw_tx_count'], report['actual']['vpw_rx_count']))
        phase = report['saved_efilive']['data_phase']
        self.assertEqual((128, 128, 128), (phase['request_35_count'], phase['short_75_count'], phase['data_36_count']))
        self.assertEqual({'4106': 1, '4108': 127}, phase['data_vpw_length_counts'])
        self.assertEqual([], phase['nonbus_host_commands'])


if __name__ == '__main__':
    unittest.main()
