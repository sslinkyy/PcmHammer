import unittest

from analyze_al5_write_capture import analyze
from test_autocal_read_gap import trace_bytes, wrapper


def program(address=0x8000, data=bytes(512)):
    body = b'\0' + len(data).to_bytes(2, 'big') + address.to_bytes(3, 'big') + data
    return bytes.fromhex('6d18f036') + body + (sum(body)&65535).to_bytes(2, 'big')


class WriteCaptureTests(unittest.TestCase):
    def test_real_container_boundary_preserves_duplicates_gaps_and_statuses(self):
        packet = program()
        rows = [(1, wrapper(packet)), (2, wrapper(bytes.fromhex('6df018760077'), 2, metadata=0x18)),
                (1, wrapper(packet)), (2, wrapper(bytes.fromhex('6df018760073'), 2, metadata=0x18))]
        result, corpus = analyze(trace_bytes(rows), bytes(57304))
        self.assertEqual(2, len(corpus))
        self.assertEqual(1, result['repeated_identical_requests'])
        self.assertEqual(1, result['positive_program_reply_count'])
        self.assertEqual(1, result['checksum_error_reply_count'])
        self.assertEqual(512, result['covered_bytes'])
        self.assertIsNone(result['calibration_matches_reference'])
        self.assertFalse(result['live_write_enabled'])
        self.assertFalse(result['automatic_retry_enabled'])

    def test_dense_coverage_matches_reference_without_inventing_marker(self):
        rows = [(1, wrapper(program(a, bytes(min(512, 0x1fffe-a))))) for a in range(0x8000, 0x1fffe, 512)]
        result, _ = analyze(trace_bytes(rows), bytes(57304))
        self.assertEqual(192, result['unique_address_payload_pairs'])
        self.assertEqual(98302, result['covered_bytes'])
        self.assertTrue(result['calibration_matches_reference'])
        rows.append((1, wrapper(program(data=b'\x01'*512))))
        result, _ = analyze(trace_bytes(rows), bytes(57304))
        self.assertEqual(512, len(result['conflicting_byte_addresses']))
        self.assertIsNone(result['captured_image_sha256'])

    def test_bad_transfer_or_wrapper_rejected(self):
        bad = program()[:-1]+b'\x01'
        with self.assertRaises(ValueError): analyze(trace_bytes([(1, wrapper(bad))]), bytes(57304))
        with self.assertRaises(ValueError): analyze(trace_bytes([(1, wrapper(program(0x1fffe)))]), bytes(57304))
        raw=bytearray(wrapper(program()));raw[-1]^=1
        with self.assertRaises(ValueError): analyze(trace_bytes([(1, bytes(raw))]), bytes(57304))


if __name__ == '__main__':
    unittest.main()
