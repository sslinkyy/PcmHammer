"""Actual container/CRC boundary with generated timing stimuli; no adapter."""
import struct
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import zlib

from analyze_finalization_timing import analyze, main, digest, FINALIZE, FINAL_REPLY, QUERY, IDENTITY
from decode_trace_containers import SIGNATURE
from test_autocal_read_gap import wrapper


def trace(events):
    body = b''
    for ms, direction, message in events:
        raw = wrapper(message, direction, metadata=0x18)
        body += struct.pack('<dBHHBI', 46000 + ms / 86400000, direction, 7, 2, 0x42, len(raw)) + raw
    decoded = SIGNATURE + bytes(1024-len(SIGNATURE)) + body
    return bytes(((((b ^ 0xa5) >> 3) | ((b ^ 0xa5) << 5)) + 0x87) & 255
                 for b in zlib.compress(decoded))


class TimingTests(unittest.TestCase):
    def test_unanswered_first_query_is_retained_without_pairing_or_reset_claim(self):
        r = analyze(trace([(0,1,FINALIZE),(56,2,FINAL_REPLY),(66,1,QUERY),
                           (1202,1,QUERY),(1220,2,IDENTITY)]))
        self.assertEqual(2,r['observed_query_count_before_identity'])
        self.assertAlmostEqual(10,r['final_reply_to_first_query_ms'],places=2)
        self.assertAlmostEqual(1136,r['query_spacing_ms'][0],places=2)
        self.assertAlmostEqual(1164,r['final_reply_to_identity_ms'],places=2)
        for key in ('physical_reset_verified','flash_readback_verified',
                    'identity_query_response_pairing_proven','physical_deadlines_qualified',
                    'live_write_enabled','automatic_retry_enabled'):
            self.assertFalse(r[key])
        self.assertEqual(16,len(r['final_reply']['saved_date_f64_le_hex']))

    def test_missing_final_reply_does_not_start_a_cleanup_epoch(self):
        r=analyze(trace([(0,1,FINALIZE),(20,1,QUERY),(40,2,IDENTITY)]))
        self.assertIsNone(r['final_reply']);self.assertIsNone(r['first_identity_reply'])
        self.assertIsNone(r['final_reply_to_identity_ms'])

    def test_missing_identity_has_no_invented_deadline(self):
        r=analyze(trace([(0,1,FINALIZE),(56,2,FINAL_REPLY),(66,1,QUERY)]))
        self.assertEqual(1,r['observed_query_count_before_identity'])
        self.assertIsNone(r['first_identity_reply']);self.assertIsNone(r['last_query_to_identity_ms'])

    def test_ambiguous_or_unowned_finalization_rejected(self):
        for events in ([],[(0,1,FINALIZE),(1,1,FINALIZE)],
                       [(0,2,FINAL_REPLY),(1,1,FINALIZE)],
                       [(0,1,FINALIZE),(1,2,FINAL_REPLY),(2,2,FINAL_REPLY)]):
            with self.assertRaises(ValueError):analyze(trace(events))

    def test_identity_without_post_finalization_query_rejected(self):
        with self.assertRaises(ValueError):
            analyze(trace([(0,1,QUERY),(1,1,FINALIZE),(2,2,FINAL_REPLY),(3,2,IDENTITY)]))

    def test_backwards_relevant_timestamp_rejected(self):
        with self.assertRaises(ValueError):analyze(trace([(10,1,FINALIZE),(9,2,FINAL_REPLY)]))

    def test_prior_identity_and_other_module_reply_do_not_establish_cleanup(self):
        r=analyze(trace([(0,2,IDENTITY),(1,1,FINALIZE),(2,2,FINAL_REPLY),
                         (3,1,QUERY),(4,2,bytes.fromhex('6cf0107c550a0012'))]))
        self.assertIsNone(r['first_identity_reply'])

    def test_corrupt_outer_wrapper_is_rejected_before_timing(self):
        from decode_trace_containers import decode
        data=bytearray(decode(trace([(0,1,FINALIZE)])));data[-1]^=1
        encoded=bytes(((((b ^ 0xa5) >> 3) | ((b ^ 0xa5) << 5)) + 0x87) & 255
                      for b in zlib.compress(data))
        with self.assertRaises(ValueError):analyze(encoded)

    def test_cli_hash_mismatch_creates_no_evidence_and_existing_output_is_retained(self):
        with TemporaryDirectory() as td:
            source=Path(td)/'saved.htx';output=Path(td)/'report.json'
            data=trace([(0,1,FINALIZE),(56,2,FINAL_REPLY)]);source.write_bytes(data)
            args=['timing','--trace',str(source),'--expected-sha256','0'*64,'--output',str(output)]
            with patch.object(sys,'argv',args),self.assertRaises(SystemExit):main()
            self.assertFalse(output.exists())
            args[4]=digest(data)
            output.write_text('retained evidence')
            with patch.object(sys,'argv',args),self.assertRaises(FileExistsError):main()
            self.assertEqual('retained evidence',output.read_text())


if __name__ == '__main__':unittest.main()
