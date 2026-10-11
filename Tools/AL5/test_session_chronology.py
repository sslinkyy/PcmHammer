"""Tests for recorded chronology identity and deliberately unresolved session state."""
import json
import struct
import unittest
from pathlib import Path
from unittest.mock import patch
from audit_session_chronology import summarize_records, report
from al5_segment import sha256
from test_offline import fixture
from write_plan import plan


def record(message, ordinal, channel=1, date=None, kind=0x42):
    wrapper = bytearray(12)
    wrapper[:2] = b'\x01\x54' if channel == 1 else b'\x01\x52'
    struct.pack_into('<H', wrapper, 10, len(message))
    return {'kind': kind, 'channel': channel, 'offset': 1024 + ordinal * 30,
            'date': 45000 + ordinal / 86400 if date is None else date,
            'payload': bytes(wrapper) + message + bytes(2 if channel == 1 else 3)}


def candidates(result, event, kind):
    reference = event[f'preceding_route_compatible_{kind}']
    return result['candidate_ordinal_indices'][reference['index']]['ordinals'][:reference['end_exclusive']]


class SessionChronologyTests(unittest.TestCase):
    def test_saved_chronology_matches_prior_trace_hashes_and_planner_binding(self):
        root = Path(__file__).resolve().parents[2]
        saved = json.loads((root / 'Docs/AL5/SESSION_CHRONOLOGY.json').read_text())
        prior = json.loads((root / 'Docs/AL5/TRACE_WRAPPER_AUDIT.json').read_text())
        hashes = {t['source_name']: t['source_sha256'] for t in prior['traces']}
        self.assertEqual(5, saved['trace_count'])
        self.assertEqual(2, saved['schema_version'])
        self.assertEqual(4, sum(t['subtype80_upload_count'] for t in saved['traces']))
        self.assertEqual(sha256((root / 'Tools/AL5/audit_session_chronology.py').read_bytes()), saved['generator_sha256'])
        for trace in saved['traces']:
            self.assertEqual(hashes[trace['source_name']], trace['source_sha256'])
            self.assertFalse(trace['upload_arming_verified'])
            self.assertIsNone(trace['operation_outcome'])
            ordinals = [e['record_ordinal'] for e in trace['events']]
            self.assertEqual(sorted(ordinals), ordinals)
            for event in trace['events']:
                for kind in ('requests', 'responses'):
                    if f'preceding_route_compatible_{kind}' in event:
                        selected = candidates(trace, event, kind)
                        self.assertEqual(len(selected), event[f'preceding_route_compatible_{kind[:-1]}_count'])
                        self.assertTrue(all(ordinal < event['record_ordinal'] for ordinal in selected))
        data = fixture()
        result = plan(data, data, sha256(data), 'AL5', 15184109)
        assessment = result['existing_trace_assessment']['session_chronology_assessment']
        self.assertEqual(sha256((root / assessment['evidence']).read_bytes()), assessment['evidence_sha256'])
        self.assertFalse(assessment['upload_arming_verified'])
        self.assertEqual([], result['would_send'])

    def test_route_links_include_global_and_f1_without_claiming_arming(self):
        rows = [record(b'\x8c\xfe\xf1\x34', 0),
                record(b'\x6c\xf1\x18\x74\x44', 1, 2),
                record(b'\x6d\x18\xf1\x36\x80private_loader', 2)]
        result = summarize_records(rows)
        response, upload = result['events'][1:]
        self.assertEqual(candidates(result, response, 'requests'), [0])
        self.assertEqual(candidates(result, upload, 'responses'), [1])
        self.assertFalse(response['request_pairing_verified'])
        self.assertFalse(upload['upload_arming_verified'])
        self.assertNotIn('private_loader', json.dumps(result))
        self.assertIsNone(result['operation_outcome'])

    def test_retries_and_stale_identical_response_are_explicitly_ambiguous(self):
        req = b'\x6d\x18\xf0\x34'
        ack = b'\x6c\xf0\x18\x74\x44'
        rows = [record(req, 0), record(ack, 1, 2), record(req, 2),
                record(ack, 3, 2), record(b'\x6d\x18\xf0\x36\x80', 4)]
        result = summarize_records(rows)
        self.assertEqual(candidates(result, result['events'][3], 'requests'), [0, 2])
        self.assertEqual(candidates(result, result['events'][1], 'requests'), [0])
        self.assertIn('multiple_preceding_requests_or_retries', result['events'][3]['pairing_ambiguities'])
        upload = result['events'][-1]
        self.assertEqual(candidates(result, upload, 'responses'), [1, 3])
        self.assertIn('prior_response_may_be_stale_or_unrelated', upload['pairing_ambiguities'])
        self.assertEqual(result['events'][1]['identical_message_candidate_count'], 2)

    def test_wrong_routes_are_not_paired(self):
        rows = [record(b'\x6d\x18\xf1\x34', 0),
                record(b'\x6c\xf0\x18\x74\x44', 1, 2),
                record(b'\x6d\x18\xf1\x36\x80', 2)]
        result = summarize_records(rows)
        events = result['events']
        self.assertEqual(candidates(result, events[1], 'requests'), [])
        self.assertEqual(candidates(result, events[2], 'responses'), [])

    def test_missing_request_and_response_are_preserved(self):
        events = summarize_records([record(b'\x6c\xf0\x18\x74\x44', 0, 2),
                                    record(b'\x6d\x18\xf0\x36\x80', 1)])['events']
        self.assertIn('no_preceding_route_compatible_request', events[0]['pairing_ambiguities'])
        self.assertIn('response_without_preceding_request', events[1]['pairing_ambiguities'])
        alone = summarize_records([record(b'\x6d\x18\xf0\x36\x80', 0)])['events'][0]
        self.assertIn('no_preceding_route_compatible_response', alone['pairing_ambiguities'])

    def test_ordinals_include_nonmessage_records_and_timestamps_do_not_reorder(self):
        rows = [record(b'private_text', 0, kind=0x54, date=45000),
                record(b'\x6d\x18\xf0\x34', 1, date=45000.5),
                record(b'\x6c\xf0\x18\x74\x44', 2, 2, date=45000.25)]
        result = summarize_records(rows)
        self.assertEqual([e['record_ordinal'] for e in result['events']], [1, 2])
        self.assertEqual(result['events'][0]['record_offset'], hex(1054))
        self.assertEqual([e['elapsed_ms'] for e in result['events']], [43200000, 21600000])
        self.assertFalse(result['timestamps_monotonic'])
        self.assertFalse(result['physical_timing_verified'])

    def test_unknown_wrappers_wrong_direction_and_long_response_are_not_events(self):
        broken = record(b'\x6d\x18\xf0\x34', 0)
        broken['payload'] += b'x'
        rows = [broken, record(b'\x6c\xf0\x18\x74\x44', 1),
                record(b'\x6c\xf0\x18\x74\x44x', 2, 2)]
        self.assertEqual(summarize_records(rows)['events'], [])

    def test_report_keeps_every_execution_and_recovery_gate_closed(self):
        with patch('audit_session_chronology.analyze', return_value={'operation_outcome': None}):
            result = report(['saved-trace'])
        for name in ('physical_transport_verified', 'complete_programming_exchange_verified',
                     'physical_recovery_verified', 'ready_to_flash', 'live_write_enabled'):
            self.assertIs(result[name], False)
        self.assertIsNone(result['erase_scope'])
        for name in ('would_send', 'erase_packets', 'program_packets'):
            self.assertEqual(result[name], [])
        self.assertEqual(len(result['generator_sha256']), 64)
        with self.assertRaises(ValueError):
            report([])

    def test_many_session_candidates_have_linear_shared_indices_and_serialized_growth(self):
        def model(size):
            rows = []
            for index in range(size):
                start = index * 3
                rows.extend((record(b'\x6d\x18\xf0\x34', start),
                             record(b'\x6c\xf0\x18\x74\x44', start + 1, 2),
                             record(b'\x6d\x18\xf0\x36\x80', start + 2)))
            return summarize_records(rows)
        small = model(2500)
        large = model(5000)
        self.assertEqual(sum(len(v['ordinals']) for v in large['candidate_ordinal_indices'].values()), 10000)
        self.assertEqual(candidates(large, large['events'][1], 'requests'), [0])
        final = large['events'][-1]
        self.assertEqual(final['preceding_route_compatible_request_count'], 5000)
        self.assertEqual(final['preceding_route_compatible_response_count'], 5000)
        self.assertEqual(len(candidates(large, final, 'responses')), 5000)
        self.assertLess(len(json.dumps(large)), len(json.dumps(small)) * 2.1)
        for event in large['events']:
            self.assertNotIn('preceding_route_compatible_request_ordinals', event)
            self.assertNotIn('preceding_route_compatible_response_ordinals', event)

    def test_orphan_response_prefix_survives_later_request_without_crossing_routes(self):
        result = summarize_records([record(b'\x6c\xf0\x18\x74\x44', 0, 2),
                                    record(b'\x6d\x18\xf0\x34', 1),
                                    record(b'\x6c\xf0\x18\x74\x44', 2, 2),
                                    record(b'\x6d\x18\xf0\x36\x80', 3),
                                    record(b'\x6d\x18\xf1\x36\x80', 4)])
        self.assertEqual(candidates(result, result['events'][0], 'requests'), [])
        self.assertEqual(result['events'][3]['preceding_orphan_response_count'], 1)
        self.assertEqual(result['events'][4]['preceding_orphan_response_count'], 0)


if __name__ == '__main__':
    unittest.main()
