import json
import unittest
from analyze_al5_write_retries import correlate
from compare_vpw_read_capture import crc8_j1850
from test_autocal_read_gap import wrapper, trace_bytes
from test_al5_write_capture import program


def fixture():
    request=program(); bad=bytes.fromhex('6df018760077'); good=bytes.fromhex('6df018760073')
    rows=[(1,wrapper(request)),(2,wrapper(bad,2,metadata=0x18)),(1,wrapper(request)),(2,wrapper(good,2,metadata=0x18))]
    gt=[request[:11],bad,request,good]
    usb={d:[{'wrapper_hex':raw.hex()} for direction,raw in rows if direction==v] for d,v in [('tx',1),('rx',2)]}
    lines=json.dumps({'kind':'capture_started','crc_in_payload':True})+'\n'+'\n'.join(json.dumps({'kind':'network','payload_hex':(m+bytes([crc8_j1850(m)])).hex()}) for m in gt)
    return rows,lines,usb


class RetryTests(unittest.TestCase):
    def test_correlates_short_crc_valid_frame_and_identical_retry(self):
        rows,gt,usb=fixture();r,replay=correlate(trace_bytes(rows),gt,usb)
        self.assertEqual({'request -> 760077 -> request -> 760073':1},r['patterns'])
        self.assertEqual(1,r['gt_short_program_frames'])
        self.assertEqual(0,r['gt_relevant_crc_failures'])
        self.assertTrue(r['cycles'][0]['short_frames_match_host_prefix'])
        self.assertEqual({},r['usb_program_wrapper_occurrences_missing'])
        self.assertFalse(r['retry_authorized']);self.assertEqual(4,len(replay))

    def test_missing_usb_occurrence_not_hidden_by_duplicate(self):
        rows,gt,usb=fixture();usb['tx'].pop()
        r,_=correlate(trace_bytes(rows),gt,usb)
        self.assertEqual({'tx':1},r['usb_program_wrapper_occurrences_missing'])

    def test_changed_request_and_unpaired_reply_rejected(self):
        rows,gt,usb=fixture();rows[2]=(1,wrapper(program(0x8200)))
        with self.assertRaises(ValueError):correlate(trace_bytes(rows),gt,usb)
        with self.assertRaises(ValueError):correlate(trace_bytes([rows[-1]]),gt,usb)

    def test_truncated_host_remains_incomplete(self):
        rows,gt,usb=fixture()
        r,_=correlate(trace_bytes(rows[:1]),json.dumps({'kind':'capture_started','crc_in_payload':True}),usb)
        self.assertEqual(1,r['trailing_host_events']);self.assertEqual({},r['patterns'])

    def test_missing_crc_layout_not_guessed(self):
        rows,gt,usb=fixture()
        with self.assertRaises(ValueError):correlate(trace_bytes(rows),gt.split('\n',1)[1],usb)


if __name__=='__main__':unittest.main()
