"""Native startup boundaries, explicit peripheral assumptions and preservation."""
import argparse
from pathlib import Path
import unittest
from trace_resident_main_startup import trace


COMPLETION = [
    dict(pc=0xB42FC,address=0xFFFFFE18,size=2,value=0),
    dict(pc=0xB4302,address=0xFFFFFE1A,size=2,value=0),
    dict(pc=0xB430E,address=0xFFFFFE18,size=2,value=0),
]


class StartupTests(unittest.TestCase):
    image = None

    def assert_clear_and_preserved(self, observed):
        self.assertTrue(observed['banks_unchanged'])
        for value in observed['final_state'].values():
            self.assertEqual(set(value), {'0'})
        calls = observed['main_calls']
        self.assertEqual([0xC5B54,0xC5A88,0x21CE0,0xA96F8,0x23018],
                         [row['target'] for row in calls])
        self.assertEqual([True,True,True,True,False], [row['returned'] for row in calls])
        self.assertNotIn(0xBDC38, [row['pc'] for row in observed['boundaries']])

    def test_dirty_ram_patterns_stop_at_same_uncompleted_peripheral(self):
        for pattern in (0xA5,0x5A):
            with self.subTest(pattern=pattern):
                observed=trace(self.image,pattern)
                self.assertEqual(dict(reason='unchanged_peripheral_poll',pc=0xB42FC,
                                      address=0xFFFFFE18,size=2,value=0xFDBF),observed['stop'])
                self.assertEqual([], observed['consumed_mmio_inputs'])
                self.assert_clear_and_preserved(observed)

    def test_completion_hypothesis_exposes_next_unknown_without_zero_filling(self):
        observed=trace(self.image,mmio_inputs=COMPLETION)
        self.assertEqual(COMPLETION,observed['consumed_mmio_inputs'])
        self.assertEqual([],observed['unused_mmio_inputs'])
        self.assertEqual(dict(reason='unknown_mmio_read',pc=0xB4314,
                              address=0xFFFFFE20,size=1),observed['stop'])
        self.assert_clear_and_preserved(observed)

    def test_out_of_order_assumptions_do_not_match_a_different_register(self):
        rows=COMPLETION[1:]+COMPLETION[:1]
        observed=trace(self.image,mmio_inputs=rows)
        self.assertEqual('unchanged_peripheral_poll',observed['stop']['reason'])
        self.assertEqual([],observed['consumed_mmio_inputs'])
        self.assertEqual(rows,observed['unused_mmio_inputs'])
        self.assert_clear_and_preserved(observed)

    def test_assumption_scope_rejects_invalid_address_size_and_values(self):
        for changed in ({'address':-1},{'address':0x1FFFFFE18},{'address':0x4000},
                        {'address':0xFFFFFFFF,'size':2},{'size':3},
                        {'value':65536},{'pc':0x100000},{'value':False}):
            row=dict(COMPLETION[0]);row.update(changed)
            with self.subTest(changed=changed),self.assertRaises(ValueError):
                trace(self.image,mmio_inputs=[row])

    def test_modified_saved_image_is_rejected(self):
        image=bytearray(self.image);image[0x4000]^=1
        with self.assertRaises(ValueError):trace(bytes(image))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--full-reference',type=Path,required=True)
    args=parser.parse_args();StartupTests.image=args.full_reference.read_bytes()
    unittest.main(argv=['test_trace_resident_main_startup.py'])
