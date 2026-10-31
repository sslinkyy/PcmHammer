import unittest
from export_al5_write_rehearsal import extract
from test_autocal_read_gap import trace_bytes,wrapper


class RehearsalExportTests(unittest.TestCase):
    def test_export_preserves_order_and_explicit_exclusions(self):
        loader=bytes.fromhex('6d18f036800636ff9000')+bytes(1590)+bytes(2)
        rows=[(1,wrapper(bytes.fromhex('6c18f02701'))),
              (1,wrapper(bytes.fromhex('6c18f034'))),(2,wrapper(bytes.fromhex('6cf0187444'),2,metadata=0x18)),
              (1,wrapper(loader))]
        frames,report=extract(trace_bytes(rows))
        self.assertEqual([1,2,3],[r[0] for r in frames])
        self.assertEqual(1,report['excluded_binary_records'])
        self.assertFalse(report['security_authorization_proven'])
        self.assertFalse(report['live_write_enabled'])
        # Export is a selector, not a replacement for the production loader validator.

    def test_missing_or_duplicate_loader_rejected(self):
        with self.assertRaises(ValueError):extract(trace_bytes([]))
        loader=wrapper(bytes.fromhex('6d18f03680')+bytes(20))
        with self.assertRaises(ValueError):extract(trace_bytes([(1,loader),(1,loader)]))

if __name__=='__main__':unittest.main()
