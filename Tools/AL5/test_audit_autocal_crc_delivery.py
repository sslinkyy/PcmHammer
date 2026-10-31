"""Malformed geometry checks for the offline CRC differential."""
import unittest
from audit_autocal_crc_delivery import REQUEST, REPLY, crc_shape

class CrcShapeTests(unittest.TestCase):
    def test_original_geometry(self):
        self.assertEqual(crc_shape(REQUEST, REPLY), {'priority_hex':'6c','size':0x20000,'address':0x60000,'crc_hex':'d6703728'})

    def test_explicit_alternate_header_preserves_geometry(self):
        result = crc_shape(b'\x6d'+REQUEST[1:], b'\x6d'+REPLY[1:])
        self.assertEqual(result['priority_hex'], '6d')
        self.assertEqual(result['crc_hex'], 'd6703728')

    def test_rejects_mixed_headers_wrong_range_and_extent(self):
        for reply in [b'\x6d'+REPLY[1:], REPLY[:8]+b'\x07'+REPLY[9:], REPLY[:-1], REPLY+b'\x00']:
            with self.subTest(reply=reply.hex()), self.assertRaises(ValueError):
                crc_shape(REQUEST, reply)

    def test_rejects_other_services_and_request_lengths(self):
        for request in [REQUEST[:-1], REQUEST+b'\x00', REQUEST[:4]+b'\x05'+REQUEST[5:], b'\x8c'+REQUEST[1:]]:
            with self.subTest(request=request.hex()), self.assertRaises(ValueError):
                crc_shape(request, REPLY)

if __name__ == '__main__':
    unittest.main()
