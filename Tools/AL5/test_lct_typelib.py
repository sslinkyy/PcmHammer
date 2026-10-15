import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import uuid

from audit_lct_typelib import (INTERFACE_GUID, EXPECTED_NAMES, audit, main,
                               parse_msft, typelib_resources)


def minimal_typelib(pointer_depth=1):
    """One dispatch interface, one HRESULT method with an out/retval SHORT*."""
    b = bytearray(328)
    b[:4] = b'MSFT'
    struct.pack_into('<I', b, 4, 0x10002)
    struct.pack_into('<I', b, 32, 1)
    for i in range(15):
        struct.pack_into('<4I', b, 88+i*16, 0xffffffff, 0, 0xffffffff, 15)

    def segment(i, value):
        start = len(b)
        b.extend(value)
        struct.pack_into('<2I', b, 88+i*16, start, len(value))
        return start

    typeinfo = segment(0, bytes(100))
    segment(5, uuid.UUID(INTERFACE_GUID).bytes_le+bytes(8))
    names = bytearray()
    no = []
    for text in ('IEcuInterface', 'ReturnToNormalMode', 'nRetVal'):
        no.append(len(names))
        raw = text.encode('ascii')
        names.extend(struct.pack('<3I', 0, 0xffffffff, len(raw))+raw)
        names.extend(bytes((-len(names)) % 4))
    segment(7, names)
    typedescs = bytearray()
    for i in range(pointer_depth):
        target = (i+1)*8 if i+1 < pointer_depth else 0x80020002
        typedescs.extend(struct.pack('<2I', 0x4002001a, target))
    td = segment(9, typedescs)
    member = len(b)
    rec = struct.pack('<8I', 44, 0x80190019, 0, 44, 0x4409, 1, 0, 0)
    rec += struct.pack('<3I', 0, no[2], 0xa)
    b.extend(struct.pack('<I', len(rec))+rec+struct.pack('<3I', 5, no[1], 0))
    struct.pack_into('<I', b, typeinfo, 4)
    struct.pack_into('<I', b, typeinfo+4, member)
    struct.pack_into('<I', b, typeinfo+24, 1)
    struct.pack_into('<I', b, typeinfo+44, 0)
    struct.pack_into('<I', b, typeinfo+52, no[0])
    return b, {'typeinfo': typeinfo, 'td': td, 'member': member}


def minimal_pe(payload):
    b = bytearray(512+128+len(payload))
    b[:2] = b'MZ'
    struct.pack_into('<I', b, 0x3c, 0x80)
    b[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', b, 0x86, 1)
    struct.pack_into('<H', b, 0x94, 224)
    opt = 0x98
    struct.pack_into('<H', b, opt, 0x10b)
    struct.pack_into('<I', b, opt+60, 512)
    struct.pack_into('<I', b, opt+92, 16)
    struct.pack_into('<2I', b, opt+112, 0x1000, 128+len(payload))
    section = opt+224
    struct.pack_into('<3I', b, section+12, 0x1000, len(b)-512, 512)
    for offset, ident, child in ((0, 0x80000058, 0x80000018),
                                  (24, 1, 0x80000030), (48, 1033, 72)):
        struct.pack_into('<2H', b, 512+offset+12, int(offset == 0), int(offset != 0))
        struct.pack_into('<2I', b, 512+offset+16, ident, child)
    struct.pack_into('<4I', b, 512+72, 0x1080, len(payload), 0, 0)
    struct.pack_into('<H', b, 512+88, 7)
    b[512+90:512+104] = 'TYPELIB'.encode('utf-16le')
    b[640:] = payload
    return b


class TypelibTests(unittest.TestCase):
    def test_pin_rejects_before_any_parsing(self):
        with patch('audit_lct_typelib.typelib_resources') as parser:
            with self.assertRaisesRegex(ValueError, 'hash differs'):
                audit(b'changed source')
            parser.assert_not_called()

    def test_resource_tree_and_declared_signature(self):
        tlb, _ = minimal_typelib()
        resources = typelib_resources(minimal_pe(tlb))
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['file_offset'], 640)
        report = parse_msft(resources[0]['data'], 640)
        method = report['methods'][0]
        self.assertEqual((method['slot'], method['name']['text']), (11, 'ReturnToNormalMode'))
        self.assertEqual(method['return']['type'], 'HRESULT')
        self.assertEqual(method['parameters'][0]['type']['target']['type'], 'SHORT')
        self.assertTrue(method['parameters'][0]['out'])
        self.assertTrue(method['parameters'][0]['retval'])
        self.assertEqual(method['dll_file_offset'], 640+method['typelib_offset'])

    def test_resource_directory_cycle_and_unmapped_payload_rejected(self):
        tlb, _ = minimal_typelib()
        cyclic = minimal_pe(tlb)
        struct.pack_into('<I', cyclic, 512+20, 0x80000000)
        with self.assertRaisesRegex(ValueError, 'Cyclic'):
            typelib_resources(cyclic)
        unmapped = minimal_pe(tlb)
        struct.pack_into('<I', unmapped, 512+72, 0x70000000)
        with self.assertRaisesRegex(ValueError, 'Unmapped'):
            typelib_resources(unmapped)

    def test_truncated_or_out_of_segment_references_rejected(self):
        tlb, loc = minimal_typelib()
        with self.assertRaises(ValueError):
            parse_msft(tlb[:320])
        struct.pack_into('<I', tlb, loc['typeinfo']+52, 0x7fffffff)
        with self.assertRaisesRegex(ValueError, 'owning segment'):
            parse_msft(tlb)

    def test_parameter_record_bounds_and_member_offset_consistency(self):
        tlb, loc = minimal_typelib()
        struct.pack_into('<H', tlb, loc['member']+4+20, 3)
        with self.assertRaisesRegex(ValueError, 'parameters exceed'):
            parse_msft(tlb)
        tlb, loc = minimal_typelib()
        struct.pack_into('<I', tlb, loc['member']+4+44+8, 4)
        with self.assertRaisesRegex(ValueError, 'offset array'):
            parse_msft(tlb)

    def test_type_cycle_rejected_and_unknown_vartype_retained(self):
        tlb, loc = minimal_typelib()
        struct.pack_into('<I', tlb, loc['td']+4, 0)
        with self.assertRaisesRegex(ValueError, 'Cyclic type'):
            parse_msft(tlb)
        struct.pack_into('<I', tlb, loc['td']+4, 0x80fa00fa)
        param = parse_msft(tlb)['methods'][0]['parameters'][0]
        self.assertEqual(param['type']['target']['raw'], '0x80fa00fa')
        self.assertIsNone(param['type']['target']['type'])
        self.assertTrue(param['type']['target']['unknown'])

    def test_long_pointer_chain_stays_flat_and_bounded_by_source(self):
        tlb, _ = minimal_typelib(pointer_depth=3000)
        param = parse_msft(tlb)['methods'][0]['parameters'][0]
        self.assertEqual(param['type']['pointer_depth'], 3000)
        self.assertEqual(len(param['type']['pointer_chain']), 3000)
        self.assertEqual(param['type']['target']['type'], 'SHORT')

    def test_existing_output_refused_before_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'source.dll'
            output.write_bytes(b'preserve')
            with patch('audit_lct_typelib.audit') as auditor, patch('sys.stderr'), \
                    self.assertRaises(SystemExit):
                main([str(output), '--output', str(output)])
            auditor.assert_not_called()
            self.assertEqual(output.read_bytes(), b'preserve')

    @unittest.skipUnless(os.environ.get('AL5_LCT_DLL'), 'Set AL5_LCT_DLL for installed pinned artifact')
    def test_real_pinned_embedded_interface(self):
        report = audit(Path(os.environ['AL5_LCT_DLL']).read_bytes())
        self.assertEqual(len(report['types']), 7)
        self.assertEqual(len(report['methods']), 28)
        self.assertEqual(tuple(m['name']['text'] for m in report['methods']), EXPECTED_NAMES)
        methods = {m['slot']: m for m in report['methods']}
        self.assertEqual(methods[10]['invkind'], 2)
        for slot, name, target in ((10, 'LCT', 'IDispatch'),
                                    (11, 'ReturnToNormalMode', 'SHORT'),
                                    (20, 'CancelSnapshot', 'LONG'),
                                    (26, 'SmartDetect', 'SHORT')):
            method = methods[slot]
            self.assertEqual(method['name']['text'], name)
            self.assertEqual(method['parameters'][0]['type']['target']['type'], target)
            self.assertEqual(method['return']['type'], 'HRESULT')
            self.assertEqual(method['native_vtable_entry']['address'],
                             method['native_address_from_prior_vtable_audit'])
        self.assertFalse(report['qualification']['ready_to_flash'])


if __name__ == '__main__':
    unittest.main()
