"""Audit the pinned DOC LCT COM declarations using static PE/MSFT metadata only.

No DLL loading, COM registration/activation, adapter API or target execution.
The small MSFT reader preserves unsupported type descriptors as unknowns; it
does not interpret coclass implementations or turn names into protocol claims.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import uuid


SOURCE_SHA256 = '023185650cddbd015a16eef4a8d58b2d6e173519ff07dc6434cb1552a55389c8'
TYPELIB_SHA256 = '58bce0ba1e2025500f39b43d525db25a54d573619f903b6d553668cb8af677db'
INTERFACE_GUID = '1830876c-83fc-4f80-8ce4-4d60499cd5b7'
NATIVE_GAPS = {10: '0x100121a6', 11: '0x1000f6bb',
               20: '0x10007046', 26: '0x1000ff6e'}
EXPECTED_NAMES = ('Connect', 'Disconnect', 'QueryLCTforStartupData', 'LCT',
                  'ReturnToNormalMode', 'ClearDiagnosticInformation', 'EngageGear',
                  'SolenoidTest', 'Reset', 'WriteCMCs', 'WriteIO', 'DataMap',
                  'SaveSnapshot', 'CancelSnapshot', 'StartPlayback', 'StopPlayback',
                  'TriggerState', 'TriggerState', 'TriggerAction', 'SmartDetect',
                  'ReadEngine', 'CurrentDeviceError', 'ClearFilters', 'SetFilters',
                  'CancelDeviceControl', 'GetWriteIOErrors', 'ReadTransHealthData',
                  'ResetErrorFrameCount')


class Reader:
    def __init__(self, data):
        self.data = bytes(data)

    def span(self, offset, size):
        if offset < 0 or size < 0 or offset > len(self.data) - size:
            raise ValueError('Metadata range outside input')
        return self.data[offset:offset+size]

    def u16(self, offset):
        return struct.unpack('<H', self.span(offset, 2))[0]

    def u32(self, offset):
        return struct.unpack('<I', self.span(offset, 4))[0]


def typelib_resources(data):
    """Resolve named TYPELIB leaves through a bounded PE resource tree."""
    r = Reader(data)
    if r.span(0, 2) != b'MZ':
        raise ValueError('Expected PE DOS signature')
    pe = r.u32(0x3c)
    if r.span(pe, 4) != b'PE\0\0':
        raise ValueError('Expected PE signature')
    sections, optsize = r.u16(pe+6), r.u16(pe+20)
    opt = pe+24
    r.span(opt, optsize)
    if r.u16(opt) != 0x10b or optsize < 120:
        raise ValueError('Only PE32 resource layout is supported')
    if r.u32(opt+92) < 3:
        raise ValueError('PE has no resource directory')
    header_size = r.u32(opt+60)
    ranges = []
    for i in range(sections):
        p = opt+optsize+i*40
        r.span(p, 40)
        ranges.append((r.u32(p+12), r.u32(p+16), r.u32(p+20)))

    def rva_to_file(rva, size):
        candidates = []
        if rva <= header_size and size <= header_size-rva:
            candidates.append(rva)
        for start, rawsize, rawoffset in ranges:
            if start <= rva and rva-start <= rawsize and size <= rawsize-(rva-start):
                candidates.append(rawoffset+rva-start)
        if len(candidates) != 1:
            raise ValueError('Unmapped or ambiguous file-backed resource RVA')
        r.span(candidates[0], size)
        return candidates[0]

    resource_rva, resource_size = r.u32(opt+112), r.u32(opt+116)
    root = rva_to_file(resource_rva, resource_size)
    tree = Reader(r.span(root, resource_size))
    visited, result, examined = set(), [], 0

    def walk(offset, path):
        nonlocal examined
        if offset in visited or len(path) > 2:
            raise ValueError('Cyclic, shared or too-deep resource directory')
        visited.add(offset)
        tree.span(offset, 16)
        count = tree.u16(offset+12)+tree.u16(offset+14)
        examined += count
        if examined > resource_size//8:
            raise ValueError('Resource entry count exceeds resource byte coverage')
        tree.span(offset+16, count*8)
        for i in range(count):
            p = offset+16+i*8
            ident, child = tree.u32(p), tree.u32(p+4)
            if ident & 0x80000000:
                q = ident & 0x7fffffff
                value = tree.span(q+2, tree.u16(q)*2).decode('utf-16le')
                key = {'kind': 'name', 'value': value}
            else:
                key = {'kind': 'id', 'value': ident}
            newpath = path+[key]
            if child & 0x80000000:
                walk(child & 0x7fffffff, newpath)
                continue
            if len(newpath) != 3:
                raise ValueError('Resource leaf is not type/name/language')
            tree.span(child, 16)
            payload_rva, size = tree.u32(child), tree.u32(child+4)
            fileoffset = rva_to_file(payload_rva, size)
            if newpath[0] == {'kind': 'name', 'value': 'TYPELIB'}:
                payload = r.span(fileoffset, size)
                result.append({'path': newpath, 'file_offset': fileoffset,
                               'bytes': size, 'sha256': hashlib.sha256(payload).hexdigest(),
                               'data_entry_file_offset': root+child, 'data': payload})

    walk(0, [])
    return result


def parse_msft(data, dll_file_offset=0):
    r = Reader(data)
    if r.span(0, 4) != b'MSFT' or r.u32(4) != 0x00010002:
        raise ValueError('Expected MSFT version 0x00010002 typelib')
    count = r.u32(32)
    if count > len(data)//100:
        raise ValueError('Impossible typeinfo count')
    # Optional help-DLL header field precedes the typeinfo offset array.
    if r.u32(20) & 0x100:
        raise ValueError('Help-DLL header variant is outside this reader scope')
    offsets = [r.u32(84+4*i) for i in range(count)]
    directory = 84+4*count
    segments = []
    for i in range(15):
        start, size = r.u32(directory+16*i), r.u32(directory+16*i+4)
        if start == 0xffffffff:
            if size:
                raise ValueError('Absent MSFT segment has nonzero size')
            segments.append((None, 0))
        else:
            r.span(start, size)
            segments.append((start, size))

    def seg(index, offset, size):
        start, length = segments[index]
        if start is None or offset > length or size > length-offset:
            raise ValueError('Metadata reference outside owning segment')
        return start+offset

    def location(offset):
        return {'typelib_offset': offset, 'dll_file_offset': dll_file_offset+offset}

    def name(offset):
        if offset == 0xffffffff:
            return None
        p = seg(7, offset, 12)
        n = r.u32(p+8) & 255
        seg(7, offset+12, n)
        raw = r.span(p+12, n)
        # MSFT names use the Windows code page, not UTF-8. Keep bytes for
        # arbitrary non-ASCII names rather than guessing the code page.
        return {'text': raw.decode('ascii') if raw.isascii() else None,
                'raw_hex': raw.hex(), 'name_segment_offset': offset,
                **location(p)}

    types = []
    for offset in offsets:
        p = seg(0, offset, 100)
        guid_offset = r.u32(p+44)
        guid = None if guid_offset == 0xffffffff else str(uuid.UUID(bytes_le=r.span(seg(5, guid_offset, 24), 16)))
        types.append({'name': name(r.u32(p+52)), 'kind': r.u32(p)&15,
                      'guid': guid, 'function_count': r.u32(p+24)&65535,
                      'variable_count': r.u32(p+24)>>16,
                      'member_data_offset': r.u32(p+4), **location(p)})
    selected = [t for t in types if t['name'] and t['name']['text'] == 'IEcuInterface']
    if len(selected) != 1:
        raise ValueError('Expected exactly one IEcuInterface declaration')
    interface = selected[0]
    if interface['guid'] != INTERFACE_GUID or interface['kind'] != 4:
        raise ValueError('IEcuInterface identity differs')
    if interface['variable_count']:
        raise ValueError('Variable-bearing interface is outside this reader scope')

    primitives = {0: 'EMPTY', 2: 'SHORT', 3: 'LONG', 8: 'BSTR',
                  9: 'IDispatch', 12: 'VARIANT', 25: 'HRESULT'}

    def typedesc(value):
        chain, seen = [], set()
        while True:
            if value & 0x80000000:
                vt = value & 65535
                row = {'raw': hex(value), 'vartype': vt, 'type': primitives.get(vt),
                       'unknown': vt not in primitives}
                break
            if value in seen:
                raise ValueError('Cyclic type descriptor')
            seen.add(value)
            p = seg(9, value, 8)
            vt = r.u16(p)
            row = {'raw': hex(value), 'vartype': vt, **location(p),
                   'descriptor_hex': r.span(p, 8).hex(), 'type': None, 'unknown': True}
            if vt == 26:  # VT_PTR; walk iteratively, preserve flat chain.
                row.update(type='PTR', unknown=False)
                chain.append(row)
                value = r.u32(p+4)
                continue
            if vt == 29:  # VT_USERDEFINED, href semantics not interpreted.
                row.update(type='USERDEFINED', href_raw=hex(r.u32(p+4)))
            break
        if not chain:
            return row
        result = {**chain[0], 'target': row, 'pointer_depth': len(chain)}
        if len(chain) > 1:
            result['pointer_chain'] = chain
        return result

    member = interface['member_data_offset']
    size = r.u32(member)
    start = member+4
    r.span(start, size)
    n = interface['function_count']
    if n > size//24:
        raise ValueError('Impossible function count')
    arrays = start+size
    r.span(arrays, 12*n)
    methods, cursor = [], start
    for i in range(n):
        relative = r.u32(arrays+8*n+4*i)
        if relative != cursor-start:
            raise ValueError('Function offset array differs from contiguous records')
        recsize = r.u16(cursor)
        if recsize < 24 or recsize % 4 or cursor+recsize > start+size:
            raise ValueError('Invalid function record size')
        nargs = r.u16(cursor+20)
        if nargs*12 > recsize-24:
            raise ValueError('Function parameters exceed record')
        params = []
        for j in range(nargs):
            p = cursor+recsize-nargs*12+j*12
            flags = r.u32(p+8)
            params.append({'type': typedesc(r.u32(p)), 'name': name(r.u32(p+4)),
                           'flags_raw': hex(flags), 'in': bool(flags&1),
                           'out': bool(flags&2), 'retval': bool(flags&8), **location(p)})
        vtable_offset = r.u16(cursor+12)
        if vtable_offset % 4:
            raise ValueError('Unaligned PE32 vtable offset')
        slot = vtable_offset//4
        methods.append({'slot': slot, 'vtable_byte_offset': vtable_offset,
                        'name': name(r.u32(arrays+4*n+4*i)), 'memid': r.u32(arrays+4*i),
                        'invkind': (r.u32(cursor+16)>>3)&15,
                        'return': typedesc(r.u32(cursor+4)), 'parameters': params,
                        'record_bytes': recsize, 'record_hex': r.span(cursor, recsize).hex(),
                        'native_address_from_prior_vtable_audit': NATIVE_GAPS.get(slot),
                        **location(cursor)})
        cursor += recsize
    if cursor != start+size:
        raise ValueError('Unexamined interface member bytes')
    return {'types': types, 'interface': interface, 'methods': methods,
            'limitations': ['Only IEcuInterface member records are decoded; other types are inventoried.',
                            'Unknown primitive, non-ASCII name and user-defined type interpretations retain source bytes.',
                            'Declared names/signatures do not establish controller protocol or execution behavior.']}


def audit(data):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('Pinned LctTransBusRules.dll hash differs; no audit')
    resources = typelib_resources(data)
    if len(resources) != 1 or resources[0]['sha256'] != TYPELIB_SHA256:
        raise ValueError('Pinned embedded typelib differs')
    resource = resources[0]
    parsed = parse_msft(resource['data'], resource['file_offset'])
    methods = parsed['methods']
    if tuple(m['slot'] for m in methods) != tuple(range(7, 35)):
        raise ValueError('Pinned IEcuInterface vtable alignment differs')
    if tuple(m['name']['text'] for m in methods) != EXPECTED_NAMES:
        raise ValueError('Pinned IEcuInterface names differ')
    # Source-bound alignment with the separately audited interface vtable:
    # VA 0x1005e99c, file offset 381340 in this exact pinned PE.
    for method in methods:
        slot = method['slot']
        if slot in NATIVE_GAPS:
            entry = 381340+slot*4
            raw = Reader(data).span(entry, 4)
            address = hex(struct.unpack('<I', raw)[0])
            if address != NATIVE_GAPS[slot]:
                raise ValueError('Pinned native vtable gap binding differs')
            method['native_vtable_entry'] = {'dll_file_offset': entry,
                                              'raw_hex': raw.hex(), 'address': address,
                                              'base_from_prior_audit_va': '0x1005e99c'}
    return {'schema': 'al5.lct-typelib-audit.v1', 'source_sha256': SOURCE_SHA256,
            'resource': {k: v for k, v in resource.items() if k != 'data'}, **parsed,
            'qualification': {'static_metadata_only': True, 'target_executed': False,
                              'adapter_opened': False, 'vehicle_transmissions_enabled': False,
                              'live_write_enabled': False, 'would_send': [],
                              'programming_proven': False, 'recovery_proven': False,
                              'ready_to_flash': False}}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('dll', type=Path)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args(argv)
    if args.output.exists():
        p.error('Output already exists; choose a new report path')
    report = audit(args.dll.read_bytes())
    report['source_path'] = str(args.dll.resolve())
    with args.output.open('x', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    print(json.dumps({'methods': len(report['methods']),
                      'gaps': {m['slot']: m['name']['text'] for m in report['methods']
                               if m['slot'] in NATIVE_GAPS}, 'ready_to_flash': False}))


if __name__ == '__main__':
    main()
