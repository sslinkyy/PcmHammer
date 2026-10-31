"""Offline SPS2/GT evidence importer. No adapter, send plan, or write authority."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import struct
import compare_usb_serial_capture as usb

LIMIT = 128 * 1024 * 1024

def sha(data):
    return hashlib.sha256(data).hexdigest()

class Frames:
    """Both GT directions; extended TX 0x11 and RX 0x09 use uint16 lengths."""
    def __init__(self):
        self.buffer = bytearray()
        self.offset = 0
    def feed(self, data):
        self.buffer.extend(data)
        rows = []
        while self.buffer:
            width = 2 if self.buffer[0] in (9, 17) else 1
            header = 1 + width
            if len(self.buffer) < header:
                break
            count = int.from_bytes(self.buffer[1:header], 'big')
            total = header + count + 1
            if len(self.buffer) < total:
                break
            raw = bytes(self.buffer[:total])
            if sum(raw) % 256 != 255:
                raise ValueError('DVI checksum failure at stream offset ' + str(self.offset))
            rows.append((self.offset, raw[0], raw[header:-1]))
            self.offset += total
            del self.buffer[:total]
        return rows
    def finish(self):
        if self.buffer:
            raise ValueError('Truncated DVI stream')

def summarize(rows, utility):
    blocks = []; replies = Counter(); negative = []; commands = Counter()
    for row in rows:
        m = bytes.fromhex(row['hex'])
        if row['direction'] == 'T' and len(m) >= 4 and m[1:3] == b'\x18\xf0':
            commands[m[:1].hex() + ':' + m[3:4].hex()] += 1
            if m[3] == 0x36:
                if len(m) < 12:
                    raise ValueError('Short AL5 block')
                size = int.from_bytes(m[5:7], 'big')
                if size + 12 != len(m):
                    raise ValueError('AL5 block length mismatch')
                code = m[10:-2]
                # Literal containment is evidence; never infer an executable offset from a filename.
                offset = utility.find(code) if m[4] == 0x80 else -1
                blocks.append(dict(record=row['record'], submode=m[4], address=int.from_bytes(m[7:10], 'big'),
                    data_bytes=size, data_sha256=sha(code), utility_offset=offset if offset >= 0 else None,
                    trailer_hex=m[-2:].hex()))
        if row['direction'] == 'R' and m[:3] == bytes.fromhex('6cf018'):
            replies[m[3:].hex()] += 1
            if m[3:4] == b'\x7f':
                negative.append(row)
    keys = [(b['submode'], b['address'], b['data_bytes'], b['data_sha256']) for b in blocks]
    duplicates = sum(n - 1 for n in Counter(keys).values())
    return dict(blocks=blocks, literal_duplicate_block_transmissions=duplicates,
        duplicate_limit='Literal repeats only; not proof of retry cause or erase semantics',
        al5_command_counts=dict(commands), al5_reply_counts=dict(replies), negative_replies=negative,
        live_write_enabled=False, ready_to_flash=False, recovery_verified=False,
        physical_readback_verified=False, physical_vpw_losslessness_proven=False)

def verify_modules(rows, modules):
    """Compare ordered saved module bytes and padding to observed staged data."""
    payload = b''.join(bytes.fromhex(r['hex'])[10:-2] for r in rows
                      if r['direction']=='T' and r['hex'].startswith('6d18f03600'))
    offset=0; results=[]
    for module in modules:
        if module.stat().st_size > 2 * 1024 * 1024:
            raise ValueError('Module exceeds memory budget')
        data=module.read_bytes(); padded=(len(data)+4095)//4096*4096
        observed=payload[offset:offset+len(data)]; padding=payload[offset+len(data):offset+padded]
        results.append(dict(module_sha256=sha(data), data_bytes=len(data), stream_offset=offset,
            literal_match=observed==data, padding_bytes=len(padding),
            zero_padding_matches=len(padding)==padded-len(data) and not any(padding)))
        offset+=padded
    return dict(modules=results, staged_stream_bytes=len(payload), examined_bytes=offset,
                exact_stream_coverage=offset==len(payload))

def analyze(pcap, utility, *, bus, device, tx_endpoint, rx_endpoint):
    if tx_endpoint & 128 or not rx_endpoint & 128 or tx_endpoint == rx_endpoint:
        raise ValueError('Explicit OUT and IN endpoints required')
    for p in (pcap, utility):
        if p.stat().st_size > LIMIT:
            raise ValueError('Input exceeds memory budget')
    raw = pcap.read_bytes(); packed = utility.read_bytes()
    with gzip.GzipFile(fileobj=__import__('io').BytesIO(packed)) as f:
        code = f.read(2 * 1024 * 1024 + 1)
    if len(code) > 2 * 1024 * 1024:
        raise ValueError('Utility expansion exceeds budget')
    inventory, _, _ = usb.parse_pcap(raw)
    if not inventory['source_fully_read'] or inventory['issues']['count']:
        raise ValueError('PCAP structure incomplete or unsupported')
    endian, units = usb.PCAP_MAGICS[raw[:4]]
    dec = {'T': Frames(), 'R': Frames()}; rows=[]; failures=[]; pos=24; ordinal=0
    while pos < len(raw):
        sec, frac, count, original = struct.unpack_from(endian+'IIII', raw, pos)
        pos += 16; r=raw[pos:pos+count]; pos+=count; ordinal+=1
        if len(r) < 27:
            continue
        h, irp, status, fn, info, b, d, ep, transfer, length = struct.unpack_from('<HQIHBHHBBI', r)
        direction = 'T' if ep == tx_endpoint and info == 0 else 'R' if ep == rx_endpoint and info == 1 else None
        if (b,d)!=(bus,device) or transfer != 3 or direction is None:
            continue
        if status:
            failures.append(dict(record=ordinal, status=status, payload_hex=r[h:].hex(), direction=direction))
            continue
        if h < 27 or h > len(r) or len(r)-h != length:
            raise ValueError('Selected USB payload length mismatch')
        if len(rows) >= 100000:
            raise ValueError('Network frame expansion limit reached')
        for offset, command, payload in dec[direction].feed(r[h:]):
            if command in ((16,17) if direction=='T' else (8,9)):
                rows.append(dict(record=ordinal, time=sec+frac/units, direction=direction,
                                 stream_offset=offset, dvi_command=command, hex=payload.hex()))
    for decoder in dec.values():
        decoder.finish()
    result = summarize(rows, code)
    result.update(schema='sps-al5-offline-observations-v1', frames=rows,
        inputs=dict(pcap_sha256=sha(raw), utility_gzip_sha256=sha(packed), utility_expanded_sha256=sha(code)),
        selection=dict(bus=bus, device=device, tx_endpoint=tx_endpoint, rx_endpoint=rx_endpoint),
        pcap_inventory=inventory, failed_selected_transfers=failures,
        selected_usb_transfers_all_successful=not failures, hardware_access_performed=False,
        limitations=['DVI timestamps are assumed disabled; mismatched framing fails closed.',
            'Record is the USB transfer completing each DVI frame; cross-direction wire timing remains unknown.',
            'PCAP structure and DVI checksums do not establish lossless physical VPW capture.',
            'SPS result, checksum verification and physical recovery require separate evidence.'])
    return result

if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ('pcap','utility','output','corpus'):
        p.add_argument('--'+arg,type=Path,required=True)
    for arg in ('bus','device','tx-endpoint','rx-endpoint'):
        p.add_argument('--'+arg,type=lambda x:int(x,0),required=True)
    p.add_argument('--module',type=Path,action='append',default=[],help='Ordered expanded SPS modules; observations only')
    a=p.parse_args()
    if a.output.exists() or a.corpus.exists():
        p.error('Outputs must be new paths')
    r=analyze(a.pcap,a.utility,bus=a.bus,device=a.device,tx_endpoint=a.tx_endpoint,rx_endpoint=a.rx_endpoint)
    if a.module:
        r['module_comparison']=verify_modules(r['frames'],a.module)
    with a.output.open('x',encoding='utf8') as f:
        json.dump(r,f,indent=2)
    with a.corpus.open('x',encoding='ascii') as f:
        f.write(''.join(x['direction']+' '+x['hex']+'\n' for x in r['frames']))
    print(json.dumps({k:r[k] for k in ('inputs','al5_command_counts','al5_reply_counts','literal_duplicate_block_transmissions','live_write_enabled')}))
