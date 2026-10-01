"""Metadata-only inspection of local EFILive trace containers; never sends packets."""
import argparse
from collections import Counter
import json
import math
from pathlib import Path
import re
import zlib
from al5_segment import sha256

MAX_INPUT=16*1024*1024
MAX_OUTPUT=1024*1024
HEADER_WINDOW=256
NAME=re.compile(r'^(\d{8})_(\d{6})_(?:(AL5)_([RWF])|([RWF])_(AL5))\.htx$',re.I)


def probe_zlib(data, *, output_limit=MAX_OUTPUT):
    """Test bounded headers after byte rotation/XOR; report hashes, never payloads.

    This is a narrow format probe, not a decryptor or a packet decoder. Complete
    streams must be nonempty, fit the bound and consume the entire remaining
    input. Other encodings, stream offsets and compression formats remain open.
    """
    candidates=0
    matches=[]
    for rotation in range(8):
        rotated=bytes(((b>>rotation)|(b<<(8-rotation)))&255 for b in data) if rotation else data
        for key in range(256):
            transformed=rotated.translate(bytes(b^key for b in range(256)))
            for offset in range(min(HEADER_WINDOW,len(data)-1)):
                a,b=transformed[offset:offset+2]
                if a&15!=8 or a>>4>7 or (256*a+b)%31 or b&32:continue
                candidates+=1
                try:
                    decoder=zlib.decompressobj()
                    output=decoder.decompress(transformed[offset:],output_limit+1)
                    if output and len(output)<=output_limit and decoder.eof and not decoder.unused_data:
                        matches.append({'rotation_right_bits':rotation,'xor_byte':key,
                                        'offset':offset,'decoded_bytes':len(output),
                                        'decoded_sha256':sha256(output)})
                except zlib.error:pass
    return {'header_window_bytes':HEADER_WINDOW,'output_limit_bytes':output_limit,
            'candidate_headers_tested':candidates,'complete_streams':matches,
            'scope':'Zlib only, offsets 0..255, fixed byte rotation and XOR; no packet interpretation.'}


def inspect(path, *, probe=False):
    path=Path(path)
    match=NAME.fullmatch(path.name)
    if not match:raise ValueError('explicit AL5 R/W/F .htx filename required')
    if not 0<path.stat().st_size<=MAX_INPUT:raise ValueError('trace size outside bounded input policy')
    data=path.read_bytes()
    if not 0<len(data)<=MAX_INPUT:raise ValueError('trace changed beyond input policy during read')
    counts=Counter(data)
    mode=match[4] or match[5]
    return {'source_name':path.name,'source_sha256':sha256(data),'bytes':len(data),
            'filename_context':{'date':match[1],'time':match[2],'controller':'AL5',
                                'mode':mode.upper(),'provenance':'Filename only, not decoded content.'},
            'entropy_bits_per_byte':round(-sum(n/len(data)*math.log2(n/len(data)) for n in counts.values()),6),
            'ascii_text_fraction':round(sum(b in (9,10,13) or 32<=b<=126 for b in data)/len(data),6),
            'prefix_4_sha256':sha256(data[:4]),
            'literal_known_read_request_header_hits':data.count(bytes.fromhex('6d18f023')),
            'literal_known_read_response_header_hits':data.count(bytes.fromhex('6cf01863')),
            'bounded_zlib_probe':probe_zlib(data) if probe else None,
            'container_decoded':False,'packet_sequence_verified':False,
            'operation_outcome':None,'programming_payload_verified':False}


def inventory(paths, *, probe=False):
    records=[inspect(p,probe=probe) for p in paths]
    if not records:raise ValueError('at least one explicit trace path required')
    return {'schema_version':1,'scope':'Saved-file metadata and narrow compression probes only; no device or EFILive executable used.',
            'limits':'High entropy does not prove encryption. No decoded packet records, timing, erase/program acknowledgments or completion evidence. Filename W does not prove a successful write.',
            'traces':records,'trace_count':len(records),
            'same_first_four_bytes_by_hash':len({r['prefix_4_sha256'] for r in records})==1,
            'format_decoding_verified':False,'programming_transport_verified':False,
            'ready_to_flash':False,'live_write_enabled':False,'would_send':[]}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--trace',type=Path,action='append',required=True)
    p.add_argument('--probe-zlib',action='store_true')
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    result=inventory(args.trace,probe=args.probe_zlib)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'trace_count':result['trace_count'],'format_decoding_verified':False,'would_send':[]}))
