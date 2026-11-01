"""Build only the callable AL5 reader core using an existing WSL toolchain. Never uploads/executes it."""
import argparse,hashlib,json,struct,subprocess
from pathlib import Path

def build(output,distro='Ubuntu'):
    output=output.resolve();output.mkdir(parents=True,exist_ok=False)
    root=Path(__file__).resolve().parents[2];source=root/'Kernels/AL5-ReadOnly/read_core.c';header=source.with_suffix('.h')
    def wsl(*args):return subprocess.check_output(['wsl.exe','-d',distro,'--',*args],text=True,timeout=60).strip()
    def linux(p):return wsl('/usr/bin/wslpath','-u',str(p))
    gcc='/usr/bin/m68k-linux-gnu-gcc';objcopy='/usr/bin/m68k-linux-gnu-objcopy'
    version=wsl(gcc,'--version');elf=output/'read_core.elf';binary=output/'read_core.text-only.bin'
    flags=['-m68020','-Os','-std=c99','-ffreestanding','-fno-builtin','-fno-pic','-fno-pie','-fno-stack-protector','-fomit-frame-pointer','-nostdlib','-static',
           '-Wl,--build-id=none','-Wl,-Ttext=0xFF9006','-Wl,-e,al5_ro_read']
    wsl(gcc,*flags,linux(source),'-o',linux(elf))
    raw=elf.read_bytes()
    if raw[:6]!=b'\x7fELF\x01\x02':raise ValueError('Expected 32-bit big-endian ELF')
    fields=struct.unpack_from('>HHIIIIIHHHHHH',raw,16)
    if fields[1]!=4:raise ValueError('Expected ELF M68K machine')
    entry=fields[3];offset=fields[5];width=fields[10];count=fields[11];names_index=fields[12]
    if width!=40 or count>64:raise ValueError('Unsupported section layout')
    sections=[struct.unpack_from('>IIIIIIIIII',raw,offset+i*width) for i in range(count)]
    names=sections[names_index];strings=raw[names[4]:names[4]+names[5]];text=None
    for s in sections:
        name=strings[s[0]:].split(b'\0',1)[0].decode('ascii')
        if s[2]&2 and s[5] and name!='.text':raise ValueError('Unexpected allocated section '+name)
        if name=='.text':text=s
    if text is None or text[3]!=0xFF9006 or text[5]>4096 or not text[3]<=entry<text[3]+text[5]:raise ValueError('Unexpected core layout')
    wsl(objcopy,'-O','binary','--only-section=.text',linux(elf),linux(binary))
    code=binary.read_bytes()
    if code!=raw[text[4]:text[4]+text[5]]:raise ValueError('Extracted text differs')
    r=dict(schema='al5-readonly-callable-core-v1',source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),header_sha256=hashlib.sha256(header.read_bytes()).hexdigest(),
        compiler=version,compiler_flags=flags,elf_sha256=hashlib.sha256(raw).hexdigest(),core_sha256=hashlib.sha256(code).hexdigest(),core_bytes=len(code),
        text_base=hex(text[3]),entry=hex(entry),distro=distro,live_upload_enabled=False,autonomous_kernel=False,hardware_qualified=False)
    (output/'build_receipt.json').write_text(json.dumps(r,indent=2));return r
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output-dir',type=Path,required=True);p.add_argument('--distro',default='Ubuntu');a=p.parse_args()
    print(json.dumps(build(a.output_dir,a.distro)))
