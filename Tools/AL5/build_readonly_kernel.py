"""Build an offline-only AL5 runtime prototype with an existing WSL toolchain. No deployment."""
import argparse,hashlib,json,struct,subprocess
from pathlib import Path

def build(output,distro='Ubuntu'):
 output=output.resolve();output.mkdir(parents=True,exist_ok=False);root=Path(__file__).resolve().parents[2];src=root/'Kernels/AL5-ReadOnly'
 def wsl(*args):return subprocess.check_output(['wsl.exe','-d',distro,'--',*args],text=True,timeout=60).strip()
 def linux(p):return wsl('/usr/bin/wslpath','-u',str(p))
 gcc='/usr/bin/m68k-linux-gnu-gcc';elf=output/'readonly_kernel.offline.elf';binary=output/'readonly_kernel.offline.bin'
 flags=['-m68020','-Os','-std=c99','-ffreestanding','-fno-builtin','-fno-pic','-fno-pie','-fno-stack-protector','-fomit-frame-pointer','-nostdlib','-static','-Wl,--build-id=none','-Wl,-T,'+linux(src/'offline.ld')]
 names=['entry.S','read_core.c','runtime.c'];version=wsl(gcc,'--version')
 wsl(gcc,*flags,*[linux(src/n) for n in names],'-o',linux(elf))
 raw=elf.read_bytes()
 if raw[:6]!=b'\x7fELF\x01\x02':raise ValueError('Expected M68K big-endian ELF32')
 f=struct.unpack_from('>HHIIIIIHHHHHH',raw,16)
 if f[1]!=4 or f[10]!=40 or f[11]>64:raise ValueError('Unsupported ELF layout')
 sections=[struct.unpack_from('>IIIIIIIIII',raw,f[5]+i*40) for i in range(f[11])];st=sections[f[12]];strings=raw[st[4]:st[4]+st[5]];text=None
 for s in sections:
  name=strings[s[0]:].split(b'\0',1)[0].decode('ascii')
  if s[2]&2 and s[5] and name!='.text':raise ValueError('Unexpected allocated section '+name)
  if name=='.text':text=s
 if text is None or text[3]!=0xFF9006 or text[3]+text[5]>0xFFA000 or not text[3]<=f[3]<text[3]+text[5]:raise ValueError('Unqualified text placement')
 wsl('/usr/bin/m68k-linux-gnu-objcopy','-O','binary','--only-section=.text',linux(elf),linux(binary))
 code=binary.read_bytes()
 if code!=raw[text[4]:text[4]+text[5]]:raise ValueError('ELF/code mismatch')
 nm=wsl('/usr/bin/m68k-linux-gnu-nm','-n',linux(elf));symbols={}
 for line in nm.splitlines():
  parts=line.split()
  if len(parts)==3 and parts[1] in ('T','t'):symbols[parts[2]]=int(parts[0],16)
 r=dict(schema='al5-offline-runtime-build-v1',core_bytes=len(code),text_base=text[3],entry=f[3],symbols=symbols,code_sha256=hashlib.sha256(code).hexdigest(),
  sources={n:hashlib.sha256((src/n).read_bytes()).hexdigest() for n in names+['read_core.h','runtime.h','offline.ld']},compiler=version,compiler_flags=flags,
  live_upload_enabled=False,live_execution_enabled=False,live_write_enabled=False,hardware_qualified=False,physical_ram_ownership_proven=False)
 (output/'build_receipt.json').write_text(json.dumps(r,indent=2));return r
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output-dir',type=Path,required=True);p.add_argument('--distro',default='Ubuntu');a=p.parse_args();print(json.dumps(build(a.output_dir,a.distro)))
