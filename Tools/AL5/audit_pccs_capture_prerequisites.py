"""Read-only installed-file audit; never loads PCCS, drivers, or utility code."""
import argparse
import configparser
import hashlib
import json
from pathlib import Path, PureWindowsPath

PIN='13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d'


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def audit(root):
    root=Path(root)
    exe=root/'Winrw32.exe'
    executable_hash=digest(exe)
    files=sorted(p for p in root.rglob('*') if p.is_file())
    utilities=[p for p in files if p.suffix.lower()=='.fil']
    ini=root/'Controller.ini'
    parser=configparser.ConfigParser(interpolation=None,strict=True)
    parser.read_string(ini.read_text(encoding='cp1252'))
    refs=[]
    other_settings=[]
    for section in parser.sections():
        if not section.lower().startswith('utility file') or not parser.has_option(section,'Transmission'):
            continue
        source=parser.get(section,'Transmission',raw=True)
        if PureWindowsPath(source).suffix.lower()!='.fil':
            other_settings.append(dict(section=section,value=source,interpretation='not classified as a FIL path'))
            continue
        basename=PureWindowsPath(source).name.lower()
        matches=[p for p in utilities if p.name.lower()==basename]
        refs.append(dict(section=section,configured_path=source,configured_path_exists=Path(source).is_file(),
                         same_basename_candidates=[dict(path=str(p.relative_to(root)),sha256=digest(p)) for p in matches],
                         compatibility_proven=False))
    return dict(executable_sha256=executable_hash,known_analysis_build=executable_hash==PIN,
                controller_ini_sha256=digest(ini),fil_count=len(utilities),transmission_utility_references=refs,
                other_utility_settings=other_settings,
                spx1850_candidates=[str(p.relative_to(root)) for p in files if p.name.lower()=='spx1850.dll'],
                generic_appandcal_present=any(p.name.lower()=='appandcal_utility.fil' for p in utilities),
                erase_app_present=any(p.name.lower()=='erase_app_utility.fil' for p in utilities),
                qualified_al5_programming_route=False,live_write_enabled=False,
                limits=['Installed PCCS tree only; no registry, system-wide driver or installer payload search.',
                        'File presence and same-basename candidates do not establish compatibility or active selection.',
                        'No configuration changes, DLL loads, application launch or hardware access.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('root',type=Path)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    result=audit(args.root)
    args.output.write_bytes((json.dumps(result,indent=2)+'\n').encode())
    print(json.dumps(result,indent=2))
