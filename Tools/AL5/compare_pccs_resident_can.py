"""Compare native PCCS payloads with saved AL5 resident handling; flash calls trapped."""
import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from emulate_pccs_native_write import run
from emulate_resident_dispatch import emulate, ENTRY, END

LOW_HASH='cf5dd139e52ba5925fc95f166627a9a7abcac1374ded8cb738df8297b961a3f6'


def compare(exe,low,xml):
    if hashlib.sha256(low).hexdigest()!=LOW_HASH:
        raise ValueError('Saved AL5 LOW identity changed')
    catalog=ET.fromstring(xml)
    interfaces=[dict(e.attrib) for e in catalog.iter('Connection') if e.get('TCM')=='TCM_1K2K3rd']
    cases=[]
    for address in (0x8000,0x20000,0x1fffc):
        payload=bytes.fromhex('1122334455667788') if address!=0x1fffc else bytes.fromhex('11223344')
        host=run(exe,address=address,payload=payload,ccp=False,quick=False)
        for ordinal,dispatch in enumerate(host['dispatches']):
            request=bytes.fromhex(dispatch['internal_buffer_hex'])
            for identifier in (0x3f8,0x3f9,0x2f8):
                controller=emulate(low[ENTRY:END],request,len(request),identifier=identifier)
                expected_address=address+ordinal*4
                if identifier==0x2f8:
                    assert controller['flash_calls']==[] and controller['responses']==[]
                else:
                    assert len(controller['flash_calls'])==1
                    call=controller['flash_calls'][0]
                    assert call['operation']==1 and call['count']==4
                    assert int(call['destination'],16)==expected_address
                    assert call['data_hex']==payload[ordinal*4:ordinal*4+4].hex()
                    assert not call['primitive_executed']
                    assert controller['responses'][0]['data_hex']==request[:4].hex()+'00'
                cases.append(dict(address=expected_address,internal_identifier=hex(identifier),
                                  host_internal_payload=request.hex(),controller=controller))
    return dict(pccs_sha256=hashlib.sha256(exe).hexdigest(),low_sha256=LOW_HASH,
                resident_code_sha256=hashlib.sha256(low[ENTRY:END]).hexdigest(),
                devices_xml_sha256=hashlib.sha256(xml).hexdigest(),interfaces=interfaces,cases=cases,
                command_payload_compatibility_observed=True,physical_can_support_proven=False,
                live_write_enabled=False,ready_to_flash=False,
                limits=['PCCS target index/family and success replies are synthetic; boot entry not executed.',
                        'Payload handoff bypasses CAN envelope, peripheral reception, driver and host response parser.',
                        'Resident internal identifier is injected, not a verified wire-ID decoder.',
                        'All flash primitives and send helpers trapped. No erase, program or recovery executed.',
                        'Saved editor LOW image is not a current physical boot-region backup.',
                        'Catalog family membership does not establish exact AL5 hardware or harness compatibility.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('exe','low','xml','output'):p.add_argument('--'+name,type=Path,required=True)
    args=p.parse_args()
    report=compare(args.exe.read_bytes(),args.low.read_bytes(),args.xml.read_bytes())
    args.output.write_bytes((json.dumps(report,indent=2)+'\n').encode())
    print('PASS',len(report['cases']),'native payload/dispatcher cases;',len(report['interfaces']),'catalog entries; no physical qualification')
