"""Offline AL5 alternate RPM selector: producers, transition descriptors, replay.

Original firmware files are read only. Emulation uses synthetic RAM and cannot
access vehicle hardware. This report keeps unresolved physical phase names open.
"""
import argparse
import collections
import hashlib
import json
import struct
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

LOW_SHA = 'cf5dd139e52ba5925fc95f166627a9a7abcac1374ded8cb738df8297b961a3f6'
HIGH_SHA = '492040d9460d53b77dda606b9a89f4254e0680f239093001663f6ed5cf51ba75'
XDF_SHA = '58d2ca843d5bc047ab5ca95911fa7dcd839b7c055e945a6f37fcd19237dfa9aa'
CONTEXT, STACK, RETURN = 0x200000, 0x218000, 0x300000


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def investigate(low, high, xdf_bytes):
    import capstone
    import unicorn
    from capstone import Cs, CS_ARCH_M68K, CS_MODE_BIG_ENDIAN, CS_MODE_M68K_020
    from unicorn import (Uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE,
                         UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_EXEC)
    from unicorn.m68k_const import (UC_CPU_M68K_M68020, UC_M68K_REG_SR,
        UC_M68K_REG_A5, UC_M68K_REG_A7, UC_M68K_REG_PC)
    if len(low) != 0x20000 or digest(low) != LOW_SHA:
        raise ValueError('low firmware identity mismatch')
    if len(high) != 0xE0000 or digest(high) != HIGH_SHA:
        raise ValueError('high firmware identity mismatch')
    if digest(xdf_bytes) != XDF_SHA:
        raise ValueError('named XDF identity mismatch')
    xdf = ET.fromstring(xdf_bytes)
    named_definitions = []
    for item in xdf:
        title = item.findtext('title', '')
        if title.startswith(('D5080 ', 'D5100 ')):
            embedded = item.find('EMBEDDEDDATA')
            if embedded is None:
                embedded = item.find("XDFAXIS[@id='z']/EMBEDDEDDATA")
            named_definitions.append({'title':title,
                'address':embedded.attrib['mmedaddress'],
                'description':item.findtext('description', '')})
    if [int(n['address'],0) for n in named_definitions] != [0xDC68,0xE24A]:
        raise ValueError('named shift-time anchors do not match the investigated XDF')
    data = low + high
    cs = Cs(CS_ARCH_M68K, CS_MODE_M68K_020 | CS_MODE_BIG_ENDIAN)

    def ins(i):
        return {'address': hex(i.address), 'bytes': bytes(i.bytes).hex(),
                'mnemonic': i.mnemonic, 'operands': i.op_str}

    refs = {}
    field = 0x2D1D
    for offset in range(0, len(data)-2, 2):
        if data[offset:offset+2] != field.to_bytes(2, 'big'):
            continue
        for start in range(max(0, offset-10), offset, 2):
            i = next(cs.disasm(data[start:offset+12], start, count=1), None)
            if i and i.address+len(i.bytes)>offset and f'${field:x}(a5)' in i.op_str:
                refs[i.address] = ins(i)
    direct_stores = [r for r in refs.values() if r['operands'].endswith('$2d1d(a5)')
                     and r['mnemonic'].startswith(('move', 'clr'))]

    windows = []
    for name, start, end in (
        ('state_machine', 0xB553C, 0xB56B0),
        ('startup_initializer_through_selector_store', 0x56068, 0x56478),
        ('transition_descriptor_prefix', 0x336C8, 0x33794),
        ('encoded_range_lookup', 0x339CC, 0x33A30),
        ('changed_request_flag', 0xBB274, 0xBB304),
        ('completion_signal_slice', 0xBCED8, 0xBCF3A),
        ('alternate_request_source', 0xA1D90, 0xA1E08),
        ('interlock_tail', 0x76110, 0x76172),
        ('alternate_rpm_pair_selector', 0xA3E3A, 0xA3E9C),
        ('state1_exclusive_shift_control_call', 0xBCE74, 0xBCED8),
        ('shift_control_bridge', 0xC2FF8, 0xC3066),
        ('shift_control_bridge_inner', 0xC58E4, 0xC58F8),
        ('shift_control_bridge_outer', 0xC58F8, 0xC5904),
        ('desired_shift_time_call', 0xC5674, 0xC567A),
        ('named_shift_time_parameter_loads', 0x52DCC, 0x52DF8),
        ('desired_shift_time_calculation_prefix', 0x83AF4, 0x83C9C),
    ):
        raw = data[start:end]
        decoded = list(cs.disasm(raw, start))
        if sum(len(i.bytes) for i in decoded) != len(raw):
            raise ValueError(f'incomplete decode: {name}')
        windows.append({'name': name, 'start': hex(start), 'end_exclusive': hex(end),
                        'sha256': digest(raw), 'instructions': [ins(i) for i in decoded]})

    codes = list(struct.unpack_from('>52H', data, 0x33A30))
    matrix = data[0x33AB0:0x34540]
    if len(matrix) != 52*52 or max(matrix) > 121:
        raise ValueError('unexpected transition descriptor matrix')
    descriptors = []
    for index in sorted(set(matrix)):
        address = 0x34540+index*16
        raw = data[address:address+16]
        descriptors.append({'index': index, 'address': hex(address), 'bytes': raw.hex(),
                            'requested_state_byte4': raw[4]})
    state_counts = collections.Counter(data[0x34540+index*16+4] for index in matrix)

    def replay(start, end, fields, allowed, expected_sp):
        uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
        uc.ctl_set_cpu_model(UC_CPU_M68K_M68020)
        uc.mem_map(0, 0x100000)
        uc.mem_write(0, data)
        uc.mem_protect(0, 0x100000, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_map(CONTEXT, 0x20000)
        uc.mem_map(RETURN, 0x1000)
        uc.reg_write(UC_M68K_REG_SR, 0x2700)
        uc.reg_write(UC_M68K_REG_A5, CONTEXT)
        uc.reg_write(UC_M68K_REG_A7, STACK)
        uc.mem_write(STACK, struct.pack('>I', RETURN))
        for offset, value in fields.items():
            uc.mem_write(CONTEXT+offset, value)
        count = [0]
        def guard(machine, address, size, _):
            if not any(lo <= address < hi for lo,hi in allowed):
                raise ValueError(f'execution escaped declared windows at {address:#x}')
            count[0] += 1
        def write_guard(machine, access, address, size, value, _):
            if not CONTEXT <= address or address+size > CONTEXT+0x20000:
                raise ValueError(f'write outside synthetic RAM: {address:#x}')
        uc.hook_add(UC_HOOK_CODE, guard)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_guard)
        uc.emu_start(start, end, timeout=1_000_000, count=10000)
        if uc.reg_read(UC_M68K_REG_PC) != end or uc.reg_read(UC_M68K_REG_A7) != expected_sp:
            raise ValueError('replay did not reach the exact stop with the expected stack')
        return uc, count[0]

    def state_case(name, inputs, expected_state, expected_detail):
        fields = {offset: bytes([value]) for offset,value in inputs.items()}
        fields[0x2D1C] = b'\xEE'
        fields[0x2D44] = b'\xCC'
        uc, steps = replay(0xB553C, RETURN, fields, [(0xB553C,0xB56B0)], STACK+4)
        state = uc.mem_read(CONTEXT+0x2D1D,1)[0]
        detail = uc.mem_read(CONTEXT+0x2D1C,1)[0]
        return {'name': name, 'inputs': {hex(k):v for k,v in inputs.items()},
                'observed_state': state, 'observed_detail': detail,
                'transition_event_2EC5': uc.mem_read(CONTEXT+0x2EC5,1)[0],
                'expected_state': expected_state, 'expected_detail': expected_detail,
                'instructions': steps, 'match': state==expected_state and detail==expected_detail}

    cases = []
    for requested in (0,1,2):
        cases.append(state_case(f'changed_request_{requested}',
            {0x2D1D:3,0x2F51:1,0x2D12:requested}, requested, (1,4,8)[requested]))
    for interlock in (0,1):
        cases.append(state_case(f'state0_interlock_{interlock}',
            {0x2D1D:0,0x2E16:interlock},0 if interlock else 1,2 if interlock else 4))
        cases.append(state_case(f'state2_interlock_{interlock}',
            {0x2D1D:2,0x2E16:interlock},2 if interlock else 3,9 if interlock else 10))
    for substate, detail in ((0,5),(4,7),(5,6)):
        cases.append(state_case(f'state1_no_completion_substate{substate}',
            {0x2D1D:1,0x1EC1:substate},1,detail))
    for completion in (1,2):
        for inhibit in (0,3):
            expected_state = 1 if inhibit==3 else 0 if completion==2 else 2
            expected_detail = 4 if inhibit==3 else 1 if completion==2 else 8
            cases.append(state_case(f'state1_completion{completion}_submode{inhibit}',
                {0x2D1D:1,0x2D95:completion,0x2D7A:inhibit},expected_state,expected_detail))
    cases.append(state_case('state3_stays_3_without_request',{0x2D1D:3},3,0))
    cases.append(state_case('unrecognized_state_is_preserved',{0x2D1D:4},4,0xEE))

    descriptor_cases = []
    for old,new in ((130,170),(170,130),(130,130),(175,205),(205,215),(215,225),(225,235),(255,255)):
        old_index,new_index = codes.index(old),codes.index(new)
        record_index = matrix[old_index*52+new_index]
        record_address = 0x34540+record_index*16
        expected = data[record_address+4]
        fields = {0x26BE: struct.pack('>H',old),0x26B4:struct.pack('>H',new)}
        uc,steps = replay(0x336C8,0x33794,fields,
            [(0x336C8,0x33794),(0x339CC,0x33A30)],STACK-48)
        actual = uc.mem_read(CONTEXT+0x2D12,1)[0]
        descriptor_cases.append({'prior_encoded_value':old,'new_encoded_value':new,
            'matrix_row':old_index,'matrix_column':new_index,'record_index':record_index,
            'record_address':hex(record_address),'record_bytes':data[record_address:record_address+16].hex(),
            'observed_requested_state':actual,'expected_requested_state':expected,
            'instructions':steps,'match':actual==expected})

    # Feed the actual descriptor output and each observed state into the next
    # state-machine replay. Other runtime inputs remain explicitly synthetic.
    sequence = []
    previous = 3
    for name, inputs, expected_state, expected_detail in (
        ('sequence_changed_request0', {0x2F51:1,0x2D12:descriptor_cases[0]['observed_requested_state']},0,1),
        ('sequence_wait_initial_interlock', {0x2E16:1},0,2),
        ('sequence_enter_alternate_rpm_state', {0x2E16:0},1,4),
        ('sequence_wait_completion', {0x2D95:0,0x1EC1:0},1,5),
        ('sequence_completion_transition', {0x2D95:1,0x2D7A:0},2,8),
        ('sequence_wait_final_interlock', {0x2E16:1},2,9),
        ('sequence_finish', {0x2E16:0},3,10),
    ):
        result = state_case(name,{0x2D1D:previous,**inputs},expected_state,expected_detail)
        sequence.append(result)
        previous = result['observed_state']
    return {
        'source_hashes': {'low':digest(low),'high':digest(high),'named_xdf':digest(xdf_bytes)},
        'versions': {'capstone':capstone.__version__,'unicorn':unicorn.__version__},
        'scope':'saved firmware static evidence and actual bounded code with synthetic RAM; no stubs or vehicle I/O',
        'direct_selector_references': list(refs.values()),
        'direct_selector_stores': direct_stores,
        'reference_coverage':'even-aligned displacement literal candidate scan, not exhaustive aliases/indirect accesses or a global CFG',
        'windows':windows,
        'transition_matrix': {'address':'0x33AB0','dimensions':[52,52],
            'sha256':digest(matrix),'row_column_code_table_address':'0x33A30',
            'row_column_codes':codes,'descriptor_base':'0x34540','descriptor_stride':16,
            'requested_state_offset':4,'requested_state_counts_over_matrix':dict(state_counts),
            'descriptors':descriptors},
        'named_shift_control_anchor': {
            'confidence':'derived static call/data chain plus established named-definition provenance; not vehicle execution',
            'definitions':named_definitions,
            'call_chain':['BCE90 -> C2FF8','C305E -> C58F8','C58F8 -> C58E4',
                          'C58F0 -> C5674','C5674 -> 83AF4'],
            'data_chain':'52DD2/52DD8 load the DC68 base family into 27FC; 52DE8/52DF0 select the E248 vector-header family into 257C. 83BBE passes 257C to signed interpolation, 83C68/83C70 add base 27FC, and 83C98 stores the combined desired shift time into 27DA.',
            'selector_relation':'Within BCE74..BCED8, only state 1 calls C2FF8. This supports active shift-control stage; exact fill/torque/inertia phase name remains unresolved.'},
        'derived_findings':[
            'Selector2D1D initializes to3: d5=3 at560BE and the uninterrupted initialization stream storesd5 at56474.',
            'The ordinary52x52 transition matrix requests only state0 or2; state1 is entered internally fromstate0 wheninterlock2E16 clears.',
            'State1 remains active until completion2D95 changes, subject to submode2D7A and detail-state1EC1; completion2 can return tostate0.',
            'State2 waits on2E16 then entersstate3; state3 remains until a newrequest or another producer changes it.',
            'Changed-request2F51 compares encoded word26B4 against2694 and also tracks control-triple changes.26B4/26BE select the transition descriptor.',
            'The state 1 RPM pair is tied to an active shift-control stage. Its exclusive call path consumes named desired shift-time parameters. An exact physical phase name such as fill, torque, or inertia remains unresolved.',
        ],
        'state_cases':cases,'descriptor_cases':descriptor_cases,'transition_sequence':sequence,
        'case_count':len(cases)+len(descriptor_cases)+len(sequence),
        'all_match':all(c['match'] for c in cases+descriptor_cases+sequence),
        'limitations':[
            'Synthetic contexts exercise extracted code; they do not establish scheduler ordering, realgear engagement, or physical shiftphase.',
            'A5+2E16 has multiple producers; bounded tail and completion-signal logic are retained but their full physicalinputs remain unresolved.',
            'Requeststate1 is possible through other sourcepaths; absence fromthis matrix does not prove global absence.',
            'No source BIN, XDF, calibration, adapter setting, or vehicle state is modified.',
        ],
    }


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('low','high','xdf','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--deps',type=Path)
    args=p.parse_args()
    if args.output.exists():
        raise ValueError('output exists; preserve prior evidence and sourcefiles')
    if args.deps:
        sys.path.insert(0,str(args.deps))
    report=investigate(args.low.read_bytes(),args.high.read_bytes(),args.xdf.read_bytes())
    report['inputs']={'low':str(args.low.resolve()),'high':str(args.high.resolve()),'xdf':str(args.xdf.resolve())}
    with args.output.open('x',encoding='utf-8',newline='\n') as out:
        out.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'cases':report['case_count'],'pass':report['all_match']}))
    raise SystemExit(0 if report['all_match'] else 1)
