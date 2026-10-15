# Allison DOC LCT handler tracing

2026-10-15: offline static analysis and isolated initializer reconstruction only.
No installed DLL was loaded as host code, no COM object was activated and no
Windows/adapter API was executed from target code. Live AL5 writing is disabled.

## Exact inputs and managed-to-native bindings

Installed Allison DOC Service Tool inputs, preserved privately:

- Gen3Tcm.dll, assembly 21.5.0.0, SHA-256
  `1acc57865921028e7a5d40835bc107a7a3fe2bed5c28694f289950729ebcadee`.
- LctTransBusRules.dll, native x86 PE, SHA-256
  `023185650cddbd015a16eef4a8d58b2d6e173519ff07dc6434cb1552a55389c8`.

The prior REA managed-member representation limit remains in effect. Focused
dnfile 0.17.0/dncil 1.0.2 parsing retained 21 selected LCT/CMC/IO types, 196
methods and 219 raw referenced string spans. Invalid UTF-16 and obfuscated
control flow remain explicit; strings were not guessed from their display.

The ConnectionLCT3 constructor (MethodDef 0x06000152, RVA 0x92978) calls the
string decoder at 0x06000B86 with seed 7. Reproducing its byte operations derives
COM activation CLSID `58006349-07FE-48B3-B80A-552078679CCE`; this is not COM
activation. The interface IID is `1830876C-83FC-4F80-8CE4-4D60499CD5B7`.

The managed interface's slot order, including explicit gaps, aligns with the
native vtable candidate at 0x1005E99C. Known Connect and StartPlayback entries
provide alignment anchors. Derived bindings include:

- Slot 9, QueryLCTforStartupData: 0x1000E9EA.
- Slot 12, ClearDiagnosticInformation: 0x1000708C.
- Slot 15, Reset: 0x1000F504.
- Slot 16, WriteCMCs: 0x10011521.
- Slot 17, WriteIO: 0x100117ED.
- Slot 32, GetWriteIOErrors: 0x100093E9.

The three metadata gaps remain unknown methods. ReprogramECU methods on other
WTEC/CEC types are not LCT methods. This bounded selection is not a proof that
all programming functionality is absent from the application.

The unnamed native slot-11 body at 0x1000F6BB selects group 3 (`20`), then
conditionally group 5 (`2A 14 FE FD FC FB` / `2A 24 FA F9 F8 F7`). Those two
group-5 bodies match the echoed request portions of the demo's two `7F 2A`
messages. This ties them to a DOC diagnostic setup path; it does not establish
interrupted-programming errors. The wrapper's original method name and full
response semantics remain unresolved. Evidence:
`ev_dfb4cdaeb93f571f2617d917caa028e2006d609634e44791c71c4427515abe3e`.

## What the apparent write/reset paths actually establish

Managed Reset values 0..11 select adaptive/TPS resets, including garage shift
and individual shift adapts. Native Reset checks that range and selects rows
12..23 in the device-control table. It does not establish bootloader reset.
REA Evidence: `ev_42e76e789dc1b8156fc1fb45d777eeb4f46f31b7cbe8ce4aed46cdc29466f924`.

WriteCMCs calls individual configuration builders for PTO engine/output speeds,
torque converter engagement and range/preselect settings. A traced builder at
0x10010CBB initializes an internal `AE 02` buffer and encodes a value into it.
WriteIO constructs `AE 03`/`AE 04` buffers and tracks per-bit write errors.
GetWriteIOErrors returns three stored error bytes for CPID 3 or 4. No firmware
image, flash address or kernel-transfer argument is exposed by these traced
managed wrappers. Persistence behavior and controller qualification remain
unverified; these are not harmless commands approved for transmission.

Native WriteCMCs Evidence:
`ev_68753072689fd6b2d3ace41dc49cd1e93a8bcd5382dc06bf4685e091e3f880d6`.
Native WriteIO Evidence:
`ev_ab1da618a23e10a333f8dc16b5470b1ef6ea2a7a14ad8ff5d939ab77ebcb0d62`.
GetWriteIOErrors Evidence:
`ev_9eed56294caa2bb97f9b59beaea4bdbbc3fdcab6b39198b2c31937e34c1f7a50`.

## Reconstructing command tables without starting DOC

Raw file bytes contain partially initialized tables. Treating zero-filled slots
as absent commands would be incorrect. The new `audit_lct_command_tables.py`
runs four exact pinned initializer ranges in private Unicorn 2.1.4 memory:

- 0x10001064..0x10001813.
- 0x10001823..0x10002BC8.
- 0x10002BC9..0x10002CC2.
- 0x10002CC3..0x10004AC7.

These selected ranges contain constant/storage initialization; no calls or
conditional branches were found in their bounded linear instruction inventories.
Each emulated run must remain within its declared range, write only to the
declared private table region or synthetic stack, and return within 20,000
instruction observations. Source hash mismatch is rejected before emulation.
No entry point, import, callback, sender or COM method executes.

The selector catalog at native 0x10008EE6 identifies 13 groups / 135 descriptor
slots with 88-byte stride. After the selected initializers, 110 slots contain
nonempty request fields; 25 are initially empty. Later mutations are not modeled.
The first word is an event-handle slot, not a response-handler pointer. The
tool retains unused descriptor bytes without assigning unsupported semantics.
Catalog Evidence: `ev_b0d6bd3dbd939cf5edefc75994bf40dae2e33085f9a064b7f2b69ebf8e8a2fe6`.

Useful internal request anchors:

- Startup table row 14 contains `12 FF FF FF`; DOC also schedules this as a
  periodic diagnostic poll. A 0x12 byte alone must not establish flash erase.
- ClearDiagnosticInformation selects group 4, whose request field is `04`.
  The demo's one-byte `44` replies are consistent with that diagnostic service;
  they are not proof of flash finalization.
- Group 2 contains `10 10`; group 0 contains single-byte `31` and `37` requests.
  These are unresolved startup/session leads, not an established download path.
- Group 7 contains 25 `AE 01` device-control buffers; the public adaptive-reset
  choices select a bounded subset. Group 9 contains the `AE 02` configuration
  template, and group 8 contains `AE 03`/`AE 04` templates.
- Other reconstructed requests include `19`, `22`, `2A`, `2C` and `3C`. No
  security algorithm, firmware block transfer or post-erase recovery was derived.

These are internal host buffers, not qualified VPW/CAN frames. The helper prefix
templates are `00 EF 00 06 F9 03` for J1939 and `03 00 00 8C 18 F0` for the main
J1850 path. Helpers replace the J1850 length field. A request worker also uses
separate prefix storage and changes one J1939 address byte for certain selectors.
There is no universal transmit frame implied by this table audit.

Startup/polling Evidence:
`ev_9630fdbf8de467d8217ed2d22ef0159108662f19229772bd701e56fa7cd7a21b`.
ClearDiagnosticInformation Evidence:
`ev_fff204342382b0604888d92004969e4e6734d540859721fb7b8d8d87ed0793da`.

## Retry and response boundaries

The worker at 0x1001995A performs up to three send/wait attempts per descriptor.
The direct wait helper at 0x10008A0E similarly uses a caller-supplied attempt
bound. These retries wait for host events; they do not demonstrate recovery
from an erased or interrupted controller.

The undefined-by-Ghidra function candidate at 0x1000C427 has a bounded raw
disassembly that emits its DPID setup debug message and calls imported SetEvent.
It was not promoted to a provider-defined function or emulated as live behavior.

Worker Evidence: `ev_829fc857fd1842daf0a7a0cf96f8e2c7f938088a5bec5a6065df7aca62fd1135`.
Wait-helper Evidence: `ev_63083af5106feaedc94a4abc673ad40808751c2ccea3f7a12e0ae7bb39570d5e`.

## Reproduce and continue

From `Tools/AL5`, with optional Unicorn 2.1.4 available:

```powershell
python audit_lct_command_tables.py 'PATH\LctTransBusRules.dll' --output 'PATH\new-audit.json'
$env:AL5_LCT_DLL = 'PATH\LctTransBusRules.dll'
python -m unittest test_lct_command_tables test_allison_playback test_offline test_authorization
```

The real-input test is explicitly skipped when its local DLL or optional emulator
is unavailable. The current run included the pinned installed DLL. Private source
and reports are under `Tools/AL5/LocalOnly/AllisonPlayback_20261015/Handlers/`.
The current table report is `native-command-tables-final.json`; earlier
exploratory reports are superseded. In particular, a first-word event handle
must not be interpreted as a callback address.

Next: follow the group-0/group-2 response and state changes, finish callback
dispatch mapping, and compare demonstrated session behavior with the EFILive and
PCCS paths. Complete erase scope, loader/block transfer, verification and recovery
remain unproven. No adapter or vehicle test is authorized by this evidence.
