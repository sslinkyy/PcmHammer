# LCT startup/session tracing — offline, 2026-10-15

The traced `31`, `37`, `35` sequence belongs to a J1939 startup branch.
The separate `10 10` request has a `50 10` acknowledgement callback, but no
direct activation was identified in the bounded caller audit. Neither path
establishes AL5 programming, erase, firmware transfer, or interrupted-flash
recovery. Live writes remain disabled.

Latest follow-up: [native COM gap tracing](LCT_TYPELIB_TRACING.md) identifies
all four previously unnamed slots from the embedded type library. None of
their traced native bodies activates group 2. Historical unknown-slot limits
below describe the earlier audit; computed/external activation remains open.

## Source and scope

Installed `LctTransBusRules.dll`, SHA-256
`023185650cddbd015a16eef4a8d58b2d6e173519ff07dc6434cb1552a55389c8`.
REA/Ghidra analysis is read-only. Source-pinned Unicorn 2.1.4 runs execute only
selected initializer or callback instructions in private memory; imported
SetEvent is replaced with a synthetic return stub. DOC, COM, transport, adapters
and controllers do not execute. Internal buffers are not qualified wire frames.

Private evidence is retained in
`Tools/AL5/LocalOnly/AllisonPlayback_20261015/SessionTrace/`, including
`complete-tables.json`, `native-callback-emulation.json`,
`selector-call-audit.json` and `lct-session-trace-20261015.snapshot.json`.
The snapshot retains 68 Evidence records and 27 primitive query bindings.

## Complete initialization and response ownership

`audit_lct_command_tables.py` now executes 15 bounded initializers instead of
four. All 135 request slots across 13 groups have initialized request fields.
This supersedes the earlier 110 populated / 25 empty partial reconstruction;
later host mutations are still unmodeled. Group 0 requests, in order, are
`31`, `37`, `35`. Group 2 contains `10 10`.

The receive dispatcher at `0x100096F9` selects registered response tables:

- J1939 startup: base `0x10073E80`, five descriptors.
- Normal receive: base `0x10074038`, 122 descriptors.

Both use 88-byte records: match length at +41, prefix at +42, callback at +80.
These differ from request descriptors. The final four bytes remain opaque.
An earlier private `callback-table-candidates.json` scan used a misaligned
base and is superseded by these registered arrays and matcher offsets.

## Startup branch

QueryStartup at `0x1000E9EA` activates group 0 only when its protocol field is
1 (J1939). The receive dispatcher routes source `03`, destination `F8` replies
to the five-entry startup table. The J1850 branch uses the normal table.
The request worker also selects the alternate J1939 source for this group.

Startup prefixes `00`, `31`, `35`, `37` bind to `0x1000D029`; `20` binds to
`0x1000C451`. The first callback reads the second payload byte and writes
host status at `this+0xB4`: `00` or `37` gives 0, `31` gives 1, `35` gives 2,
and other values give 4. It then signals the selected group-0 host event.
The numerical status meanings beyond this classification are unknown.
QueryStartup exits on nonzero status and otherwise proceeds to identification
and diagnostic groups. No memory-transfer or erase operation occurs in this
callback. Literal startup bytes must not be assigned UDS meanings by analogy.

## The `10 10` lead

The normal table binds `50 10` to `0x1000A783`. Its bounded raw instructions
signal the group-2 event only when `this+0x1AE` is zero, then return zero.
They do not change the startup status or initiate transfer. Ghidra leaves this
address undefined; the analysis and emulator do not promote it to a
provider-defined function.

The source-bound executable call audit found 14 direct calls to waiting
selector helper `0x10009944`, and four to nonwaiting helper `0x1000992D`.
None selects group 2. Absolute group-2 table references cover initialization,
event creation/cleanup, catalog lookup and acknowledgement. No fixed group-2
activation through imported SetEvent was found in that scan. Computed callers,
external modules and other activation mechanisms remain unresolved. This is
not proof that the command is unreachable or that DOC lacks programming code.

## Validation and continuation

`emulate_lct_session_callbacks.py` exercises 33 synthetic native callback cases:
30 group-0 combinations and three group-2 indices. Exact input hashes,
instruction boundaries, write boundaries, instruction budgets and RET-8 stack
behavior are guarded. Source mismatch fails before reconstruction; existing
report paths are refused. Synthetic event results establish host callback
behavior only, not actual controller responses or programming readiness.

From `Tools/AL5`, with optional Unicorn 2.1.4:

```powershell
$env:AL5_LCT_DLL = 'PATH\LctTransBusRules.dll'
python audit_lct_command_tables.py $env:AL5_LCT_DLL --output 'PATH\new-tables.json'
python emulate_lct_session_callbacks.py $env:AL5_LCT_DLL --output 'PATH\new-callbacks.json'
python -m unittest test_lct_command_tables test_lct_session_callbacks test_allison_playback test_offline test_authorization test_pccs_methods -q
```

Current validation: 48 tests passed, including pinned real-DLL initializer and
callback emulation. Real-input tests skip explicitly when their dependencies
are absent. No hardware behavior is qualified. Next useful work is to identify
a computed/external group-2 activator and compare the startup branch against
the actual PCCS loader selection and transfer path. Erase coverage, loader
transfer, final verification and recovery remain unproven.

## REA Evidence anchors

- Receive routing: `ev_313c68d82a03e018dc106c76ad3f020a5a22835bc8d37092f68fa7003644400b`.
- J1939 matcher: `ev_e11afe870c43fafe6c58854327bc54ff5216195331175d0a7f453a19631bd899`.
- J1850 matcher: `ev_292f7779c005b03dc19bfbee0f4f866301945f0726df1fbc07a6404797cd3ecc`.
- Startup callback: `ev_d7b4eabda4405da66f3ea235d318651efcbeb02d44e2cde301e26d65f1bb5724`.
- Nonwaiting selector: `ev_8148b3dd5fc2ac4349e703aeeabd568c6d0790374b186a2a8f889b4497b5bd3a`.
- Undefined group-2 address: `ev_fb94b0ee8f7379a8815f99efc2b28931f77e9bea0f5cf865ac356c491e64c6f2`.

## Follow-up: creation and managed activation audit

The native event setup at `0x1000796F..0x10007AFE` creates 168 events:
135 request-descriptor acknowledgement handles, five auxiliary object handles,
and 14 request / 14 completion handles. Every call requests
`CreateEventA(NULL, FALSE, FALSE, NULL)`: anonymous, auto-reset and initially
unsignaled. In particular, group 2's request event at `this+0xDC` is distinct
from its completion event at `this+0x114` and its descriptor acknowledgement at
`0x10073220`. Creation does not activate `10 10`.

`emulate_lct_event_setup.py` reproduces this exact provider-defined body with
synthetic successful allocation handles. The only allowed native-code writes
are exact event-handle slots and the private stack; descriptor request bytes
must remain unchanged. Only the setup body and a three-byte synthetic RET-16
stub may execute. No Windows event is created, signaled or waited on. This
models requested creation state, not subsequent live event state or allocation
failure handling. Source mismatch and existing output paths are rejected.

An independent dnfile/dncil audit decoded all 1,909 RVA-bearing CIL bodies in
Gen3Tcm (1,104), AllisonDocCore (587) and DocConn (218), with zero decode failures.
It found 29 typed LCT COM call sites covering all 24 named interface methods.
None establishes group-2 activation. Gen3Tcm's ConnectToTCM MethodDef
`0x06000155` calls Connect (`0x06000AB3`) at IL offset 277 and
QueryLCTforStartupData (`0x06000AB5`) at IL offset 690. Three ReprogramEcu
calls resolve to WTEC2, WTEC3 and CEC2 interfaces, not the LCT interface.

This is a bounded static-token audit. Four unknown COM slots are represented
by three `_VtblGap` entries; no managed invocation is declared for those slots.
Reflection, computed dispatch and native external callers remain unresolved.
The native root executable, PlayBMgr, DataReadEngine5_0 and AtlRP1210 were
inventoried and hashed by this audit, not decompiled.

Private follow-up evidence, source hashes, tokens and scripts are retained under
`Tools/AL5/LocalOnly/AllisonPlayback_20261015/SessionFollowup/`:
`managed-call-audit.json`, `managed-findings.json`, `audit_managed_callers.py`,
`native-event-setup.json`, and `lct-event-followup-20261015.snapshot.json`.
The new snapshot contains 70 Evidence records and 28 primitive query bindings.
Event-setup Evidence:
`ev_36b906539b6abe349d08151f6f68a75e5e71dcde963957fb24af69208ef5b2b8`.

Reproduce the added check from `Tools/AL5`:

```powershell
python emulate_lct_event_setup.py $env:AL5_LCT_DLL --output 'PATH\new-events.json'
python -m unittest test_lct_event_setup test_lct_command_tables test_lct_session_callbacks test_allison_playback test_offline test_authorization test_pccs_methods -q
```

Updated validation: 53 tests passed, including the pinned native event setup.
The working reader is unchanged. No controller programming or recovery claim
follows; live writing remains disabled. The remaining activation question now
requires the unnamed native COM slots or computed/native caller paths, rather
than another search of named managed LCT calls.
