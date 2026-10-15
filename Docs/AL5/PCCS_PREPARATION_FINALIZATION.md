# PCCS preparation, routing and post-write checks

2026-10-15, offline. Standard-LCT preparation connects to RequestSeed,
SendKey and an ordinary boot-request builder. Post-write tracing identifies
BlockFill and EndWrite. Their results do not establish checksum or readback
verification. Actual AL5 routing and interrupted-flash recovery remain
unproven; live writing stays disabled.

Follow-up: [QuickWriteData and optional readback](PCCS_QUICKWRITE_READBACK.md)
traces the indexed getter/route conditions and a real W/WC configured-byte
comparison. That optional comparison does not establish whole-flash integrity.

## Source and scope

Installed Winrw32.exe SHA-256:
`13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.
Private Capstone 5.0.6 windows, metadata and findings are retained under
`Tools/AL5/LocalOnly/PCCS_20261015/PreparationTrace/`:

- `PREPARATION_ROUTING_FINDINGS.md` and routing/configuration source windows.
- `POSTWRITE_VERIFICATION_FINDINGS.md`, `postwrite-verification-source.json`.
- `native-prepare-slice.json`: seven native request/status contexts.
- `native-end-write-final.json`: nine native finalization contexts.
- `pccs-preparation-finalization-20261015.snapshot.json`: 31 retained REA
  Evidence records, four primitive bindings, including earlier analysis.

Interior windows are not full recovered functions or reachability proofs.
Ghidra leaves EnterWrite, BlockFill, ReadData and EndWrite undefined in this
session. These were not promoted or mutated. Emulation uses explicitly bounded
source instructions, not provider-defined function claims. Some exploratory
linear reference scans stopped at embedded data; their empty output is not a
negative-reference proof. No Windows API, executable entry point, COM object,
adapter or controller ran. Selected instructions ran in private Unicorn memory.

## Preparation before erase

WriteCal invokes TJ1939 VMT +`0x3C` at `0x7C5A98` or `0x7C5AAB`, passing
argument `0A` or `0B`, controller index and stack flag 1. This resolves to
**EnterWrite**, `0x5B87AC`, named by its Delphi descriptor. Host status zero
at `0x7C5B6A` gates erase. A conditional retry is specific to family 1,
version 7, status 3; it must not be generalized to standard-LCT recovery.

EnterWrite expressly includes family 1/version 0 (`standard_lct`) when the
caller flag is enabled. It calls VMT +`0x34` = **RequestSeed** (`0x5B6138`)
and +`0x38` = **SendKey** (`0x5B6718`), with key/file operations between them,
then later marks per-controller +`0xB5`. Complete key derivation, acceptance
and failure behavior are not reconstructed here.

With object +`0x72D90` zero, the builder at `0x5B8ED6` constructs internal
`10 01 00 01`. Version 5 appends `B0`, `BF` or `AC` according to its selector.
This differs from DOC's `10 10`. Dispatch uses request class 1, timeout
parameter 1,000, controller index and trailing zero. These are host buffers
and parameters, not qualified CAN or VPW packets.

The actual status mapping clears initial host status 1 to zero, skipping the
response-byte test. Initial status zero with a nonzero +`0x52679` response
becomes status 3; other nonzero statuses remain. Zero here therefore does not
independently prove a positive controller acknowledgement. Subsequent ordinary
identification polling uses VMT +`0x70` and InBoot (`0x5ADC54`), with up to 12
iterations; exhaustion sets status 8. Entry retries do not prove recovery.

`emulate_pccs_prepare.py` runs only `0x5B8ED6..0x5B8FED`, stopping before
identification polling or error-text formatting. It excludes seed/key
prerequisites and full EnterWrite. Seven cases reproduce the request variants
and status mapping with synthetic dispatcher replies.

## Routing owners and unresolved AL5 state

Configuration loads a **UDS** string list and looks up the selected section.
A nonempty result sets globals `0x81D140/144/148` and object +`0x72D91`, among
other changes; an empty result clears several flags. Preparation/identification
also modify them. Global `0x81D148` is mutable routing state, not AL5 identity.
The version-7 identification route explicitly sets +`0x72D90`; that does not
establish its value in a standard-LCT session.

Object +`0x68C60` is initialized/reset to zero, but identification can enable
it for a version-zero context, including a condition involving target index 3,
a capability threshold and global `0x81D16C`. WriteData can then use VMT
+`0x18`, **QuickWriteData** (`0x5B4F80`), instead of its ordinary four-byte `22`
fallback. QuickWriteData constructs internal `23` requests in the examined
source; their semantics must not be inferred from the existing VPW Mode `$23`
reader. The earlier WriteData emulator forced these alternate-routing fields
to zero. It remains a synthetic branch check, not the confirmed truck route.

## Post-transfer work and finalization

The continuation is not uniformly verification. Numeric operation modes 1..4
can perform additional power-off-data erase/write work. The standard family-1,
version-0 branch includes erase arguments 1 then 2 and another 256-byte write
loop starting at `0x4000`, count `0x40`. Mode ownership, array construction,
physical geometry and preservation still require proof.

The selected path can next call **BlockFill**, VMT +`0x20` = `0x5B5C08`.
Modes 2/4 bypass it; other flags/statuses also gate it. The standard caller
argument zero builds internal `60 4A FC 00`, timeout parameter 45,000.
BlockFill can normalize host status 2 to zero, and some bypass branches return
zero without dispatch. This is not an independent integrity check.

With host status zero and a separate local flag clear, WriteCal calls
**EndWrite**, VMT +`0x40` = `0x5B93E4`, with checking enabled. UI text says
"Exiting programming mode". VMT +`0x2C` is **ReadData**; it is not invoked as
an identified verification routine in this selected continuation.

Ordinary EndWrite constructs internal `11` (version 7: `11 00 00 00`), delays
and reinitializes communication. Its inner loop permits three initialization
calls; statuses zero and `0C` end that inner loop early, although `0C` remains
failure at the final gate. With status zero, InBoot checks refreshed identity.
Standard-LCT InBoot compares an identity string to ASCII `BP `, not flash data.

Persistent boot mode can repeat three outer attempts, allowing up to nine
initialization calls, and finally becomes host status 7. These are application/
boot-readiness checks, not checksum validation or interrupted-flash recovery.
No byte comparison, readback buffer or checksum calculation was identified
in this bounded EndWrite body. This is not a whole-application absence claim.

## Offline models and validation

`emulate_pccs_end_write.py` runs `0x5B93E4..0x5B96C9` in synthetic ordinary
contexts. Prefix, send, initialization, boot predicate, sleep and cleanup are
replacements. Sleep arguments are recorded without waiting. Native temporary
communication flags must be restored. Both new tools guard source identity,
execution/write bounds, instruction budgets, callback context and stack balance;
EndWrite also rejects exhausted synthetic response sequences.

Nine EndWrite cases cover normal readiness, disabled checking, initialization
retry/failure, persistent/transient boot mode, nine initialization calls,
version-7 request construction and status `0C`. Disabled checking can return
zero without a readiness predicate; this remains an explicit limitation.

From `Tools/AL5`, with optional Unicorn 2.1.4:

```powershell
$env:AL5_PCCS_EXE = 'PATH\Winrw32.exe'
python emulate_pccs_prepare.py $env:AL5_PCCS_EXE --output 'PATH\new-prepare.json'
python emulate_pccs_end_write.py $env:AL5_PCCS_EXE --output 'PATH\new-end-write.json'
python -m unittest test_pccs_end_write test_pccs_prepare test_pccs_native_write test_pccs_file_chunks test_pccs_framing test_lct_typelib test_lct_event_setup test_lct_command_tables test_lct_session_callbacks test_allison_playback test_offline test_authorization test_pccs_methods -q
```

**87 tests passed**, including ten new test methods and 16 native contexts.
Source mismatches and existing output paths are rejected. Real-input tests
skip explicitly if their input or emulator is absent. The working reader and
live-write gates are unchanged.

Preparation is partially traced; routing owners are identified but effective
AL5 state is unresolved; post-write readiness is modeled but integrity and
recovery remain unproven. Next: RequestSeed/SendKey acceptance, identification
to QuickWriteData, and independent checksum/readback coverage of exact
programmed and preserved regions.

REA undefined-entry observations, not recovered-function claims:

- EnterWrite: `ev_a1c0fb9b7bb9e96a73926785e80b5b417fffb53bdc7abaf5c96389f935f4608f`.
- EndWrite: `ev_f86adcaa5986074ecfa8bd0e56500f7364143936ab3eea2b13c7daa83f37e1c0`.
