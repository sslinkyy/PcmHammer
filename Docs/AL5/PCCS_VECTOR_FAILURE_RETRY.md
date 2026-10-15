# PCCS vector failure and initialization retry

2026-10-15, offline continuation from `PCCS_SLOW_WRITES_CHECKSUM_RANGES.md`.
A failed vector comparison exits the nested write body after forcing Slow
Writes. A separate wrapper loop offers an initialization retry for status
`0x0C`. The traced vector mismatch does not enter that retry automatically.
Live writes remain disabled.

## Vector mismatch versus read error

The standard-LCT gate and `0x20000..0x2040F` read span were established in
the previous findings. After ReadData returns, `0x7BAAA5..0x7BAAB3` uses the
actual status getter `0x5B0AF0`. Nonzero read status skips the comparison
through `0x7BAC36`; the later status test branches to `0x7BBADB`. That path
calls `0x5D3310` with EDX zero, logs `FE` (`Error communicating with TCM`),
sets global `0x9E03B8` to 1 and
joins cleanup. It is distinct from the byte-mismatch branch.

With zero read status, `0x7BAAB9..0x7BAC30` scans the read buffer and expected
file blocks `0x200..0x204`. Positive block length permits an expected-byte
load and comparison. On mismatch it checks that the byte offset is below
the declared length before recognizing failure. An absent block skips this;
a mismatch beyond a short block's length is ignored. The source loads the
expected byte before that latter length check: these observations do not
establish general pointer safety for malformed file metadata.

A recognized mismatch at `0x7BAB4A` calls `0x5D3310` with EDX zero, formats
segment/byte coordinates, logs `F8` with `Vector check failed: $`, disables
controls and sets the Slow Writes byte to 1 at `0x7BABE1`. The unconditional
jump at `0x7BABE4` goes to cleanup `0x7BBB31`. This branch bypasses the normal
continuation and does not itself restart writing or rerun identification.

The Delphi descriptor names helper `0x5D3310` as `Close_Hardware`; its source
closes host communication resources and clears object +`0x2E`. This identifies
a host communication close operation, not a controller recovery command.

No direct store to object +`0x68C60` appears in this local failure slice.
The host helper's full effects are excluded from the new native model, so
unchanged synthetic route state is not proof that the complete application
preserves the route flag through every call.

## Caller and retry condition

The nested body beginning `0x7B66A4` returns after cleanup at `0x7BBE04`.
Its direct call at `0x7BE8B9` is in wrapper `0x7BE7C4`; a bounded direct-E8
candidate inventory does not exclude indirect callers.

At `0x7BE897`, the wrapper clears BL and calls initialization `0x5D6C5C`
with DL 1 and CL 0. The following status decision is:

- Status zero calls the nested body.
- Status `0x0C` enters initialization-error handling.
- Other nonzero statuses reach the final retry test without setting BL.

For initialization status `0x0C`, option byte `*0x81F480 == 1` logs `FD`
and exits that attempt. Otherwise PCCS builds an initialization-error dialog,
including protocol, hardware error text and port. Virtual +`0x110` supplies
its result. `0x7BE9DA` compares that result to 4; only equality sets BL to 1.
The test at `0x7BE9F7` then jumps back to `0x7BE897`, starting initialization
again. No numeric attempt limit or delay is observed in this wrapper loop;
repeated dialog approval can request repeated attempts. Callee-internal
limits and waits remain separate unknowns.

After the nested write body returns, the wrapper can run an optional report
path gated by `0x81E810` and `*0x81F44C`, then reaches the retry test. There
is no identified BL setter on the vector-mismatch return path. The nested
body saves EBX at `0x7B66B4` and restores it at `0x7BBE00`; the optional report
saves it at `0x7BEBD8` and restores it at `0x7BF0D2`. These ordinary returns
preserve the wrapper's BL, verified from source rather than calling-convention
assumptions. Exceptional returns and transitive cleanup effects remain outside
this proof. The traced behavior is failure/cleanup plus a Slow Writes setting change,
not an automatic slow rewrite after vector failure. Future operation routing
still depends on object state and identification. The initialization status
check occurs before calling the write body: a `0x0C` returned later by
QuickWriteData is not itself an edge back to this dialog decision.

These retry mechanisms have distinct scopes. The previously modeled
QuickWriteData send loop retries transport return words 11/137, up to 41
attempts. The wrapper here repeats initialization after a dialog decision.
The vector mismatch path performs neither loop automatically. None of these
constitutes interrupted-flash recovery.

A distinct reset helper, VMT +`0x70` / `0x5DCB40`, clears object +`0x68C60`
at `0x5DCB54` before calling identification `0x5D8EC8`. Its reachability from
this initialization call is not yet established. Do not assume the next
attempt necessarily uses ordinary writes solely because Slow Writes is on.

## Offline models and limits

`emulate_pccs_vector_check.py` executes the actual post-read comparison and
local failure slice with synthetic buffers, file metadata, status and prior
flags. It uses the real pure status getter; host helper, formatting, logging
and UI calls are synthetic callbacks. Native writes are restricted to the
private stack and one-byte Slow Writes flag. The model stops at normal
continuation or failure cleanup. It executes no read, write or retry.

Nine cases cover matching data, read error, absent blocks, a mismatch outside
a short block's declared length, and failures at offsets 0, 255, 256, 1024
and 1039. Tests check coordinates, callback order, control-flow stops, source
pin rejection, invalid contexts, bounds and existing-output preservation.
The unchanged synthetic route flag is explicitly scoped to excluded helpers.

`emulate_pccs_retry_gates.py` executes thirteen independent native gate contexts:
initial status, dialog result and final BL test. The actual status getter runs;
initialization, write body, dialog and optional report do not. Synthetic prior
BL values demonstrate source preservation, not a full linked retry scenario.
The wrapper explicitly starts each attempt with BL zero. Report:
`native-retry-gates.json`. A source pin, strict instruction/write bounds,
instruction budget, balanced-call checks and exclusive output apply to both
models.

**117 tests passed**, with the installed pinned PCCS/DOC inputs and both S2
images present, with no skips. Nine new test methods cover these two models;
the vector tests also compare nonuniform data and corrupt expected bytes after
a block boundary. From `Tools/AL5`, with the optional pinned Unicorn dependency
and `AL5_PCCS_EXE` pointing to the existing executable:

```powershell
python -m unittest test_pccs_vector_check test_pccs_retry_gates -q
```

All sources pin Winrw32.exe SHA-256
`13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.
Private source windows and reports remain under
`Tools/AL5/LocalOnly/PCCS_20261015/QuickWriteTrace/`.
The final vector report is `native-vector-check-final.json`.
Outer control-flow evidence is `vector-failure-outer-exits-source.json`;
ordinary-return preservation is in
`vector-optional-report-ebx-preservation-source.json`. Detailed private findings
are in `VECTOR_FAILURE_OUTER_RETRY_FINDINGS.md`.
No application entry point, Windows API, UI, COM object, adapter or controller
executed. The working Mode `$23` reader and live-write gates are unchanged.

## Remaining questions

The initialization retry decision is identified, but complete initialization
and route requalification are not. Full programming acceptance, independent
image/preserved-area verification and recovery after erase or interruption
remain unproven. Switching a setting or retrying initialization does not
establish recovery of an erased or partially programmed controller.
