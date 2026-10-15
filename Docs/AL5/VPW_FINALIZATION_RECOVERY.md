# AL5 loader finalization and conditional recovery routes

The captured loader's finalization and error paths now execute in bounded
offline models. The saved application also exposes conditional calibration
marker/CRC failure routes toward resident boot code. This improves the
programming reconstruction; it does not establish a complete physical VPW
session, safe retries, power-loss recovery or permission to write.

## Reconstructed sequence and evidence boundaries

The saved traces contain RAM-transfer subtype `0x80` loading a common 1,590-byte
loader at `0xFF9000`. The supported trace interpretation still contains no
matching erase, block-program or finalize requests. The following destructive
stages are therefore loader-code observations rather than captured successful
transactions:

- Service `0x36`, subtype `0xEE`: ID check, then erase calls at `0x8000` and
  `0x10000`. Under the still-conditional CPU/chip mapping this reaches 98,304
  bytes, including 41,000 bytes outside the calibration. Current collateral
  backup and preservation remain unverified.
- Subtype `0x00`: block length/address/payload parsing, byte-sum check and
  word programming. `0x73` is constructed after the successful program path;
  `0x77` follows a bad block sum. Bounds, physical framing and safe block
  sizes remain separate requirements. Subtype `0xDB` can return success
  after a delay without programming, so status alone is insufficient.
- Subtype `0xFF`: sum the calibration range, attempt completion marker
  `0x4AFC` at `0x1FFFE`, construct final status, then enter a shared reset
  sequence. The new model executes these native verification and error
  branches while suppressing flash commands and hardware transmission.

Source loader SHA-256 is
`b545d9b2d078662466ab32d9cdeb5b3c38c840135e8aeca09f33760ec66780fa`.
The pointer table is synthetic in the finalizer model, using the previously
pinned saved-image bounds `0x8000..0x15FD7`. Source images remain saved editor
memory, not current physical backups. No packets are produced for replay.

## Finalization and failure behavior

`emulate_loader_finalize.py` executes the original finalizer at `0xFF91D6`
through its sum loop, marker word-program loop and error/status builder.
Flash command/reset stores are skipped, marker readback is synthetic, and
the hardware sender is a guarded return stub. Execution stops before the
shared reset exit or at the receive boundary.

Eight contexts show:

- Valid zero-sum data and matching modeled marker readback construct `0x86`
  and reach the shared exit.
- A zero-sum image with an invalid native CRC does the same. Finalize does
  not recompute native CRC16; its positive status is not complete image
  verification.
- Bad-sum, erased and partial synthetic calibration images construct `0xFF`
  and still reach the shared exit. An existing old marker is not cleared
  by the sum-failure branch.
- Marker readback failure constructs `0xF8`, skips the later `0x86`/shared
  exit, and jumps to receive. The pending word-program return frame remains
  on the synthetic stack: delta `-4` bytes. This is a nonlocal error branch,
  not rollback or qualified retry.
- Stopping before the marker command leaves the synthetic erased marker
  untouched; this is an instruction-boundary test, not a physical
  interrupted-programming experiment.

Independent static tracing also distinguishes timeout/error behavior:

- Receive idle/partial-frame timeout reaches `0xFF9236`, delays, writes
  peripheral controls and attempts a reset-register store at `0xFFFF8000`,
  then self-loops if no reset occurs. The absolute-short address is not
  calibration flash `0x8000`. The model does not execute the reset store.
- Sender polling timeout jumps to RAM entry `0xFF9000`, which reinitializes
  its stack/budget. It does not restore flash or clear all receive state.
- Program errors pass flash reset-command stores before reporting failure.
  Some erase/ID failures bypass their reset stores. The erase toggle poll
  has no identified explicit software deadline.
- With a returning sender, static ordinary-program and erase-poll error
  paths retain 4 and 12 bytes of pending call frames respectively. Repeated
  failure is not proven idempotent; a later sender restart can change this
  state again. Earlier successful words are not rolled back.

## Application integrity and boot error routes

`emulate_calibration_marker.py` runs original application marker checks,
incremental CRC code/table and interrupt masking in read-only synthetic ROM.
Only declared stack/state fields are writable. It separately invokes a
selected reset-marker branch; it does not run a reset or full boot startup.

When synthetic entry flag `A5+0x104` is set:

- Missing/partial calibration marker writes RAM error `CC8B` and spins.
  The separately selected boot branch changes it to `C7D8` and reaches `0x97C`.
- Calibration CRC mismatch writes `30D4` and spins; the selected boot branch
  changes it to `3E91` and reaches `0x97C`.
- A CRC-correct prefix identifier mismatch writes `9515`; the selected
  boot branch changes it to `C12A` and reaches `0x97C`.

The initial flag's complete producer remains unresolved. With that flag
clear, a valid-CRC image with an erased marker returns without reading the
marker. Consequently, this is not a universal erased-marker recovery gate.
Bulk initialization, computed aliases and intervening startup are unknown.

The CRC sweep checks the stored word at `0x15FD4` and excludes the compensation
word at `0x15FD6`. Compensation-only corruption can pass this application CRC
check while failing the loader's BE16 sum. Conversely, independent synthetic
handoffs show zero-sum/bad-CRC data receiving loader status `0x86`, then being
rejected with application marker `30D4`. These are joined test inputs between
independent slices, not a continuously executed programming/reset session.
PcmHammer's file checks must continue requiring both checksum components.

Boot also checks a different application marker at `0xFFFFE`; it must not be
conflated with calibration marker `0x1FFFE`. Peripheral startup, RAM retention,
application integrity and VPW availability after failure remain unverified.

The static continuation beyond `0x97C` preserves a RAM marker around RAM
operations and jumps to caller `0xA78`. That caller invokes several peripheral
initializers, tests separate byte `0xFF8010` at `0xAB4`, conditionally calls
the previously modeled initializer `0x3B7C`, and later calls `0x2A24`.
The separate byte's producer reads hardware word `0xFFFD02`; its physical
meaning is unresolved. Callee effects and placeholder-looking operands in
adjacent saved initialization code prevent treating these calls as a proven
VPW listener after power loss. The application `+0x104` flag and boot
`0xFF8010` flag are distinct.

## Reports, planner and verification

Public metadata reports are `LOADER_FINALIZATION_EMULATION.json` (eight
contexts) and `CALIBRATION_MARKER_EMULATION.json` (nine). They contain hashes,
bounded observations and explicit limitations, not loader or calibration
payloads. The file-only write planner hash-links both reports and their
implementations under `calibration_recovery_assessment`. Its physical reset,
VPW re-entry, recovery and automatic-retry qualifications remain false.

Validation: **252 tests passed with no skips**, including twelve new native/
guard test methods and a planner evidence/qualification test. The native
inputs used pinned LOW/HIGH/loader files with Unicorn 2.1.4. Focused commands
from `Tools/AL5`, with `AL5_CAPTURED_LOADER`, `AL5_LOW_DUMP`, `AL5_HIGH_DUMP`
and the existing Unicorn dependency path configured:

```powershell
python -m unittest test_loader_finalize test_calibration_marker test_offline -q
```

Private source windows and findings are retained under
`Tools/AL5/LocalOnly/VPWRecovery_20261015/`, including
`captured-loader-recovery-source.json`, `CAPTURED_LOADER_RECOVERY_FINDINGS.md`,
`marker-startup-source.json`, `MARKER_RECOVERY_FINDINGS.md` and
`boot-continuation-decisive-source.json`. No new provider
function-completeness claim is made. No PCCS/EFILive application, flash/MMIO
operation, adapter or controller ran. Mode `$23` reading is unchanged, and
PcmHammer's unconditional AL5 live-write rejection remains in place.

The remaining gates are a complete physical VPW entry/upload/acknowledgment
sequence, proven erase scope and preservation, independent programmed-image
readback, and a demonstrated recovery route after erase or power loss. The
conditional boot branches identified here do not yet satisfy those gates.
