# AL5 integrated interruption, retry and reconstruction experiments

`emulate_al5_interruptions.py` adds seven explicit failure/retry scenarios to
the joined boot/upload/erase/program/finalize model. All flash bytes, faults,
persistence and FIFO behavior are synthetic. No adapter, driver, controller,
physical interruption or hardware reset runs. Live writes remain disabled.

## Interruption and snapshot ownership

The model stops at declared boundaries after a selected sector erase or word
write, before the marker write, or after the marker write but before its poll
and status. The interrupted instance becomes closed: further block exchanges
are rejected. A snapshot can retain only the conditional flash backing and an
optional external collateral backup. It contains no CPU registers, stack,
receive buffers, upload flag or other RAM.

A fresh emulator imports that snapshot and explicitly selects synthetic boot
interrupt entry. Original boot code uploads the pinned loader again. This
exercises native upload/entry with fresh emulator state; it does not prove
physical reset, retained flash values, boot integrity gates, IRQ availability
or loader reentry after real power loss. Imported snapshot SHA-256 values are
recorded without publishing raw snapshots or loader bytes.

The previous verifier now represents an absent collateral baseline explicitly:
`collateral_backup_available=false`, `collateral_before_sha256=null`, and
`collateral_matches=null`. Unknown collateral cannot satisfy verification.
The fresh-instance constructor does not recreate a lost baseline from its
fixture initialization. Existing sessions with a real model snapshot baseline
continue to compare all 40,998 collateral bytes.

## Seven scenarios and observations

- **First-sector interruption, external backup retained.** The model contains
  an erased first sector and the original second sector. A fresh emulator,
  explicit two-sector reerase, calibration programming, collateral restoration
  and finalization reconstruct the expected modeled image successfully.
- **Same interruption, backup missing.** Calibration and marker can match after
  reconstruction, but collateral comparison remains unknown and verification
  fails. A new CPU instance must not magically supply the pre-erase baseline.
- **Partial block, identical retry.** Stop after four completed modeled words.
  In a fresh instance, retrying identical bytes succeeds under the model's
  old-word AND requested-word rule. Subsequent sparse reconstruction verifies.
  This assumes those completed words persisted exactly; it does not prove
  repeat programming is electrically safe or that an in-flight word is known.
- **Chosen unwanted zero bit.** An explicitly injected fault clears a bit the
  candidate requires to be one. An identical retry cannot restore it, producing
  native status `0xF8` and a pending four-byte call frame. Explicit reerase and
  reconstruction repair the synthetic bytes; the old retry-error frame still
  remains at finalization. The injected word is a chosen counterexample, not
  an observed chip power-loss outcome.
- **Acknowledgment lost, duplicate and conflicting retries.** The actual sender
  timeout runs after all reply bytes are staged and jumps to loader entry.
  An identical block succeeds in the model. A conflicting block requesting
  zero-to-one changes fails with `0xF8`; later successful reconstruction leaves
  that error frame pending. No automatic retry is authorized by this result.
- **Interruption before marker.** Calibration CRC and collateral can match while
  the marker is erased and verification fails. Explicit fresh-instance boot
  entry and finalization complete the modeled marker; no erase is assumed to
  be necessary in this chosen unchanged-flash snapshot.
- **Interruption after marker.** Full data verification can pass although no
  final response was constructed. Explicit fresh-instance finalization also
  passes. A missing acknowledgment alone does not identify an incomplete image.

The last two cases distinguish data state from acknowledgment state. None
establishes real application bootability, flash mode cleanup or recovery.
Successful modeled verification may coexist with pending native call frames;
it cannot qualify the runtime session or make further writes safe.

## Tests, evidence and remaining qualification

The tests check exact native status/stack results, terminal interrupted
instances, partial-sector contents, fresh-RAM isolation, immutable snapshot
shape, explicit backup absence, duplicate/conflicting retries, marker timing
and continued physical qualification gates. `INTERRUPTION_RETRY_EMULATION.json`
contains seven source-pinned scenario reports. The previous integrated-session
report is regenerated for the verifier's additive absent-backup semantics.

The offline planner hash-links the new evidence while physical interruption,
programming/readback/recovery, automatic retry, live writing and flash readiness
remain false. The Mode `$23` reader and C# AL5 write rejection are unchanged.

With existing Unicorn 2.1.4 dependencies, `AL5_LOW_DUMP` and
`AL5_CAPTURED_LOADER` configured, run from `Tools/AL5`:

```powershell
python -m unittest test_al5_interruptions test_al5_program_session test_offline -q
```

The 32 KiB/64 KiB erase map, chosen word faults and snapshot persistence remain
model assumptions. Current physical backups, real erase preservation, actual
VPW reset/upload/readback and interrupted-flash recovery remain unqualified.
The installed truck TCM stays outside experimental qualification.

Validation: **371 offline tests passed with no skips**, including twelve new
interruption/snapshot/retry tests and a planner evidence/qualification test.
The CLI generated the seven-case source-pinned report. No adapter, controller
or vehicle access occurred; staged changes passed `git diff --cached --check`.
