# AL5 error sender timeout and native software reentry

## What the Allison tools established

The supplied Allison artifacts materially improved the reconstruction: PCCS
FIL/file selection, block-write logic, preparation and checksum/readback ranges
are traced in the existing reports. The documentation describes LCT programming
over CAN and excludes writing through the documented SPX J1850-VPW interface.
A real TJ1850 class and inherited programming methods exist, but a complete
compatible AL5 VPW programming route remains unproven. The examined WriteCal
body does not reproduce the UI's explicit J1850 exclusion, so those UI controls
must not be treated as proof that all programmatic routes are impossible.

See [PCCS LCT programming](PCCS_LCT_PROGRAMMING.md),
[J1850 route](PCCS_J1850_PROGRAMMING_ROUTE.md), and
[WriteCal callee effects](PCCS_WRITECAL_SWITCHES_CALLEE_EFFECTS.md).
The captured EFILive loader supplies the concrete VPW-side erase, word-program
and finalization code currently modeled. Neither source alone establishes a
complete physical session or preservation/recovery after erase.

The candidate implementation path is now specific: identify and qualify the
controller/session; upload and enter the matching RAM loader; issue its erase,
block-program and finalize operations; independently verify image integrity
and readback. Important boundaries remain: boot and loader models are still
separate, flash/FIFO effects are synthetic, erase preservation is unqualified,
and no interrupted-flash recovery has been demonstrated. A stock utility name,
a positive status, or an offline test pass cannot replace those observations.

## New joined sender model

`emulate_loader_error_sender.py` extends the same-session erase/program models
through the original status sender, its polling counter, timeout JMP and actual
loader reentry. No selected restart call is substituted. The captured loader
SHA-256 remains
`b545d9b2d078662466ab32d9cdeb5b3c38c840135e8aeca09f33760ec66780fa`.
Source and dependency hashes are in `LOADER_ERROR_SENDER_EMULATION.json`.

All FIFO control/data stores are suppressed before execution. Readiness values
are synthetic; staged bytes are observations of intended FIFO values, not wire
transmission. Watchdog/delay and broadcast-cleanup helpers remain guarded
synthetic callbacks. Every flash command/reset store remains suppressed or
trapped. No adapter, hardware register, driver or vehicle runs.

Six sequences distinguish:

- Returning error sender: the actual sender returns after six synthetic-ready
  checks, then nonlocal error routing retains -4 program or -12 erase bytes.
- First-byte busy timeout: native countdown reaches its timeout and executes
  `0xFF95E8` JMP to `0xFF9000`. Before that jump the program-error stack is -16;
  the erase-error stack is -24. Only the priority byte has been staged. Actual
  loader entry resets A7/budget, retaining D7 and modeled partial word state.
- Last-byte busy timeout during an erase error: all six intended bytes have
  been staged, but the sender does not reach its normal return. Pending stack
  is -28 at the jump, including sender/body/error and three erase return words.
  Loader reentry restores the stack pointer, without flash rollback.
- Last-byte busy timeout after modeled programming success: intended body
  `76 00 73` is constructed and all six bytes staged, but sender completion and
  the later cleanup call are bypassed. A -16 pending stack is replaced by
  original entry. The host's receipt of a success reply remains unknown.

The full captured-stack words are included in the report, from current SP
upward. These cases explain why a simple host timeout cannot determine whether
an operation completed or whether retrying is safe. They do not determine
whether physically staged bytes would already have appeared on the wire.

Nine tests cover source/input/output guards, native sender return, exact
pending frames, timeout-to-entry continuity, partial/complete byte staging,
cleanup bypass and an explicitly selected later frame. A planner test pins the
report while physical acknowledgment, recovery, automatic retry, live writes
and readiness remain false. No C# write gate or Mode `$23` reader changes occur.

With the existing Unicorn 2.1.4 path and `AL5_CAPTURED_LOADER` configured, from
`Tools/AL5`:

```powershell
python -m unittest test_loader_error_sender test_loader_sender test_offline -q
```

This advances the software reconstruction. Physical VPW startup/upload,
actual flash state, collateral preservation, independent readback and recovery
qualification remain outstanding. The user has no recoverable spare AL5; the
installed truck TCM remains outside experimental qualification. Live writing
stays disabled.

Validation: **335 offline tests passed with no skips**. The CLI reproduced the
six-case evidence report byte-for-byte; staged changes passed
`git diff --cached --check`. No adapter or controller was accessed.
