# AL5 joined offline erase, programming, finalization and verification

`emulate_al5_program_session.py` extends the native boot-to-loader model through
original erase dispatch/polling, complete calibration block programming,
finalization and host verification of the same modeled flash memory. One CPU
and RAM session carries the state from service `0x34` upload arming to the
final status. No adapter, driver, live controller or flash command runs.

## Successful full-calibration sequence

The public audit uses a generated 57,304-byte calibration fixture with AL5
layout anchors, a patterned data region, native CRC16 and BE16 compensation.
It is synthetic test data. The successful sequence performs:

1. Original resident boot instructions copy the private pinned 1,590-byte
   loader and execute their JSR into its RAM entry.
2. Actual loader receive/dispatch reaches ID/erase code. Synthetic ID/poll
   samples select the normal two-sector path. At each stable poll, a host
   flash model fills the selected conditional sector with `0xFF`; original
   command/reset stores are suppressed before execution.
3. The actual receive/parser/checksum and word loop process **224 blocks**,
   programming every one of the **57,304 calibration bytes** in the model.
   The block resource bound is 256 bytes; the final block is shorter. This
   does not qualify a physical buffer size or safe transfer length.
4. The model restores collateral from its pre-erase synthetic snapshot via
   native block programming. All-FF collateral blocks may be skipped only
   after confirming they are already FF in modeled memory.
5. Finalize arrives through actual receive dispatch. Original code reads a
   declared synthetic pointer table, computes its calibration sum and enters
   the real completion-marker word loop. Matching modeled readback produces
   `76 00 86`, then execution stops before the shared reset exit.
6. Host verification compares full calibration SHA-256/bytes against the
   candidate, checks layout anchors, native CRC16/compensation and zero BE16
   sum, checks marker `0x4AFC`, and compares all collateral bytes to snapshot.

The finalizer, original sender and native caller stacks share the same CPU
state used for upload and block programming. A positive finalization status
is recorded separately from the verification result.

## Conditional erase and collateral model

The explicit hypothetical sector mapping is `0x8000..0x10000` (32 KiB) and
`0x10000..0x20000` (64 KiB). Together those spans cover 98,304 bytes, including
41,000 bytes outside the calibration. The completion-marker word occupies two
of those bytes; the preservation comparison therefore covers **40,998 bytes**
from `0x15FD8` through `0x1FFFD`.

This mapping and the synthetic snapshot are assumptions of the experiment.
They do not prove installed-chip erase scope, current backup completeness or
physical collateral preservation. Erased bytes are host-modeled FF; program
readback uses old-word AND requested-word, so a modeled zero-to-one update
fails without an erase. Native polling/status code executes against that
backing. This simple model does not establish electrical flash behavior,
partial erase effects, timing or recoverability.

## Negative verification cases

The audit additionally completes the same software sequence with:

- A zero-sum image with an incorrect native CRC. Loader status remains `0x86`
  and the marker matches, but independent host checksum verification rejects it.
- Omitted collateral restoration. Calibration hash/checksum and finalize
  succeed, but collateral comparison rejects the result.
- Mismatching marker readback. Native error routing constructs `0xF8`, returns
  to receive with a pending 4-byte call frame, and verification rejects it.

A further fault injected into the successful session after finalization leaves
its marker intact while full hash and checksum verification detect corruption.
Negative cases may skip confirmed erased all-FF calibration blocks to reduce
test cost; the principal case executes every calibration byte through native
word programming.

These checks inspect the same synthetic backing through host memory access;
there is no independent controller readback exchange or physical verification.
The original pointer table is not recovered here. All IRQ/FIFO/readiness
inputs remain synthetic, MMIO/command stores stay suppressed, and reset is
not executed. No interrupted-flash recovery claim follows.

## Reproduce and qualification

`PROGRAM_SESSION_EMULATION.json` contains four scenario reports, source and
implementation hashes, native byte/block counts and verification results. It
contains no original loader payload or controller calibration. The planner
hash-links it while physical programming, physical readback, recovery,
automatic retry, live writing and readiness remain false. The Mode `$23`
reader and C# AL5 write gates are unchanged.

With existing Unicorn 2.1.4 dependencies, `AL5_LOW_DUMP` and
`AL5_CAPTURED_LOADER` set, run from `Tools/AL5`:

```powershell
python -m unittest test_al5_program_session test_offline -q
```

The CLI accepts explicit `--low`, `--loader` and a new `--output` report path;
it runs the synthetic scenarios rather than accepting a live programming task.
Physical startup, actual flash extent/preservation, independent programmed-image
readback and interrupted-flash recovery remain outstanding. Live writes stay
disabled; the installed truck TCM remains outside experimental qualification.

Validation: **358 offline tests passed with no skips**. The production CLI
generated the four-case source-pinned report. The principal native model
processed all 57,304 calibration bytes in 224 blocks. No adapter, controller
or vehicle was accessed; staged changes passed `git diff --cached --check`.
