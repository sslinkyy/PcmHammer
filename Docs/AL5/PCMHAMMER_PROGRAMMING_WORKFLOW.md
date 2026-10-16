# PcmHammer AL5 offline programming workflow

The shared `Apps/PcmLibrary/AL5ProgrammingWorkflow.cs` now owns a typed,
file-only assessment of the modeled AL5 programming sequence and retry
constraints. Both the WinForms file tools and the shared `WriteManager` consume
it. The workflow has no vehicle/adapter dependency, packet payload, execution
callback or enable switch. The existing Mode `$23` reader is unchanged.

For a calibration that passes the existing inspector, the assessment describes
these modeled stages in order: boot/loader entry, conditional erase, calibration
blocks, collateral restoration, finalization and independent verification.
Dense calibration transfer has 224 blocks and collateral restoration has 161
blocks, each bounded to 256 bytes with a shorter final block. These are offline
resource bounds, not a qualified physical transfer size. The conditional erase
scope remains `0x8000..0x20000`, including collateral and the final marker;
physical erase geometry is unverified. This is a layout, not an executable plan.

`Assess(candidate, snapshot, collateralBackup)` accepts a 57,304-byte candidate,
an optional 98,304-byte saved flash range at `0x8000`, and an optional independent
40,998-byte pre-erase collateral baseline at `0x15FD8`. It owns copies while
computing and returns immutable facts with SHA256 digests. Invalid candidate
files yield inspector errors and no stage layout or retry comparisons. Wrong
snapshot/backup lengths are rejected before copying or comparing.

Retry assessment preserves the distinction between data and session state:

- No snapshot: `SnapshotRequired`.
- A requested one bit is already cleared: `ZeroToOneConflict`, with word counts
  and the first conflicting address in each region. A simple word retry cannot
  resolve this under the current model.
- Missing independent collateral baseline: `CollateralBaselineRequired`, even
  when calibration and marker match.
- Exact calibration, collateral and `4AFC` marker: `SavedImageMatches`.
- Remaining differences only clear bits: `ClearOnlyDifferences`. This is an
  arithmetic observation, not permission to retry.

Last-operation success and loader-session reuse remain nullable unknowns in
every case. No ACK input can turn a file comparison into proof of success, and
matching bytes cannot prove that native pending call frames were unwound.
Physical readback, recovery, automatic retry, live writes and readiness remain
false, with no override.

In WinForms, use **Tools → AL5 Assess Saved Flash Snapshot (Offline)**. Select a
candidate and the exact saved flash range, then select the independent collateral
backup or cancel that selection if unavailable. Cancellation leaves collateral
unknown; it never reconstructs a baseline from already erased data. The log
contains input paths, hashes, region counts, conflicts and blocking reasons.
The calibration comparison command also displays the modeled stages. Both file
commands remain available without selecting an interface and do not initialize
one. No new live-read or capture operation is part of these commands.

`WriteManager.Write` still rejects every AL5 calibration segment before any
vehicle query, security exchange or programming call, including forced PCM
types. It now reports the shared offline assessment and candidate validation
errors before returning false. Other PCM writing paths are unchanged.

Validation on 2026-10-15:

- BCL-only production-source harness: 17 checks passed, including eight workflow
  scenarios for range coverage, partial writes, conflicts, missing collateral,
  independent marker verification, invalid inputs and immutable reports.
- Production `WriteManager` with a null vehicle and no prompts: 210 valid/invalid
  AL5 image, write-type and forced-controller combinations returned false and
  logged the expected offline assessment before vehicle access.
- Shared library and WinForms application compiled. No adapter or controller
  was opened. Interactive file dialogs and Uno UI were not exercised.
- Existing Python file-reconciliation and blocked-planner regression groups:
  31 tests passed. Native emulation code was unchanged and was not rerun here.

The C# assessment carries the same data-versus-authority distinction as
[Python snapshot reconciliation](SNAPSHOT_RECONCILIATION.md). Native instruction
experiments remain in the existing offline tools; none of this establishes
physical programming or interrupted-flash recovery.
