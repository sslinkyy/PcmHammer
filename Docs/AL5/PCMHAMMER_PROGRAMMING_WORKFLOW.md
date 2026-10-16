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

## Ordered offline coordinator (2026-10-16)

`AL5OfflineProgrammingSession` now expands the shared stage layout into 389
immutable, ordered operations: boot/loader entry, conditional erase, 224
calibration blocks, 161 collateral blocks, finalization and saved verification.
The final calibration block is 216 bytes; the final collateral block is 38 bytes.
There are no payloads, packets, transport callbacks or live execution methods.
The constructor requires a valid candidate and an exact independent collateral
baseline before a rehearsal can start. It owns copies of both input buffers.

The synchronous host coordinator accepts explicit **model** results against the
exact pending operation object. Reused ordinals or addresses from another attempt
do not identify that operation. Stale, duplicate, out-of-order and foreign-attempt
results are rejected without changing the cursor or journal. Modeled completion
advances one operation; lost replies, model failures, interruptions and cancellation
stop the attempt immediately, retaining the pending operation and outcome.

`AssessStoppedSnapshot` compares saved bytes using the existing assessment. It
never resumes or advances the stopped attempt, including when the complete saved
image matches. A reconstruction rehearsal requires explicitly creating a separate
session, which begins at boot/loader entry and conditional erase with a new set
of operation identities. This choice is a host-model experiment, not proof that
a physical TCM can reenter its loader or survive another erase.

Finalization completion cannot substitute for verification. The last operation
requires `RecordSavedVerification` and matching calibration, collateral and marker
bytes. A damaged region stops the attempt; malformed verification input changes
neither the journal nor state. A match yields `SavedImageVerified`, which describes
the supplied files only. Physical operation success and loader-session reuse
remain unknown; live writing, automatic retry, recovery and readiness remain false.
Observation collections are immutable snapshots, and include the snapshot SHA256
when verification was assessed.

The WinForms saved-snapshot tool now also prepares this coordinator when a valid
candidate and independent collateral file are supplied. It logs the operation
count and first pending stage, without supplying any synthetic completion results
or executing controller operations. Existing WriteManager rejection and the reader
are unchanged in this step.

Validation adds nine coordinator scenarios to the production-source BCL harness
(26 checks total). These cover exact block coverage, short tails, full sequence
completion, immutable ownership, and all four stop outcomes at all six stages.
They exercise host decision semantics, not native instructions or hardware.
The shared library and WinForms builds passed, as did all 210 null-vehicle write
guard combinations and 31 file-only Python reconciliation/planner regressions.
No adapter, controller, native emulator or interactive UI was run for this step.
