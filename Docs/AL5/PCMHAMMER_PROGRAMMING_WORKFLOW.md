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

## Constructed loader reply handling (2026-10-16)

`RecordLoaderModelResult` connects the coordinator to a phase-specific captured
loader reply contract. It accepts a constructed three-byte body, an explicit
modeled sender state, an optional observed stack delta and modeled block coverage.
It does not accept raw VPW frames or prove delivery to a host. Boot handoff and
saved verification retain their separate contracts and reject loader replies.

For the modeled erase stage the expected body is `7600EE`; calibration and
collateral blocks expect `760073`; finalization expects `760086`. Known negative
bodies ending in `77`, `85`, `89`, `F8` or `FF`, malformed bodies and wrong-phase
statuses stop the attempt. Unknown body values are retained rather than promoted
to success. Malformed body sizes and undefined sender enum values are rejected
at the result boundary before any coordinator transition.

A success-looking body advances exactly one modeled operation only when the
sender returned and the observed stack delta is zero. Missing sender, body or
stack facts produce a terminal `UnconfirmedModelResult`. A nonzero delta stops
the attempt even after a positive status: native error paths can retain pending
call frames. A sender timeout with software reentry produces `ReplyLost`, even
if the constructed body is positive and the reentry reset the stack. Neither
condition establishes host receipt or rollback.

Block completion additionally requires the exact pending block's modeled start
address and byte count. This matters because a non-programming delay subtype can
also construct `760073`. Missing coverage stays unknown; wrong address or byte
count stops as a model failure. These facts describe modeled effects only, not
physical writes or independent readback. Generic explicit `RecordModelOutcome`
remains available for sequence-only rehearsal; it is not a native evidence parser.

The observation journal now retains the decision reason, expected body, exact
constructed body value, sender state, stack delta and supplied coverage facts.
No failure, unknown result or later snapshot match automatically retries a block
or resumes the attempt. All physical qualification and live-write gates remain
unchanged.

Run the production-source harness with the saved native evidence:

```powershell
dotnet run --project Tools/AL5/CalibrationInspectionTest.csproj --no-restore -- --loader-model-evidence-root .
```

Validation passed 34 C# checks, including 27 observations from the saved entry,
erase-failure and native-sender reports. Their report hashes, captured-loader
identity and current producer/dependency hashes are checked before use. Older
reports without native sender return facts remain unconfirmed; no sender success
is inferred from constructed status bytes. The source scenario, not the reply
value, selects hypothetical host-stage context for these comparisons.

The shared library and WinForms builds passed, as did 210 null-vehicle write
guard combinations and 31 Python file-only regressions. No native instructions
were rerun in this step; saved evidence was reused. No hardware or interactive
UI was accessed, and the optional native calibration-file corpus was not supplied.

## Pending-operation reconciliation (2026-10-16)

`AssessStoppedSnapshot` now returns an `AL5StoppedOperationAssessment`, joining
the original stop observation to both the full-image facts and an exact comparison
of the pending operation's range. Callers access the former whole-image report
through `ImageAssessment`; the experimental API's previous return type is
superseded. Repository tests use the richer report; no live-writing caller is
introduced.

This distinguishes a block that matches after a lost acknowledgement from an
entire image that passed saved-file verification. A matching block can coexist
with erased or incomplete data elsewhere. Partial clear-only differences and
zero-to-one conflicts are classified independently for that block. The report
retains the stopped operation identity, original outcome and any loader decision,
including sender timeout and constructed status, alongside the saved-image hash.

Expected bytes follow the pending stage:

- Calibration and collateral operations compare only their exact block ranges,
  including the 216-byte and 38-byte tails.
- Conditional erase compares the modeled 98,304-byte range against erased `FF`
  bytes, rather than against the desired programmed image. A zero-to-one
  difference here indicates that saved bytes are not all erased; it is not an
  instruction to retry either erase or word programming.
- Finalization compares the `4AFC` marker word; it cannot establish matching
  calibration or collateral data.
- Independent verification compares the complete desired conditional image.
- Boot/loader entry has no flash range whose contents could prove execution,
  so its range comparison is explicitly absent.

Whole-image and operation comparisons use the same owned snapshot and the same
word-comparison implementation. Reconciliation does not append outcomes, advance
the cursor or reopen the stopped session. `RetryEnabled`,
`CanResumeStoppedSession` and `PhysicalReadbackVerified` remain false, even for a
perfect pending-range match. Physical identity, erase geometry, programming and
recovery remain unqualified.

Validation passed 40 C# checks, including six new reconciliation scenarios and
the existing 27 pinned native-model observations. The shared library and WinForms
builds, 210 null-vehicle write guards and 31 Python file-only regressions passed.
No native instructions, hardware or interactive UI were exercised in this step. The optional
native calibration-file corpus was not supplied.

[Native/C# coordinator integration](NATIVE_COORDINATOR_BRIDGE.md) now drives the shared host sequence with original loader instructions over bounded local test pipes. Six full/failed/interrupted scenarios pass; physical programming, readback and recovery remain unqualified and live writes stay disabled.
