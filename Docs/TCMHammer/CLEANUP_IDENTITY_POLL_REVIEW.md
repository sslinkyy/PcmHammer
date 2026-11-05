# Bounded cleanup identity-poll review

2026-11-04 continuation of [saved finalization timing](FINALIZATION_READINESS_TIMING.md). The chronological cleanup scheduling gap is now implemented in the **offline** dispatcher/executor. The public writer remains unconditionally `LiveDisabled`; no adapter, vehicle, upload, execution, flash or reset was accessed. The spare remains in transit.

## Narrow opt-in behavior

`AL5OfflineCleanupPollPolicy` requires an explicit maximum number of accepted query attempts and an explicit total model window. There is no default policy, polling interval or delay derived from the three vendor captures. The original dispatcher constructor remains available; its default behavior still stops on an empty receive. No UI control or live factory exposes this new review path.

With the policy explicitly selected for a saved session:

1. The owned finalization success reply must already have been accepted. Only the cleanup query `6C 18 F0 3C 55` qualifies. Setup identity queries, security, erase, data, finalization and other cleanup controls cannot use this exception.
2. The execution owner must observe its receive task **completed successfully with no message**. Only then may the dispatcher retire that query's reply slot, retain its immutable owner record and enter `CleanupIdentityPollReview`. A timed-out outstanding task, cancellation, receive fault or uncertain send remains terminal; none is classified as an empty reply.
3. Ordinary resume sends nothing at this review boundary. Internal, explicitly invoked `ReviewCleanupIdentityPollAsync` reserves exactly the same non-destructive identity query with a new immutable owner. Checksum review cannot consume the slot. There is no automatic retry and no arbitrary request argument.
4. The attempt cap includes the first adapter-accepted cleanup query. The total window begins at that acceptance, includes review pauses and subsequent sends/receives, and stops at observed identity. Existing per-send, per-reply and whole-session budgets also apply. Exact deadline expiry stops before another dispatch; later cleanup controls retain their ordinary budgets. None of these durations is a measured controller deadline.
5. After the saved identity response, the ordinary captured cleanup sequence must still complete. Identity observation alone does not allow full readback comparison. A stop remains terminal even when a pending transport task later completes.

The repeated queries have no transaction identifier. A matching identity response in the new host reply slot may still be delayed from an earlier query; `CleanupIdentityResponsePairingProven` therefore remains false. This does not establish a bank/session freshness fence. `PhysicalResetVerified`, `PostFinalizationReadbackWindowVerified`, `PhysicalDeadlinesQualified`, physical readback/recovery and all live flags remain false even after a successful saved comparison.

## Results and evidence scope

All three chronological captured cleanup tails now reach the saved full-readback boundary after one explicit query review, with exactly two cleanup queries and one finalization request. Full-image equality is then tested separately against the synthetic flash peer. Earlier programming no-reply repeats and selected broadcasts remain explicitly normalized; this is not a claim of unmodified full-session replay or real elapsed bus time.

The focused run passes 24 cases, including the retained default-stop controls for all three captures, three opt-in successes, invalid policy/early review, attempt caps, both total-window boundary sides, cancellation, pending receive/send ownership, late completions, send/receive faults, identity without completed cleanup and exclusion of destructive/later-control repeats. It also verifies that the identity window does not incorrectly cover later cleanup exchanges.

The 67 existing execution/candidate regressions pass against the same new library, reusing the saved native watchdog/post-reset and journal reports. The direct dispatcher suite passes its 25,058 assertions, and the null-vehicle gate rejects all 210 write-type/controller combinations. These are software checks, not physical tests or recovery qualification. No native emulator campaign was rerun.

The disabled Windows candidate was rebuilt because production dispatcher/report inputs changed. Output: `LocalOnly/tcmhammer_cleanup_poll_preflight_v1`; tested PcmLibrary.dll SHA256:

`a96e2564e12a732067fc4c1b3d891f029e737879b6826bd052524b6159e1f98c`

The execution harness uses its explicit pinned-library reference and checks byte identity against that Windows candidate. Builds succeeded; the application build retains the known async-without-await warnings and the existing nullable J2534 warning. Application startup was not run. Receipts are in `LocalOnly/al5_cleanup_poll_v1`; raw captures and proprietary loader/calibration bytes remain in their prior private locations.

## What this closes and what remains

This closes the offline executor's inability to represent the saved unanswered-first-query/repeated-query cleanup tail without normalizing it away. It does not qualify a physical retry interval, prove the loader reset, or supply independently acquired flash bytes.

The next gate is a usable **independent preservation acquisition epoch** around finalization/startup on the spare: full required coverage, exact original/prepared provenance, compensation and completion-marker verification, and strict bank/collateral comparison. Reuse the existing watchdog and journal evidence; do not reopen checksum/loader discovery, substitute an identity reply for a flash read, or whitelist all startup bank changes. The experimental correlated reader and external acquisition/restoration remain separate available routes requiring actual AL5 qualification.
