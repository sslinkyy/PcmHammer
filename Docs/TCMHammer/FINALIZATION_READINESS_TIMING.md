# Finalization response, cleanup polling and readback epochs

Follow-up: [bounded cleanup identity-poll review](CLEANUP_IDENTITY_POLL_REVIEW.md) now implements the offline owner described below, with explicit review/attempt/window limits. The earlier observations and default-stop regressions remain evidence; the physical readback epoch is still unqualified.

2026-11-04 continuation of [current work status](WORK_STATUS.md). This is saved-capture and offline host evidence. The spare remains in transit. No live security, upload, execution, programming, reset or adapter access is enabled.

## What the saved tails establish

`Tools/AL5/analyze_finalization_timing.py` reuses the existing HTX container decoder and complete-wrapper CRC validator. It preserves the source digest, record ordinals, decoded offsets, original float timestamp bytes and implementation digests. It analyzes one finalization request per selected session, rejects ambiguous final success replies or backwards relevant timestamps, and retains missing observations as unknown. It emits no send plan. Existing output is never overwritten.

Three successful EFILive AL5 calibration captures were examined, using the already retained source hashes:

- Session 02: final reply to first identity query **11 ms**; next query **1,147 ms** later; first observed identity reply **1,177 ms** after the final reply and **19 ms** after the second query.
- Session 04: first query **10 ms**; spacing **1,136 ms**; identity reply **1,164 ms** after the final reply and **18 ms** after the second query.
- Session 05: first query **9 ms**; spacing **1,150 ms**; identity reply **1,177 ms** after the final reply and **18 ms** after the second query.

Final request is `6C 18 F0 36 FF`; matching final success reply is `6C F0 18 76 00 86`. The subsequent queries are `6C 18 F0 3C 55`; observed identity response is `6C F0 18 7C 55 0A 00 12`. All three tails have two queries before that response and zero observed Mode $23 requests/Mode $63 responses after final success. These short protocol identifiers are public source evidence; calibration and loader payloads remain private.

The trace does not show an intervening identity response to the first query. Because these queries have no transaction ID, the later response cannot be causally assigned to the second query solely by order. Nor does missing capture evidence prove the absence of a wire response. These are host/device wrapper timestamps; they are not measurements of final-bit delivery, last watchdog service, hardware reset, application readiness or a coherent flash-read window. The three intervals must not become a fixed 1.2-second sleep, a polling deadline or a physical watchdog specification.

The [saved timing metadata](../AL5/FINALIZATION_READINESS_TIMING.json) retains all three source identities and observations without proprietary payloads.

## Previously hidden executor-test limitation

The execution harness's `Peer` removes identical consecutive requests without an intervening saved reply, as well as selected programming broadcasts. This was an explicit normalization for the earlier programming fixtures, but also removed the second cleanup identity query. It made a response recorded after that query available to the executor after its first query. The existing normalized success cases therefore do not qualify cleanup polling or reproduce the chronological cleanup tail.

The peer now has a targeted `preserveCleanupRepeats` mode. It preserves repeats only in the finalization/cleanup epoch, records how many were retained, and leaves earlier programming normalization explicitly reported. The new `--cleanup-timing-only` harness mode runs only this new regression against the three retained templates. It does not replay the earlier native campaigns or all 67 established host cases.

Results with the **unchanged sealed PcmLibrary.dll**, SHA256 `027a0e9bd9c403ad1d93108f90121d34b3f119025591b89f7169caf5e06743df`:

- All 192 modeled data blocks and the final success reply are processed.
- The first cleanup query has no reply in its chronological saved slot. A completed empty scripted receive causes the current executor's terminal `Timeout` stop.
- Exactly one cleanup query and one finalization request are submitted. No implicit second query, destructive repeat or resume occurs.
- Finalization evidence remains true; cleanup, reset and readback-window qualification remain false. Full readback comparison is rejected after the stop.
- Separately, the candidate's saved-frame grammar consumes both recorded cleanup queries and reaches its saved-verification boundary. Thus the missing behavior is bounded polling in the executor, not discovery of a new message format.

This is a synthetic completed-empty receive, not an emulation of 1.17 seconds of physical bus behavior. Existing pending-I/O/late-completion tests remain the owner of outstanding-task safety. These three cases do not prove physical silence, physical retry safety or restoration.

## Required implementation and qualification boundary

The executor still needs a separately reviewed cleanup identity-poll owner before it can reproduce this tail without normalization. Such an owner must:

1. Apply only to the exact non-destructive cleanup identity query after an owned final success reply. It must never repeat finalization, erase, data, a key or arbitrary control messages.
2. Retain ownership of outstanding receive/send tasks; a caller timeout must not mean the underlying operation settled. No overlapping receive, queue reset or terminal-session restart is allowed.
3. Use explicit caller-selected attempt/total budgets and cancellation. Historical timestamps are observations, not defaults that qualify physical deadlines. Delayed/stale identity responses remain causally ambiguous.
4. Keep “identity observed,” “cleanup complete,” “physical reset proven” and “independent flash comparison acquired” separate. A matching identity response cannot unlock a physical readback-window flag.

Even with polling implemented, independent readback still needs a qualified acquisition epoch. Reuse the [finalizer watchdog trace](FINALIZER_WATCHDOG_TIMING.md), [inherited configuration trace](WATCHDOG_INHERITANCE_AND_RESET_CHECKS.md) and [startup bank diagnostics](STARTUP_BANK_VERIFICATION.md): the marker/park path is not a RESET instruction, application CRC excludes the compensation word, and ordinary startup can change persistent banks. Exact prepared/original provenance and strict comparison remain required. No timing inference excuses a bank difference.

## Validation and reuse

Nine Python tests exercise actual container/CRC parsing with synthetic timestamps: retained repeats, absent success/identity, ambiguous ownership, backwards timestamps, other-module/prior replies, CRC corruption, hash mismatch and output retention. Three additional C# cases exercise the current production library through the script-only executor, preserving cleanup order. Only the test harness was rebuilt, with `AL5PinnedLibraryPath` pointing to the sealed library; no production app, kernel or native model was rebuilt or rerun.

The first test-harness build resolved a different existing library despite disabled project-reference builds. That output was rejected by SHA256 before running tests. An explicit pinned-reference build option now removes that ambiguity. A first new test also counted setup identity queries as cleanup queries; the counter was corrected to start after finalization. The failed attempt remains in private receipts; final three-session checks pass with the corrected epoch ownership.

Reproduce the focused checks only when these producers or selected traces change:

```powershell
python Tools/AL5/test_finalization_timing.py
python Tools/AL5/analyze_finalization_timing.py --trace SAVED_TRACE --expected-sha256 EXPECTED_SOURCE_SHA256 --output NEW_REPORT.json
dotnet build Tools/AL5/ExecutionBindingTest/ExecutionBindingTest.csproj --no-restore -p:AL5PinnedLibraryPath=ABSOLUTE_SEALED_PcmLibrary.dll
dotnet LocalOnly/ExecutionBindingTest/bin/AL5ExecutionBindingTest.dll --receipt NEW_RECEIPT.json --cleanup-timing-only PINNED_LOADER FULL_REFERENCE SAVED_TEMPLATE CALIBRATION
```

The harness is linked against the caller-selected library; check its receipt's library SHA256 before reusing its result. Detailed trace paths, commands, intermediate failures and final receipts are retained in `LocalOnly/al5_cleanup_timing_v1` and the private preservation archive. Public live APIs remain unconditionally disabled.
