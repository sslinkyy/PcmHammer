# Independent preservation/readback epoch review

2026-11-04 continuation of [bounded cleanup polling](CLEANUP_IDENTITY_POLL_REVIEW.md). This adds an ordered **saved-response** acquisition owner and a file-only exporter. No app startup, adapter, vehicle, upload, execution, reset or flash operation was run. Live operations remain disabled while the spare is in transit.

## The missing distinction

Cleanup identity observation is not a flash read. Complete, correctly correlated flash addresses are also insufficient to establish an atomic snapshot: startup or reader entry may change persistent banks during or before acquisition. Previously the strict writer comparator accepted an explicit saved full-image argument, while original/prepared acquisition and startup-bank diagnosis had their own owners. The new workflow joins these existing components without replacing their rules.

`AL5SavedReadbackEpoch` is created only for one candidate with completed saved finalization/cleanup and explicit prepared banks. It freezes that candidate's original-image, prepared-bank and constructed expected-image hashes. It then owns three separate campaigns in order:

1. All 16,384 bank bytes at `0x4000..0x7FFF`.
2. All 1,048,576 flash bytes, including those same banks and the locations excluded by stock Mode $23.
3. All 16,384 bank bytes again.

These reuse the existing `AL5ReadOnlyRangeCampaign`, `AL5ReadOnlyFlashCampaign` and nonce/sequence/full-24-bit-address/count/CRC correlation. The campaigns require three distinct eight-byte nonces. A complete review contains 33,792 matched replies at the existing 32-byte maximum, representing one unique 1 MiB image plus two bank observations. It does not silently upgrade a stock low-16 echo to this stronger protocol or fill unread bytes.

The assessment retains each phase's coverage, nonce identity, hashes, bank-difference counts, expected-image binding and comparison outcome. Incomplete values stay unknown. A declared intervening reset/startup stops an open acquisition instead of requalifying it. Partial/late replies cannot reopen it. Complete image bytes can remain available for diagnosis even if the following bank campaign stops; they cannot pass the epoch comparison gate.

## Agreement, prediction and preservation remain separate

The bank comparison checks before-to-image, image-to-after and before-to-after observations. Agreement of only the outer observations cannot hide different banks inside the full image. Disagreement prevents the new route from invoking strict comparison, while retaining the full observed image and all complete samples as diagnostic evidence.

Agreement of all three views is still only agreement of sampled bytes. An abstract host-side counterexample changes a bank after its bytes have been read, then restores it before the last sample. All recorded data agrees, but the observation cannot prove atomicity. This is an observation-limit test, not a demonstrated native AL5 erase/journal cycle. `SnapshotCoherenceVerified` remains false even for an exact saved-image match.

When observations agree, the new owner invokes the **unchanged** `AL5CalibrationWriteCandidate.VerifySavedFullReadback`. It never adopts post-startup observations as expected banks. Another candidate with identical hashes cannot consume the bound epoch, and a stopped candidate cannot be reopened by a completed acquisition.

The existing [ordered startup-bank prediction](STARTUP_BANK_VERIFICATION.md) is reused through `DiagnoseSavedStartupBanks`. All three retained native cases can have stable bank observations and match their exact startup prediction, yet still fail strict preservation because their banks differ from the recorded prepared epoch. This diagnostic does not clear the stop or waive any address. Boot, compensation, collateral, completion-marker and OS corruption also remain strict failures when the bank observations agree.

`AfterCleanupStartupUnobserved` and `AfterDeclaredStartup` are caller labels for saved evidence. Neither establishes physical startup history. Snapshot coherence, reader-entry effects, physical readback/reset/preservation, global nonce uniqueness, recovery/readiness and all live flags remain unproven or disabled. The owner is a serial file/model consumer, not a live transport binding.

## File-only command

The saved backup tool now supports:

```powershell
dotnet SAVED_BACKUP_TOOL.dll --readback-epoch ORIGINAL-full.bin PREPARED-banks.bin LOADER.bin SAVED-lifecycle.txt BANKS-before.txt FULL-image.txt BANKS-after.txt BEFORE-nonce IMAGE-nonce AFTER-nonce declared-startup evidence-id NEW-directory
```

Use `startup-unobserved` instead of `declared-startup` when startup is not declared. The original and prepared files must be exactly 1 MiB and 16 KiB; the loader must be the pinned 1,590-byte calibration loader. The supported profile and checksum are checked. No short-file padding, byte-order guessing or proprietary loader bytes are generated.

The saved `T ...` / `R ...` lifecycle is replayed as evidence only. It must reach the candidate's cleanup boundary and record the prepared banks at its before-erase slot. No frame is sent and no fresh security is inferred. Each following transcript must consume exactly its own complete correlation campaign; missing stages, swapped stages and reused nonces are rejected. The existing transcript consumer and exact-sized file reader are reused. Validation finishes before output creation, and existing output is retained.

Outputs are `readback.observed.saved.bin`, `banks.before.saved.bin`, `banks.after.saved.bin` and `epoch.json`, with selected/resolved input paths and SHA256. **Exit zero means a diagnostic report was exported**, not that preservation passed. Check `outcome`: `unstable_saved_observations`, `strict_saved_comparison_failed` or `strict_saved_comparison_matched`. Even the last outcome retains false physical/coherence flags. Firmware outputs remain private.

The library's saved-lifecycle factory performs the internal preparation binding; the exporter was not granted friend access to internal writer/Vehicle controls. The command currently rehearses unchanged calibration from the supplied original, matching the first-write qualification objective.

## Evidence and checks reused

No native finalizer, watchdog, startup or full-reader emulation was rerun. The existing journal loader now supplies both the earlier diagnosis tests and new epoch tests, preserving the same source/reference and exact predicted-bank checks.

The new Windows candidate and pinned exporter/harness pass:

- 20 focused epoch cases: full/partial coverage, distinct ownership and nonces, cross-stage stale reply, wrong bank, malformed frame, stopped parent, intervening startup, changing samples, abstract hidden transition, protected-region corruption and all three saved native journal epochs.
- 12 actual compiled-exporter cases: matched comparison, unstable samples, observed-bank self-baseline rejection, compensation corruption, incomplete coverage/cleanup, phase/nonce errors, exact input sizes and output retention.
- The existing 67 execution/candidate and 24 cleanup regressions, plus 210 null-vehicle write-gate combinations.

These are software/model checks, not physical test counts. The application was built but not started. Known build warnings remain unchanged. PcmLibrary.dll in `LocalOnly/tcmhammer_readback_epoch_preflight_v1` and both pinned consumers has SHA256:

`4048e5a74e0b99d952434ee3eb7cbe01f3d51ff59771876fcfd33c20390d9084`

The [metadata-only review](../AL5/INDEPENDENT_READBACK_EPOCH.json) retains the focused cases and explicit uncertainty flags without proprietary flash payloads.

Receipts, exporter fixtures and intermediate build records are retained under `LocalOnly/al5_readback_epoch_v1`. The new disabled arrival packet is `LocalOnly/AL5_READBACK_EPOCH_BENCH_PACKAGE_V1`. Earlier packets remain historical; their producing application inputs no longer equal the current source.

## Remaining physical gate

This closes the **software evidence workflow**, not the acquisition mechanism. There is still no measured reset/readback window or qualified independent full acquisition on the spare.

For the correlated-reader route, prove the actual handoff/address mapping and which banks change on entry. A new programming-style reader entry can contaminate the epoch before the first sample. Repeating samples afterward does not explain that change; `ReaderEntryEffectsVerified` remains false. Do not call a reader upload non-mutating merely because its read handler has no erase operation.

The external chip-acquisition route remains an alternative; it is not required to finish this experimental reader first. Preserve the actual post-write/power history and label those dumps as readback, not as an original pre-entry backup. The documented Intel/T48 success still does not qualify the spare AL5's actual chip, byte representation or restoration.

Once the spare arrives, the useful new evidence is its independent original, actual prepared-bank epoch, exact reader-entry/reset/startup history, complete independent readback and an applicable restoration demonstration. A post-startup prediction match or agreeing samples cannot replace those observations. Until then, retain the completed checksum, loader, polling and bank-trace work; no fixed sleep or broader bank whitelist is justified.
