# Writer-first multipart checkpoint: 2026-11-03

Objective: one unchanged-calibration write to the spare, independent preservation/readback verification and a successful reboot; then custom calibration qualification. The spare's last reported state is in transit. All current live security, upload, execution and write gates remain disabled. This checkpoint is an evidence and work-order record, not programming authorization.

## Part 1: acquisition strategy decision

1. **Offline traced:** background response index two retains tracking for numeric `E0/30` with empty RX, retires for the same input with an accumulated request, and requeues for `E0/00` with nonempty RX.
2. **Offline traced:** native interface clear requeues that background response; running the complete scheduler submits `49 FE 18 06` again. Probe branches fork from the same complete startup snapshot and preserve its bank bytes. Native flash code remains trapped.
3. **Host behavior established:** the real GT parser can queue a native upper-bank alias before an adapter ACK. `ClearMessageQueue` clears that queue and requests a local port discard. A separately scripted upstream delivery after the completed discard still reaches the real parser and new bank owner. This counterexample does not claim a measured physical GT delay.
4. **Existing limitation retained:** the new owner accepts the same-echo alias; it cannot infer full address or freshness from a stock reply. Unrelated background responses remain unrelated, timeout remains terminal and incomplete export remains rejected.
5. **Decision:** develop a correlated, coherently acquired read-only baseline as the primary complete-backup route. Stock Mode $23 remains useful for limited observations but is not a qualified full-backup/session boundary. External flash acquisition is the fallback if safe pre-entry reader handoff cannot be qualified. Stop adding stock queue-clear or fixed-delay heuristics without new evidence.

Part 1's software investigation now has a decision. Physical IRQ/FIFO/status, controller/adapter/USB draining and a safe correlated-reader handoff remain unqualified; the word "complete" above does not close those gates.

## Part 2: security and preservation audit

6. **Audited:** the saved security exchange requires a complete 1 MiB reference, matching boot/OS hashes, valid calibration and selector zero. The supported boot span is `0..0x3FFF`; the supported OS span starts at `0x20000` and is 679,828 bytes. Service number or filename alone does not establish these identities.
7. **Qualification prepared:** retain one owned fresh exchange with exact seed/status lengths, explicit key review and terminal rejection/lockout/timeout. The captured fixed pair is profile evidence, not generic algorithm-50 support. No new key generator, guessed delay or automatic security retry is justified.
8. **Epoch defined:** "original" means independently acquired after ordinary startup and before programming-style entry. Periodic journal activity can continue after communication initialization, so a full acquisition must establish snapshot coherence as well as nonce, sequence and full-address correlation.
9. **Unresolved dependency identified:** stock Mode $23 excludes four boot security bytes and two OS bytes. The current security owner requires the complete reference that the experimental reader is intended to acquire. If that reader requires security/preparation first, reusing the historical image would conceal a bootstrap dependency. Qualify a genuinely non-bank-changing acquisition route or independently acquire the flash externally; do not promote reconstructed bytes to a spare backup.
10. **Existing contract retained:** keep original and prepared images separate. The pre-erase binding requires complete prepared banks from a separate acquisition epoch. Expected readback uses the prepared banks while retaining the original image and its provenance. Later unexplained bank changes fail verification.

Part 2's software requirements are now explicit. Actual spare profile, independent coverage, coherence, fresh authorization and acquisition provenance remain hardware gates.

## Part 3: candidate and sealed arrival packet

11. **Implemented sequence; verification-window gap identified:** the saved calibration writer constructs setup/security boundaries, programming entry, the pinned 1,590-byte loader, erase, 192 data blocks, separate finalization and cleanup. Its 195 programming requests are not a raw USB replay. The captured loader's finalizer enters a shared reset attempt. The current candidate permits full comparison only after cleanup; a subsequent startup can legitimately update banks. The new native-journal regression demonstrates that exact programmed sectors plus those eight bank changes still fail complete preservation. A defined, independently qualified comparison epoch is required before the live candidate can be enabled; do not silently whitelist all bank differences.
12. **Implemented, evidence retained:** the internal production Vehicle/GT binding owns pending sends/replies and terminal stops. Late completion cannot restart a stopped session. Adapter acceptance is not a controller programming acknowledgement.
13. **Implemented, evidence retained:** profile, loader and original hashes bind the unchanged candidate; separate prepared banks are reviewed before erase. An unchanged candidate cannot silently become a custom write.
14. **Targeted continuation completed:** native startup tests and production-host freshness tests cover the four background completion branches, completed-local-flush counterexample, and native journal changes applied through a full saved writer lifecycle. Retain the existing writer/security/fault receipts when their producing runtime sources and built artifacts are unchanged.
15. **Arrival packet:** seal the already built disabled application, offline writer, backup exporter, current source, capture helpers and explicit new/prior receipts. Verify package hashes and source drift. This is a file-only integrity check; do not launch the app to inspect the package.

## Parts 4-6: hardware-dependent work, still pending

16. Verify the spare's actual identity and matching wiring before power.
17. Establish stable bench power, the GT as sole active interface and capture recording.
18. Independently acquire the spare's baseline using the selected qualified route; record all missing coverage.
19. Qualify fresh security, bounded reader access, safe handoff, watchdog handling and exit in separately bounded stages.
20. Demonstrate an applicable restoration route before first erase testing; neither A12 nor a spare alone establishes recovery.
21. Construct the unchanged candidate from that spare's actual baseline.
22. Review erase allowlist, collateral restoration, marker and preparation epoch against the acquired evidence.
23. Implement/enable only the separately reviewed spare-bench binding after its gates pass; the present public API stays disabled.
24. Capture one full unchanged-calibration write; ambiguous completion stops without automatic destructive repetition.
25. Independently compare readback and preservation, then power-cycle and verify identity/operation.
26. Establish reproducibility with a second unchanged write.
27. Qualify a minimal custom calibration change with the correct native checksum and strict region limits.
28. Independently verify the custom write and restore the baseline.
29. Perform separately designed interruption/recovery experiments after restoration capability is demonstrated.
30. Integrate only the qualified profiles and recovery behavior into the TCM Hammer workflow.

The installed truck TCM is not the experimental target. The next required external inputs are the spare's arrival/identity, verified bench connection information, and an applicable independent acquisition/restoration capability. Work on unresolved safe-reader entry can continue offline; no packet or test receipt removes those physical requirements.

## Continuation: previously documented equipment and external original path

Review of the retained October 15 work confirms the T48/ADP_S44_EX-1/Xgpro workflow and a successful separate Intel readback. Re-identifying that equipment is not a remaining task. The [new external-original continuation](EXTERNAL_ORIGINAL_AND_RESET_VERIFICATION.md) imports two matching full-chip saved files with explicit byte representation, feeds the existing prepared-bank/unchanged-writer owner, and retains all physical gates. It also traces the finalizer's retained RAM marker and park path, and implements a terminal offline stop before finalization. Actual AL5 chip acquisition/recovery, loader timeout behavior and an independent verification window remain unqualified while the spare is in transit.

## Continuation: startup bank verification

The [journal restart continuation](STARTUP_BANK_VERIFICATION.md) traces historical, modeled-prepared and second modeled restart epochs. Eight-byte changes move with parent-bank selection; a subsequent startup makes six different changes. Exact ordered bank diagnosis is now available, but every bank byte is still compared and the writer continues to reject unexplained preservation differences. Physical reset/readback timing remains a qualification gate.

## 2026-11-04: finalizer watchdog continuation

The [native watchdog tail](FINALIZER_WATCHDOG_TIMING.md) services through both delays, stores the retained marker and stops servicing in park. Sender-busy exhaustion instead branches to loader entry before marker/park. The saved execution report now separates final reply and cleanup from physical reset/readback timing; all physical/live gates remain false. Actual watchdog configuration and reset/readback epochs still require qualification on the arriving spare.
