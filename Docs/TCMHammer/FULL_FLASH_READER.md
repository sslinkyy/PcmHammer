# Full-flash read-only rehearsal

The offline reader campaign now covers all 1,048,576 bytes, using 32,768 correlated 32-byte requests. No live reader backend, loader upload, execution or flash writer is enabled by this work. Images produced here are fixtures, not newly acquired controller backups.

## Three startup contexts

1. **Legacy native-copy context:** the existing boot ISR/stack state is supplied synthetically; FIFO/sender helpers are callbacks and boot watchdog instructions are skipped. The native copy enters the compiled reader and the complete historical fixture is read in one persistent CPU/RAM session.
2. **Reset-vector context:** saved vectors supply SSP FFFF8FFE and PC 400. Native boot initialization, receiver, sender, Mode 34 handler and Mode 36 byte copy execute. Reset status 20 and retained BFC1 are explicit inputs; synthetic IRQ entries replace actual exception delivery, and RTE is never executed. The reader adopts this exact CPU after native copy, without preloading its code or remapping RAM. No native boot watchdog instructions are skipped in this context.
3. **Atomic application-preparation context:** the source-pinned application preparation and native storage wrappers run first with bounded host-modeled atomic flash effects and stubbed subsystems. The resulting RAM and persistent-bank bytes are explicitly carried into a new reset-model CPU. Reset-to-reader execution then remains on that CPU. This is a conditional join across an injected reset, not a physical application-to-boot qualification.

Each complete campaign must reproduce its supplied fixture byte for byte, read every flash byte exactly once in sequential order, retain nonowned RAM canaries, preserve the flash fixture, validate every payload CRC and reach local software park. A queued request remains unprocessed after park. The park call is an explicitly injected local call frame, not an implemented host wire command or a demonstrated safe hardware exit.

## Handoff and negative cases

The reset-derived native copy supplies all 1,328 compiled code bytes at FF9006 before entry. Its pending return is 33B8, with a 72-byte stack delta. The observed incoming stack is FFFF8FA6 under the declared 24-bit alias model, distinct from the reader's owned FFA700..FFA7FF stack. Boundary-probe tests verify that the abandoned frame bytes remain intact; the reader does not return through them.

Unarmed, bad-checksum and copy-only transfers do not enter the reader. They can still copy the payload into RAM before rejection; copied bytes are not rollback, execution permission or a reusable session. A failed copy attempt is terminal in the retained-context tool. Runtime attachment requires the identical paused CPU and matching code/flash view.

Additional tests cover odd boundary reads, bank transitions, permission-excluded resident-reader locations, final-flash bytes, out-of-range requests and cross-end requests. Invalid requests produce no new response, flash read or TX submission. A previously retained response is never counted as a new reply. Runtime symbol dictionaries are copied so caller mutation cannot redirect subsequent model calls.

## Host ownership and coverage

`AL5ReadOnlyRangeCampaign` owns sequential request progress, pending correlation and retained bytes for a bounded interval. The existing collateral campaign delegates to it, preserving its fixed 41,000-byte API. `AL5ReadOnlyFlashCampaign` applies the same owner to the entire 1 MiB interval. It exports an image only after complete correlated coverage; unknown bytes cannot escape as synthesized zeros or FF.

Synthetic and compiled-fixture tests exercise nonce, full 24-bit address, sequence, count and CRC correlation, including stale replies, wrong-bank echoes, duplicate replies, cancellation and malformed data. Full-image completion is an offline observation; physical readback, address mapping, recovery and readiness remain false.

## Pre-entry and post-entry epochs

Normal application entry can change persistent banks 4000..7FFF before the reader runs. An image read afterward cannot be called the original pre-entry backup. The preparation campaign therefore labels its fixture `atomic_post_preparation`, records pre/post bank digests and RAM provenance, and retains the separate original historical LOW/HIGH identities. The host verifier permits only the modeled bank interval to differ from the original fixture and checks the recorded difference counts and hashes.

The spare's qualification plan must acquire and preserve the obtainable pre-entry bank data through an independently qualified nonprogramming path. A post-entry full image still helps verify calibration-sector collateral, but does not recover overwritten original bank contents. Resident Mode 23 permissions and low-16 response correlation remain separate qualification gates.

## Reproduction and provenance

`emulate_readonly_full_flash.py --low LOW --high HIGH --build-dir BUILD --output-dir NEW_DIR` runs the legacy context. Add `--reset-context` or `--preparation-context` for the stronger joins. All source images and the compiled reader are identity checked. Each output directory is new; failure records and partial frames are retained instead of being reported complete.

Outputs include frames.jsonl, readback.offline.bin, result.json and source snapshots. New campaigns snapshot their dependencies before execution so an analyst's later edits cannot silently change the recorded source identity. The first completed legacy run had its recorded source versions preserved before subsequent edits. These artifacts remain local/private because they contain complete firmware fixture bytes.

`dotnet run --project Tools/AL5/ReadOnlyFlashCampaignTest.csproj -- DIRECTORY LOW HIGH` verifies the producer records through the production host campaign. `test_reset_readonly_chain.py --low LOW --high HIGH --build-dir BUILD` checks positive/negative handoffs, inherited RAM/stack, boundary probes, model epochs and trace-detail equivalence.

Summary trace mode retains watchdog ordering, TX/RAM counters, exact sequential read coverage and completed frames without collecting millions of redundant event objects. Detailed mode remains the default for existing short tests. Elapsed emulator timings are not physical VPW throughput or watchdog timing evidence.

Hardware remains unresolved: actual MCU/FIFO identity, chip/address routing, clock/VPW behavior, real IRQ/exception frames, SRAM ownership, power/reset retention, physical exit and recovery. No hardware operation was performed.
