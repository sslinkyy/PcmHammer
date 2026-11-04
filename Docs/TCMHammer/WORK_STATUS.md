# AL5 continuation and work audit — 2026-11-04

Start here before opening another AL5 investigation. This is the current continuation index; dated checkpoints and captured evidence remain historical records. The objective is one unchanged-calibration write on the spare, independent preservation verification and reboot, followed by custom-calibration qualification. Live security, prototype upload/execution and writing remain disabled. This audit accessed no hardware and repeated no native emulation campaign.

## What the review found

The project has substantial retained implementation and successful **vendor** programming evidence. It is no longer at the stage of discovering whether an AL5 loader or checksum exists. It still has no physically qualified PcmHammer writer or demonstrated AL5 restoration. Repeating protocol discovery does not close those physical gates.

Three sources of avoidable repetition were found:

1. The original `C:\Car Tuning\To tune\AL5 Transmission Work\CODEX_AL5_PCMHAMMER_TUNERPRO_HANDOFF.md` is a 1,395-line historical handoff. It still says checksum synthesis is unresolved, infers algorithm 50 from one security pair, points to XDF v0.3 and has instructions to resume those investigations. Later evidence supersedes each claim. Preserve the original; do not execute its old continuation checklist.
2. Newer status documents accumulated additions without replacing older conclusions. In particular, an original backup need not be acquired only after ordinary startup, and the finalizer does not establish a measured reset deadline. Those current checkpoint statements have been corrected. Read the topic owners below instead of restarting each dated plan.
3. The package verifier previously treated a changed document or Python test tool as grounds for invalidating the application source snapshot. It now offers a clearly scoped application-input check, while complete verification stays strict and every scope still verifies all sealed package bytes. Documentation changes do not require rebuilding an unchanged application.

The working tree and published writer branch also differ. At review start, the local checkout was `imob/2.0-al5-readonly-probe` at `9b296da0aaefbc974ab1419db9ebbf51d57269f2`, with many writer files present as modified/untracked files. The published writer work was on `codex/al5-sps2-preservation-20261031` at `c289ac2ec4dc051b7ee53e534bd5a8a358b20ce3`. That branch did not contain the newer XDF v0.13/v0.14 commits; the remote read-only branch still pointed to `d335b6e...`. A bare checkout of either branch therefore did not reproduce all local work. Do not reset, clean, checkout over, or stage the whole working tree. The committed XDF history is now also preserved remotely at `codex/al5-xdf-v014-preservation-20261104` (`9b296da...`), without moving the checkout or the original branches. Preserve writer and XDF histories explicitly; do not interpret a clean older branch as the latest project state. Local uncommitted TCC follow-up remains untouched.

## Completed work to reuse

Each topic has a source owner, a result and a reason to reopen it. “Implemented” or “modeled” does not mean physically qualified.

### 1. Native calibration checksum

[BIN-to-SPS mapping](../AL5/BIN_TO_SPS_MAPPING.md) and [calibration candidate](CALIBRATION_WRITE_CANDIDATE.md) own the current synthesis and validation. Calibration is 57,304 bytes at `0x8000..0x15FD7`; the four-byte tail `0x15FD4..0x15FD7` contains the native CRC and BE16 compensation. This is implemented, not merely a forced word sum. Reopen for a different verified profile or an actual failing differential, not because an October handoff says it is unknown.

### 2. Existing programming captures and distinct loaders

[Successful EFILive sessions](../AL5/CAPTURED_WRITE_SESSIONS_20261030.md) establish loader/erase/program/finalize exchanges and checksum-error/retry observations. The selected first candidate uses the pinned 1,590-byte EFILive-derived loader, VPW 1x and 195 programming requests, including 192 calibration blocks. Loader SHA256: `b545d9b2d078662466ab32d9cdeb5b3c38c840135e8aeca09f33760ec66780fa`.

[SPS2 capture](../AL5/SPS2_AL5_WRITE_CAPTURE_20261031.md) independently establishes successful vendor OS+calibration programming: a different 3,858-byte loader at `0xFF9006`, 679,828 OS bytes at `0x20000..0xC5F93`, and 57,304 calibration bytes. Its 181 transfers, pending replies and tail replacement are a separate profile. The post-SPS calibration readback matches the expanded SPS calibration, SHA256 `140b70ea90cb57c20aaab2d9641d2b7caaa6bf312c89bd9369b27b8bce5fcbe6`.

Do not mix these loaders, replay captured security, call the SPS write loader a read-only kernel, or start another search for a missing AL5 kernel. Reopen only a specified unsupported exchange or profile discrepancy. Successful vendor writes do not establish PcmHammer write/recovery qualification.

### 3. Writer implementation and retry ownership

[Candidate](CALIBRATION_WRITE_CANDIDATE.md), [dispatcher checkpoint](WRITER_DISPATCH_CHECKPOINT_20261102.md), `AL5WriteExecutionBinding.cs` and `AL5OfflineWriteDispatcher.cs` own setup, entry, erase, blocks, finalization, cleanup and immutable stage boundaries. Production Vehicle/GT integration is exercised through scripted offline boundaries. Adapter send acceptance is separate from a controller acknowledgement. Checksum retry requires explicit review; ambiguous send completion cannot trigger an automatic destructive repeat. Late completion cannot restart a stopped owner.

The public unchanged-calibration entry remains `LiveDisabled`. An offline candidate or internal binding is not an enabled live writer. Reopen for an observed defect, changed runtime source or the separately reviewed spare-bench binding, not to reconstruct the same packet sequence.

### 4. Fresh security

[Security and backup](SECURITY_AND_BACKUP_PATH.md) and `AL5SavedSecurityExchange.cs` own profile-bound fresh seed/status validation and the selector-zero fixed boot-word interpretation at `0x3FD8/0x3FDA`. One captured pair does not establish generic algorithm-50 support. Exact response lengths, owned fresh exchange, rejection/timeout and unknown-seed failure remain enforced. Actual spare identity and fresh security are unqualified; do not introduce a guessed key generator or automatic retries to bypass that gate.

### 5. Stock reader coverage and stale responses

[Remaining flash](../AL5/REMAINING_FLASH_READ_20261031.md), [reply freshness](RESIDENT_REPLY_FRESHNESS.md) and [startup scheduling](RESIDENT_STARTUP_SCHEDULING.md) own these results. The working stock Mode $23 calibration reader is retained. A full independent original cannot be assembled by pretending its six excluded bytes were read: four boot security bytes and two OS bytes remain excluded. A low-16-bit address echo does not prove the full address bank or freshness.

Local queue clear, a new host owner and fixed waits already have counterexamples. Native clear/requeue and scheduler effects are traced. Reopen only on new controller-side correlation or physical transport evidence; do not repeat queue-clear/sleep variations as a full-backup solution.

### 6. Original and prepared backup routes

[External original and reset verification](EXTERNAL_ORIGINAL_AND_RESET_VERIFICATION.md) and `AL5SavedBackupPath.cs` implement two saved acquisition routes: explicit external original import, and correlated read-only acquisition. Original and prepared images have distinct provenance and epochs. Two identical full 1 MiB raw dumps plus explicit CPU-byte/swap16 representation are required by the external importer; raw and canonical data stay separate. A full reader also needs coherent snapshot acquisition, not just complete addresses.

Choose **one physically qualified original acquisition route**. Do not require both independent approaches to finish sequentially. A pre-first-power external original is a different valid epoch from an original acquired after resident startup; neither becomes a prepared-bank image by renaming it. Historical/reconstructed bytes are not the spare's backup. Actual prepared banks before erase are still required.

### 7. Experimental full-flash reader

[Full-flash reader](FULL_FLASH_READER.md) owns the compiled read-only implementation and modeled full coverage. Real handoff, RAM ownership, VPW FIFO/interrupt/status semantics, watchdog and safe exit remain unqualified. Emulation assumptions are explicit, not proof of hardware behavior. Qualify this only if it is the chosen acquisition route or needed for the comparison epoch; an external route can avoid its security/bootstrap dependency.

### 8. Erase geometry and preservation

[Sector policy](CALIBRATION_SECTOR_POLICY.md) owns the candidate CPU-byte mapping and host erase allowlist at `0x8000/0x10000`. Preserve the full 98,304-byte erase span through `0x1FFFF`: calibration plus 40,998 collateral bytes and the two-byte completion marker. The often-cited “41,000 bytes” includes that marker. Host guards do not physically protect flash sectors or prove mapping on the spare.

### 9. Finalizer, inherited watchdog and reset

The [cleanup timing continuation](FINALIZATION_READINESS_TIMING.md) retains three real saved tail intervals and exposes a cleanup-repeat normalization in the earlier executor success fixtures. Three focused tests with the unchanged library now preserve cleanup order and stop at the first unanswered identity query. A bounded cleanup-poll owner is still needed; neither observed identity traffic nor a fixed wait qualifies independent readback.

[Finalizer timing](FINALIZER_WATCHDOG_TIMING.md) and [watchdog inheritance](WATCHDOG_INHERITANCE_AND_RESET_CHECKS.md) own the latest native traces. `D0C2` is stored in retained RAM at effective `0xFFFF8000/0xFF8000`, not a reset register. Two delay loops each service the watchdog 20,479 times, then the loader parks without further service. There is no RESET opcode on that tail. Sender timeout instead takes a software jump back to loader entry before reaching the marker/park path.

The `0x84` inherited configuration survives under a conditional family/write-once peripheral interpretation. Actual MCU identity, effective clock, watchdog deadline, retained RAM and physical reset remain unproven. Do not convert instruction counts to milliseconds or repeat a fixed-delay readback guess. New physical evidence, not another identical peripheral stub, is needed to close this boundary.

### 10. Post-reset comparison and journal changes

[Startup bank verification](STARTUP_BANK_VERIFICATION.md) and the watchdog continuation own ordered historical/prepared/second-startup diagnostics. Eight changed bank bytes in one startup and six in another are distinct modeled epochs, not a global whitelist. Full 16 KiB bank comparison remains strict.

The examined application CRC checks 57,302 calibration bytes, excluding the final compensation word. A changed compensation word can pass those application checks but fail the writer's strict full comparison. Application boot success alone cannot prove preservation. A physically usable independent comparison epoch remains a first-write gate.

### 11. T48 and recovery

[Physical hardware](../AL5/PHYSICAL_HARDWARE_20261010.md) and the external-original continuation already document T48, Xgpro 13.16, firmware 00.01.39 and ADP_S44_EX-1. A loose Intel TB28F400B5B 44-pin chip was programmed/verified with an independent 512 KiB readback. Do not ask the user to identify this equipment again.

That Intel result does not qualify the spare AL5's chip, byte order, rework or restore operation. [A12 modeling](../AL5/A12_RECOVERY_MODEL.md), physical pin 38 and reset-status hypotheses are retained research, not demonstrated recovery. An intact bottom boot sector does not guarantee SPS recovery. Reopen recovery against the actual spare/chip or new physical evidence, not the generic P59 analogy.

### 12. Passive capture, AutoCal, PCCS and DOC

[ACK investigation](../AL5/ACK_GAP_INVESTIGATION_20261030.md) and [USB comparison](../AL5/USB_CAPTURE_COMPARISON.md) retain the short-response gap. In the E54 4x control, successful USB bulk-IN data and serial capture agreed; missing/invalid short responses were not repaired by retaining CRC-invalid frames. This localizes the observed gap upstream of the COM logger; it does not prove lossless wire capture or zero electrical interference. Repeating that same setup is not an AL5 first-write prerequisite.

[AutoCal transport](../AL5/AUTOCAL_TRANSPORT.md), PCCS and DOC research remain useful references. AutoCal direct model queries/read-delivery progress do not establish an enabled writer; guarded CRC/read qualification remains separate. PCCS J1850 programming was not established. Neither a linked FlashScan, another AutoCal backend nor a PCCS interface purchase is required to finish the selected GT/VPW 1x candidate. Reopen these only for a specific missing capability, not broad tool availability.

### 13. XDF and tuning work

[TunerPro index](../AL5/TunerPro/README.md) supersedes v0.3 instructions: v0.12 covers all 127 native definitions/2,517 numeric cells; v0.14 retains those and has 310 items. The old unexplained `0x10A24` difference has later D5197 evidence. The two v0.14 alternate RPM constants have offline audit evidence but still need their own GUI validation. Alternate RPM latch/selector evidence does not establish forced hydraulic lockup.

Keep XDF GUI follow-up and future shift/TCC tuning separate from the unchanged-calibration writer. Do not restart mapping or apply old proposed pressure/volume edits for a first write.

## Remaining work, in order

1. **Actual spare and bench:** record identity/profile, actual chip markings and verified AL5 wiring. The packet has no verified bench pinout. Do not reuse an E54 harness or guessed pins. Spare arrival alone does not make the disabled candidate writable.
2. **Independent original and restoration:** select the external or correlated route, obtain a coherent complete original, and demonstrate applicable AL5 restoration before erase. The T48 workflow is known; actual AL5 fitment/acquisition/recovery is not.
3. **Bounded access qualification:** establish fresh security and preparation effects on the spare, transport/handoff/RAM/watchdog behavior and independently acquired prepared banks. Capture each boundary; unknown or ambiguous completion stops. Implement the separately reviewed live bench factory/UI binding only for qualified stages.
4. **Resolve finalization/readback timing:** implement the separately scoped cleanup identity-poll owner identified in the timing continuation, then choose and qualify the independent comparison epoch. Preserve marker/collateral and diagnose startup journals exactly; do not relax whole-bank comparison because a model predicts some changes. There is no measured reset/readback window yet.
5. **First write and custom path:** run the unchanged-calibration candidate, independently compare the full required regions and verify reboot/identity. Establish reproducibility before a minimal custom calibration. Deliberate interrupted-write experiments follow demonstrated restoration capability.

The installed truck is not the experimental qualification target. No fresh research is required simply because the spare is still in transit; advance only a named unresolved gate with new evidence.

## Reuse and verification procedure

The latest pre-audit frozen packet is `LocalOnly/AL5_INHERITED_WATCHDOG_BENCH_PACKAGE_V1` (1,103 sealed files). Its application is from `LocalOnly/tcmhammer_watchdog_tail_preflight_v1`; PcmLibrary.dll SHA256 is `027a0e9bd9c403ad1d93108f90121d34b3f119025591b89f7169caf5e06743df`. The saved application-reuse receipt compared 491 producing inputs. These are retained artifacts, not a newly built application.

Use file-only checks, from the PcmHammer checkout:

```powershell
python Tools/AL5/freeze_bench_candidate.py verify --package LocalOnly/AL5_INHERITED_WATCHDOG_BENCH_PACKAGE_V1
python Tools/AL5/freeze_bench_candidate.py verify --package LocalOnly/AL5_INHERITED_WATCHDOG_BENCH_PACKAGE_V1 --repo . --application-only
```

The first verifies the sealed inventory. The second also checks application inputs and explicitly reports documentation/tool/kernel drift separately. `verified` in application scope does **not** qualify changed tools or kernels, prove dependency completeness, rebuild software, or authorize hardware. The default `--repo .` complete scope still fails on any source drift. Inspect changed producers and run affected checks only; do not reseal/rebuild every runtime because a status document changed. All scopes fail for modified, missing or extra package files.

For each continuation, record: question, newest evidence owner, changed producer/input, smallest closing check, observed result and unresolved physical boundary. If those inputs are unchanged and the prior receipt answers the question, reuse it. Synthetic assertion counts are not counts of physical test cases.

## Audit scope and retained history

Reviewed governing plans, source owners, preservation commits, original handoff, current XDF state and saved evidence families spanning EFILive/PCCS/DOC, adapter tests, vendor captures, backup, writer, reader, finalizer and recovery. This was not a byte-by-byte replay of every raw trace or a fresh hardware qualification. Dated artifacts remain evidence of what was known then; only a specific newer conflicting observation supersedes them. Raw captures, kernels, binaries and acquisition provenance remain in the private archive, not public Git source.

### File-only checks performed for this audit

The 1,103-file sealed packet passed full byte-integrity verification. Application-scope comparison passed with zero application/kernel input drift; complete source comparison correctly reported the changed audit documents and package tools. All 830 prior private-manifest entries matched byte counts and SHA256. All local links in this status document resolved. Eleven package-verifier tests passed, including changed application inputs, tool/kernel/documentation drift separation, corruption, missing/extra files and authority/path rejection. No application build, native trace replay or physical test was run. Detailed receipts are retained under `LocalOnly/al5_work_audit_20261104` and in the private audit archive.
