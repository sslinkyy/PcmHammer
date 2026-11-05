# Spare AL5: external acquisition route to the first bench write

The spare's last reported state is **in transit**. No physical acquisition epoch has been observed. This continuation prepares the existing T48/file workflow for the actual spare; no programmer, adapter, vehicle, upload, execution or flash operation is enabled.

## Why this advances the first write

The first bench test needs a complete independent result after programming. The correlated-reader route still needs a qualified handoff and an explanation of reader-entry bank effects. The new **external readback** command compares two saved chip reads after the recorded shutdown against the existing unchanged-calibration candidate. It requires no additional reader-kernel entry and therefore removes that dependency from the post-write comparison.

This does not remove the programming loader, fresh security, actual prepared-bank acquisition, correct bench wiring or AL5 restoration qualification. An external result may still differ legitimately after startup; the existing comparator remains strict and will not ignore or adopt those banks. Choose this route for first qualification if safe chip access and applicable restoration can be established. The correlated reader remains a separate alternative, not a second prerequisite to finish first.

## Arrival sequence and current tooling

1. **Identify before startup.** Keep the arriving module unpowered until its label, connector and actual flash marking are recorded. The installed truck's service number is not proof of the spare's identity. Verify the actual device/socket support and AL5 bench wiring; there is still no validated AL5 pinout in the packet. Do not reuse the E54 harness or Intel programming settings by assumption.
2. **Preserve its starting flash.** Obtain two separate, untouched full-chip read files using the physically appropriate method. Save new filenames; retain the raw files and any programmer logs. The current importer expects exactly 1 MiB and the supported boot/OS/calibration profile. A short or unsupported image stops qualification; it is never filled from the historical reference.
3. **Import with a target label.** Use one explicit case/target ID for this actual spare. New external readback requires that exact ID from the original import. It rejects imported-original/source paths as readback inputs. IDs are operator declarations, not an authenticated hardware identity.
4. **Qualify restoration and the before-erase epoch.** Demonstrate an applicable restoration route before the first PcmHammer erase, and acquire the actual prepared banks separately at the correct interval. Do not copy `original_banks.saved.bin` into the prepared role. The known T48/Intel success is retained equipment evidence, not proof of AL5 restoration. The prepared-bank acquisition mechanism remains a physical gate.
5. **Qualify bounded writer stages, then one unchanged write.** Fresh security, programming entry, transport and loader behavior must pass on the spare before the separately reviewed live bench binding can be enabled. The present public entry remains unconditionally disabled. Keep capture and actual power/reset/startup history through finalization and cleanup.
6. **Capture an external readback.** After the required completed-operation/shutdown sequence and safe access are established for the actual module, save two new chip-read files. Record actual events, including unknown intervals. Do not trigger another reader upload just to feed this comparison route, and do not call a post-write dump an original.
7. **Review the full comparison.** Import the readback pair using the explicit representation and target ID. Verify calibration, compensation, marker, collateral, banks and other protected bytes through the unchanged comparator. Any bank differences remain failures of strict preservation even when an existing native startup prediction can diagnose them. Independently qualify the reason before declaring a successful bench write or proceeding to custom calibration.

No step above authorizes a live operation now. The objective is an unchanged-calibration write on the spare, independent comparison and reboot; custom-BIN qualification follows that result.

Record whether the flash was isolated from the controller during programmer access. Saved files and a shutdown declaration cannot establish that the CPU was unable to run during the reads.

## Prepared intake directory

`LocalOnly/AL5_SPARE_INTAKE_V1` now contains empty `incoming/identity`, `incoming/original`, `incoming/prepared`, `incoming/lifecycle`, `incoming/readback` and `notes` directories. Its README and clearly marked history template record that no physical events or BINs exist yet. Actual `notes/operator_history.txt` must be filled from observations. Import/review output directories are intentionally not precreated because the tools reject existing outputs.

The documented T48, ADP_S44_EX-1 and Intel read/program evidence are already retained; do not repeat equipment-identification questions or prior native campaigns. Actual spare/chip fitment and observations are the missing inputs.

## File-only commands

Use the current packet's `offline_backup/SavedBackupTool.dll`. Replace uppercase placeholders with actual saved-file paths, the explicit `cpu-bytes` or `swap16` representation, and the chosen target/evidence IDs. These commands read files; they do not control Xgpro or communicate with the TCM.

```powershell
dotnet SAVED_BACKUP_TOOL.dll --external-chip ORIGINAL-read1.bin ORIGINAL-read2.bin REPRESENTATION ORIGINAL-EVIDENCE-ID NEW-original-import --target-id TARGET-ID

dotnet SAVED_BACKUP_TOOL.dll --external-readback ORIGINAL-import-directory ACTUAL-prepared-banks.bin PINNED-loader.bin SAVED-unchanged-lifecycle.txt READBACK-read1.bin READBACK-read2.bin REPRESENTATION shutdown-declared TARGET-ID ACTUAL-operator-history.txt READBACK-EVIDENCE-ID NEW-readback-review

dotnet SAVED_BACKUP_TOOL.dll --capture-external-readback ORIGINAL-import-directory READBACK-read1.bin READBACK-read2.bin REPRESENTATION power-history-unobserved TARGET-ID ACTUAL-operator-history.txt FAILURE-EVIDENCE-ID NEW-capture-directory
```

Use `power-history-unobserved` when shutdown history is not declared; it cannot qualify a physical epoch. A nonempty history file is required and retained as supplied, not interpreted as proof. Original import without `--target-id` remains supported for historical tools, but an untagged original cannot be used by the new spare external-readback command. Reimport its retained original raw pair into a new target-tagged directory if appropriate; never edit provenance to claim a different physical target.

Raw pair equality and explicit adjacent-word conversion have one owner, `AL5SavedExternalFlashPair`, reused by the original importer and readback reviewer. Original import still rejects blank/zero or unsupported firmware. **Readback deliberately retains blank, zero or damaged images** as failed-comparison evidence; it does not reject them merely for failing an original-image profile. No automatic byte-order reinterpretation occurs.

The reviewer reuses the saved lifecycle/prepared-bank owner and strict comparator. Outputs preserve both raw readback files, a separate canonical readback, its banks, the supplied operator history and `readback.json` with selected/resolved paths and hashes. Original files remain untouched. Exit zero means a diagnostic export completed; inspect `strict_saved_comparison_matched` versus `strict_saved_comparison_failed`. Even a byte match keeps physical power state, freshness/independence, target continuity, coherence, preservation, restoration and all live authority unverified. Historical missing source paths do not invalidate intact archived original artifacts.

If a write stopped without complete cleanup, use the capture-only command. It needs no prepared-bank file, loader or successful lifecycle and retains blank/damaged readbacks. It reports `captured_saved_pair_comparison_unavailable`, with `comparison_performed=false` and a null comparison result. It must not be used to claim success, resume a stopped writer, or authorize recovery. Never invent cleanup events to make a failure capture pass the strict review.

## Validation and retained candidate

The new route is exercised through the actual compiled exporter: CPU-byte and swap16 reads, declared/unknown power history, wrong representation, protected-byte and bank differences, retained blank/zero failure data, mismatched/partial/self-reused dumps, original path aliases, wrong/missing target tags, missing history, altered/promoted original metadata, relocated historical source paths and existing-output retention. Existing original-import, prepared-join and correlated-readback commands retain their regression coverage. No native emulator campaign was rerun.

The [metadata-only review](../AL5/SPARE_EXTERNAL_ACQUISITION.json) records the external-readback and capture-only cases, the affected importer/join regressions and the still-open physical gates. These counts describe file/model checks, not actual spare reads or flashing attempts.

The disabled Windows candidate is `LocalOnly/tcmhammer_external_readback_preflight_v1`; its PcmLibrary.dll SHA256 is:

`c2f7030b43fdb59e3f1fcc2d23d4229e94b4f49103ed0f16b7c12d71d76aa408`

The pinned exporter uses those exact library bytes. Receipts and synthetic fixtures are under `LocalOnly/al5_external_readback_v1`. The current disabled arrival packet is `LocalOnly/AL5_SPARE_ACQUISITION_BENCH_PACKAGE_V2`, including the failed-write capture path; prior packets remain historical and all physical/live gates remain closed.

The next real acquisition starts with the arriving spare's identity and two original reads. No software report created during transit is being counted as that evidence.
