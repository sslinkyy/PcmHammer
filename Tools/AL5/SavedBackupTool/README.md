# Saved AL5 backup path

External programmer files now have a separate file-only route. Use `--external-chip first.bin second.bin cpu-bytes|swap16 evidence-id NEW-directory` with two exactly 1 MiB saved files and one explicitly selected representation. Both raw files are retained; the canonical output must pass the existing supported AL5 profile. The tool does not infer physical reads, chip identity, byte-lane mapping or recovery. The prior 512 KiB Intel programmer example is rejected as an AL5 original.

To combine that original with a separately correlated prepared-bank transcript, use `--external-prepared ORIGINAL-directory prepared.txt prepared-nonce-hex evidence-id --entry-boundary-recorded NEW-directory`. It validates original artifacts/hashes and complete prepared coverage. It records an external source rather than inventing an original reader session. All physical and live flags remain false. See [external original and verification timing](../../../Docs/TCMHammer/EXTERNAL_ORIGINAL_AND_RESET_VERIFICATION.md).

For stock resident bank transcripts, use `dotnet run --project Tools/AL5/SavedBackupTool/SavedBackupTool.csproj -- --resident-banks PINNED_SPS_OS frames.jsonl evidence-id NEW-output-directory`. Each JSONL row has `address`, `vpw_request_hex`, and `vpw_reply_hex`. This separate mode requires all 4,096 sequential dwords and exports only `preentry_banks.saved.bin` plus a report. It preserves the low-16 echo/freshness limitation and does not produce or certify a full original image. See [the native pre-entry trace](../../../Docs/TCMHammer/RESIDENT_PREENTRY_BANK_BACKUP.md).

This file-only tool consumes original and prepared acquisition transcripts from the experimental correlated reader protocol. Each line is `T HEX` or `R HEX`, with transport CRC removed. It checks each constructed request, response nonce, sequence, full address, count and payload CRC using the production campaign implementation. Unrelated replies do not consume the pending slot. It requires all 1 MiB of original coverage before recording the entry boundary, then all 16 KiB of prepared banks. Partial data and repeated or out-of-order requests cannot produce an export.

```
dotnet run --project Tools/AL5/SavedBackupTool/SavedBackupTool.csproj -- original.txt prepared.txt 0102030405060708 0807060504030201 saved-evidence-id NEW-output-directory
```

The example nonces are for offline fixtures. Physical session acquisition is not implemented here. Nonces must differ across the two saved acquisition epochs; they do not prove that a physical reader entered safely or that data came from the correct controller.

Output retains the complete original image, its original banks, the separate prepared banks and a report with input paths, transcript hashes, image hashes, coverage counts and preparation delta. Existing output directories are rejected. Invalid or incomplete transcripts produce no output. All physical qualification and live-operation flags remain false. No adapter is constructed or opened.

These are experimental correlated-reader transcripts, not stock Mode $23 traces, whose limited address echo cannot supply the same session correlation. A reconstructed historical fixture can test the software but cannot become a physical backup through export.

After building, run `python Tools/AL5/test_saved_backup_tool.py --tool LocalOnly/SavedBackupTool/bin/SavedBackupTool.dll --output NEW-test-directory` for complete, stale-epoch, partial, wrong-nonce, duplicate-request, unowned-reply and existing-output cases. The test generates a synthetic image and never opens a hardware port.

`--startup-bank-review ORIGINAL-full.bin PREPARED-banks.bin READBACK-full.bin native-journal-report.json case-name evidence-id NEW-directory` diagnoses exact ordered startup-bank predictions against all bank bytes. It exports predicted banks and a report; a match is not preservation or physical verification. See [startup bank verification](../../../Docs/TCMHammer/STARTUP_BANK_VERIFICATION.md).
