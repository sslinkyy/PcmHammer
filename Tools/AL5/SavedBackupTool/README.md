# Saved AL5 backup path

This file-only tool consumes original and prepared acquisition transcripts from the experimental correlated reader protocol. Each line is `T HEX` or `R HEX`, with transport CRC removed. It checks each constructed request, response nonce, sequence, full address, count and payload CRC using the production campaign implementation. Unrelated replies do not consume the pending slot. It requires all 1 MiB of original coverage before recording the entry boundary, then all 16 KiB of prepared banks. Partial data and repeated or out-of-order requests cannot produce an export.

```
dotnet run --project Tools/AL5/SavedBackupTool/SavedBackupTool.csproj -- original.txt prepared.txt 0102030405060708 0807060504030201 saved-evidence-id NEW-output-directory
```

The example nonces are for offline fixtures. Physical session acquisition is not implemented here. Nonces must differ across the two saved acquisition epochs; they do not prove that a physical reader entered safely or that data came from the correct controller.

Output retains the complete original image, its original banks, the separate prepared banks and a report with input paths, transcript hashes, image hashes, coverage counts and preparation delta. Existing output directories are rejected. Invalid or incomplete transcripts produce no output. All physical qualification and live-operation flags remain false. No adapter is constructed or opened.

These are experimental correlated-reader transcripts, not stock Mode $23 traces, whose limited address echo cannot supply the same session correlation. A reconstructed historical fixture can test the software but cannot become a physical backup through export.

After building, run `python Tools/AL5/test_saved_backup_tool.py --tool LocalOnly/SavedBackupTool/bin/SavedBackupTool.dll --output NEW-test-directory` for complete, stale-epoch, partial, wrong-nonce, duplicate-request, unowned-reply and existing-output cases. The test generates a synthetic image and never opens a hardware port.
