# D5197 identified; native-ID and numeric-cell coverage

The completed v8 report independently sets each D5197 text alternative and
records one changed byte at `0x10A24`. All exact readbacks, raw restorations,
GUI-unchanged checks and secondary close succeeded. No tune save, checksum
finalization or vehicle communication occurred.

- `00`: All Enabled (stock).
- `20`: Torque Limit Req Disabled.
- `40`: RPM Limit Req Disabled.
- `60`: Torque and RPM Limit Req Disabled.

`expand_d5197.py` validates every case and context against stock, requires only
the named byte to change, and identifies the direct-read PPEI byte as `40`.
Thus the previously unknown PPEI `00→40` change is D5197 RPM Limit Req Disabled.
This is native-option identity proof, not proof of a particular shift-flare
mechanism or of downstream ECM behavior. It should not be described as an
unidentified patch anymore. Other bits at this byte remain unassigned.

`D5197_DIFFERENTIAL_EVIDENCE_v8.json` preserves the report with its source path
redacted; `D5197_MAPPING_v0_11.json` links stock/PPEI/source/report hashes.
The option-name screenshot SHA-256 is
`7b70b2badd36393301f14ed3e03836cf8fa8b86534e9e7c26996cae50ef8a2ba`.
The screenshot and user BINs remain local and are not committed.

## XDF v0.11 and limits

`AL5_15184109_15183960_MARKER_EXTENDED_v0_11.xdf` relabels the existing research
byte entry as D5197, without adding a duplicate overlapping entry. Its address,
8-bit width, raw conversion and hexadecimal display are preserved. The range
narrows to 0..96, but a raw constant cannot enforce the discrete valid set:
only 00/20/40/60 are validated. Keep stock 00; do not use arbitrary byte values.
This new enum entry is not yet GUI checked. The minimal write-plan allowlist
still rejects D5197 changes, and all live writes remain blocked.

All 127 native IDs are represented, including partial/research entries.
All 283 numeric entry comparisons pass. The audit now also counts unique native
numeric cell coordinates, preventing ID coverage from implying completeness:
2381 of 2517 numeric cells are represented; 136 are missing. They are exactly
D5000 and D5005 Patterns E/F/G/H (four 17-cell vectors in each table).
The four text-valued native cells are separate from this numeric count.

Complete-sequence/header searches were checked first. Their stock vectors have
repeated matches, including identical E/H upshift vectors and E/F/G downshift
vectors. Existing A-D anchors do not identify these remaining modes. No new
addresses are guessed from table adjacency.

## Next focused pass — v9 remaining columns

`Tools/AL5/AL5_REMAINING_COLUMNS_MAPPER_v9.lua` prepares 24 numeric markers:
rows 0/8/16 for every E-H column in D5000/D5005. It uses the successful isolated
secondary capture/restore engine. The manifest is `REMAINING_COLUMN_CASES_v9.json`.
Its Lua syntax check passes; actual EFILive execution is pending.

Run v9 in EFILive F9 → Scripting with the same unchanged stock CTZ and installed
AL5RAW views. Return `AL5_REMAINING_COLUMNS_MAP_<timestamp>_<NNN>.json`, including
an error report if applicable. Each cell is restored before the next case and
the entire captured range must return to baseline. The script does not save,
update checksums or communicate with a vehicle. No repeat v8 run is needed.
