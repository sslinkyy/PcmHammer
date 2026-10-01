# Adaptive enable mappings and checksum milestone — XDF v0.10

Subsequent v8 completed: D5197 is now marker mapped in v0.11. This document
preserves the v0.10 milestone; current limits and next actions are in
[D5197 and cell coverage](D5197_AND_CELL_COVERAGE_v0_11.md).

The successful v7 report independently finalized three controlled edited
payloads in EFILive. Both words match the offline formula for every case:
`732DAAC8` (D5000), `EBA232B3` (D5120), `7B29A38C` (D5194). All raw restores
passed, the GUI was unchanged, and the secondary closed without saving.
See `../CHECKSUM_RECOVERY.md` and `../ENUM_CHECKSUM_VALIDATION_v7.json`.
This advances offline checksum generation, not programming readiness.

The same report identifies two byte enums independently:

- D5053 Upshift Adaptive Learn Enable: `0xF6AC`, Enable 1 → Disable 0.
- D5054 Kickdown Adaptive Learn Enable: `0xCCF2`, Enable 1 → Disable 0.

Exact text readback, isolated byte changes and full raw restoration confirm
the named values. Saved firmware uses `TST.B` at `0x730BC` and `0x72FFA`,
respectively, followed by nonzero branches. A zero byte sets bit 0x40 in a
shared runtime byte at A5+0x2CCE. This establishes a full-byte zero/nonzero
consumer rather than requiring a bit-field guess. Only 0/1 have native label
evidence; other values are not offered in the new entries.

`ADAPTIVE_ENABLE_FIRMWARE_REFERENCES.json` preserves bounded disassembly and
source hashes. `expand_enum_mappings.py` validates source firmware bytes,
the native stock labels, the report, and checksum comparisons before adding
the entries. `ADAPTIVE_ENABLE_MAPPING_v0_10.json` records provenance.

`AL5_15184109_15183960_MARKER_EXTENDED_v0_10.xdf` preserves all previous data
encodings, adds two 8-bit 0/1 constants, and resolves the visible EFILive unit
templates in the H0105/H0136 titles. It also updates checksum/usage wording.
The audit passes 283 numeric comparisons across 290 items; two new text enums
are checked separately against the marker data. 126/127 native IDs are now
represented, including partial/research entries. D5197 remains absent. Keep
both adaptive enables at stock 1 for the first vehicle test. The two new
entries have not yet been displayed in TunerPro; prior GUI checks are recorded
for v0.9.1 and are not automatically extended to every v0.10 entry.

## Final enum pass — exact options supplied by the user

The user supplied the D5197 EFILive dropdown labels and a screenshot confirming:

- All Enabled.
- Torque Limit Req Disabled.
- RPM Limit Req Disabled.
- Torque and RPM Limit Req Disabled.

The last label uses `and`, not an ampersand. No raw enum values are inferred
from these names. `Tools/AL5/AL5_D5197_TEXT_MAPPER_v8.lua` prepares one isolated
marker for each of the three alternatives. It uses the already-tested
secondary-descriptor/raw capture engine, requires exact text readback,
restores the original `All Enabled` text and complete raw baseline after
each case, and verifies the GUI captured memory is unchanged at completion.
It never saves the tune, finalizes its checksum or communicates with a vehicle.

Run v8 in EFILive F9 → Scripting with the same unchanged stock CTZ and existing
AL5RAW views. Return `AL5_D5197_DIFFERENTIAL_MAP_<timestamp>_<NNN>.json`, including
an error report if applicable. No need to rerun v7. The v8 syntax check passes;
actual EFILive execution and any D5197 XDF assignment remain pending.
