# Marker extended XDF v0.9

The 2026-10-01 EFILive v6 report completed all 83 isolated cases. Every case
reported successful restoration, the secondary descriptor closed without
saving, and the GUI raw image remained unchanged. No vehicle I/O occurred.
The original report stays local. `TARGETED_DIFFERENTIAL_EVIDENCE_v6.json`
preserves its marker/validation data with only the source path redacted and
records the original report SHA-256.

`expand_marker_mappings.py` checks every changed byte and surrounding context
against the saved stock segment, validates source values against the native
export, and checks the encoded marker against actual API readback. It rejects
partial passes, duplicate/missing cases, unrestored cases, unexpected changes,
incorrect baseline bytes, unreported context changes and invalid flags.
For each vector, it additionally checks its header and all stock cells.

## Result

`AL5_15184109_15183960_MARKER_EXTENDED_v0_9.xdf` derives from the named v0.7
baseline, preserving all existing data entries. It adds 16 scalars and 25
vectors (41 items), with 283 numeric native comparisons passing across 288
items. Representation increases to 124/127 native IDs; D5053, D5054 and D5197
remain absent because their enum setter/encoding is unproven. Representation
includes partial/research entries and is not a claim of complete validation.

The marker report resolves:

- Bidi D5042–D5045: `0x9CFC/0x9CFE/0x9D00/0x9D02`, signed BE16 /4 RPM.
- TCC temperatures D5055/D5056: `0x1378C/0x1378E`, signed BE16 /128.
- TCC RPM D5057/D5058: `0x1375C/0x1375E`, unsigned BE16 /8.
- Transfer-case D5061, final-drive H0103, speed ratio H0137:
  `0x14B14/0x14B16/0x14B18`; each scale reproduces stock and actual marker
  readback. D5061 uses the native fixed-point factor 0.0001220704, H0103 /8192,
  and H0137 0.0097089219. These units follow the native export.
- Pressure RPM D5062/D5063: `0xB03C/0xB03E`, signed BE16 /4.
- Locked counter D5183: byte `0x803C`; diagnostic inspection only, keep stock.
- Tire revolutions H0136: `0x15640`, unsigned BE16 /32.
- Throttle-release D5073 Normal: family header `0x13B78`; D5074 Tow/Haul:
  `0x13950`; D5075 4WD Low: `0x13AC0`. Five columns each, data at header+2,
  36-byte record stride, rows 0/8/16 independently marked for every column.
  BE16 percent conversion is raw*100/65536. This corrects the prior candidate
  family order; equal stock values did not prove the native mode identities.
- Second-gear TCC Pattern G: D5010 data `0x133F2`, D5015 `0x13416`, /128 km/h.
  Rows 0/8/16 distinguish the previously identical candidate records.
- D5035–D5038 downshift Pattern A: data `0x12570+6*n`; Pattern D:
  `0x12840+6*n`, both High/Low rows marked, /128 km/h. These are native
  downshift identities and must not inherit adjacent RPM pattern labels.

For 17-cell vectors, only rows 0/8/16 have marker evidence; the other rows are
structurally mapped and match the full native stock sequence. Two-cell records
have both rows marked. TunerPro GUI display validation is still pending.
The v0.8 raw supplement is preserved separately; its two extra flag-dependent
families remain unassigned. Firmware selector mode 1 now correlates with the
native Tow/Haul family, mode 2 with 4WD Low, and the other-mode base with Normal;
this does not prove the meaning of every runtime flag or mode producer.

## H0105 width limit and next evidence pass

This subsection records the original v0.9 limit. The follow-up below resolves
the high-word question; no additional H0105 pass is currently required.

H0105's marker changed bytes `0x152E6/0x152E7` only. Its conversion factor
0.6213709992 reproduces stock and readback. The unsigned BE32 interpretation
starting at `0x152E4` matches the native hard maximum (4294967295 raw counts)
and the unchanged zero high word, but the marker did not independently prove
that high word belongs to the field. The v0.9 entry states this limitation;
do not edit it until confirmed.

`Tools/AL5/AL5_H0105_HIGH_WORD_MAPPER_v6_1.lua` prepares a single additional
offline test using the same now-exercised capture/restore engine. It requests
100000 count/km, within the native soft range, to require a nonzero raw high
word. Run it in EFILive F9 → Scripting on the same unchanged stock source with
AL5RAW views installed. It writes `AL5_HIGH_WORD_DIFFERENTIAL_MAP_*.json`
beside the script. Return the report; no vehicle connection, tune save or flash
is involved. The new one-case script itself is not yet GUI executed.

This report provides no additional native checksum-finalization evidence.
No BIN was edited or committed. Read code and the live-write block are unchanged.

## Completed high-word pass — v0.9.1

The 2026-10-01 03:05 local EFILive v6.1 report completed its single case,
restored the entire raw baseline, closed the secondary without saving, and
reported the GUI raw image unchanged. Requested 100000 count/km changed
`00000FA0` to `000274A6` at `0x152E4` (raw 4000 → 160934). The changed bytes
are `0x152E5/0x152E6/0x152E7`; the most significant byte stayed zero. The
high word changed from zero to two. The fixed factor 0.6213709992 reproduces
the actual readback 99999.7203852528 count/km. The difference from requested
value is less than one raw-count unit, consistent with integer quantization.

`validate_high_word.py` checks the full report safety/baseline/restoration
flags, case identity, all changed bytes and context against stock, native
stock/readback values, nonzero high word, and the native unsigned 32-bit hard
maximum. The redacted original is preserved in
`H0105_HIGH_WORD_EVIDENCE_v6_1.json`; input hashes and results are in
`H0105_HIGH_WORD_VALIDATION_v0_9_1.json`.

`AL5_15184109_15183960_MARKER_EXTENDED_v0_9_1.xdf` updates H0105's confidence
description and usage warning only. Every v0.9 data encoding is preserved.
All 283 numeric comparisons pass across 288 items. Native representation
remains 124/127; D5053/D5054/D5197 text enums still need encoding evidence.
TunerPro GUI display verification is the next GUI task. Check H0105 on the
stock segment displays approximately 2485.484 count/km, H0136 424 rev/km,
H0103 4.0998535, and H0137 262.791389 rev/km. Keep the native units as labeled;
no unit conversion or tune editing is needed for this check.

This additional marker does not prove checksum finalization, physical flash
geometry, recovery or live programming. No vehicle I/O or user BIN edit was
performed, and the reader/live-write gate remain unchanged.

## TunerPro v0.9.1 screenshot — four PPEI scalar displays

The user supplied a TunerPro RT screenshot on 2026-10-01. Its title bar shows
`Direct Read PPEI AL5 Performance Tune.bin` with the v0.9.1 XDF. The following
visible values agree with the independent PPEI decode, rounded to four decimals:

Screenshot SHA-256: `9fe488c3ee6115ad3f90510aea1e9868845db1982f071561f5e75262e44b2bf9`.
The image remains local and is not committed.

- H0105: 2485.4840 count/km.
- H0136: 424.0000 rev/km.
- H0103: 4.0999.
- H0137: 262.7914 rev/km.

This confirms these four scalar displays on the PPEI file. The stock BIN was
not shown; its separate GUI check remains pending. No table windows, table
orientation, axes, save/round-trip behavior or other scalar displays were
validated by this screenshot. The underlying four values are identical in
the stock and PPEI audits. TunerPro reports no connected hardware.

The H0105/H0136 titles visibly contain EFILive `{du,...}` description templates
instead of resolved prose. The numeric values and explicit units are correct;
cleaning those titles is a presentation follow-up, not new mapping evidence.

## TunerPro v0.9.1 screenshot — four stock scalar displays

The subsequent user screenshot on 2026-10-01 shows
`AL5_15184109_15183960_STOCK_REFERENCE_SEGMENT.bin` with the v0.9.1 XDF.
H0103 displays 4.0999, H0105 2485.4840 count/km, H0136 424.0000 rev/km,
and H0137 262.7914 rev/km. All match the rounded independent stock decode.
These four scalar displays are now GUI checked on both stock and PPEI.

Screenshot SHA-256: `636812db9c070dfb239e88b9314016e119b36c3862a8312c535c7e0d2cd6d452`.
The image remains local and is not committed. Table/axis orientation and
save/round-trip behavior remain unchecked. No tune edit or vehicle operation
is inferred from this screenshot.

## TunerPro v0.9.1 screenshot — D5073 Normal / 1st Gear on stock

The next user screenshot on 2026-10-01 shows the stock reference BIN and
v0.9.1 XDF with D5073 Normal, Native Column 0: 1st Gear selected. All 17 rows
are visible in order: 0,16,32,48,64,80,96,112,128,144,160,176,192,208,224,240,256.
Every cell displays 99.998, matching the independent decoded value
99.99847412109375 rounded to three decimals. The status bar reports a 17x1
table, offset 13B7A, and 16-bit cells, matching the XDF/native mapping.

Screenshot SHA-256: `dbd90a6fed1054375299612958fb7fe8ea081a6c69fc95998d5d8e75533f74b7`.
The image remains local and is not committed. This confirms rendering of one
named column's row labels, values and dimensions; it does not GUI validate
other gear columns/modes or save/round-trip behavior. Labels remain the native
export labels; no new physical row-axis unit is inferred from 0..256.

The requested scalar and first table GUI spot checks are complete. Next offline
work remains enum encoding for D5053/D5054/D5197, independent native checksum
finalization evidence, and write-protocol/erase-geometry/recovery reconstruction.
No additional screenshot of these same checked fields is required. Live writes
remain blocked, and this screenshot supplies no programming evidence.
