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
