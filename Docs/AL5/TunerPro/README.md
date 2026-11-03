# AL5 validated core v0.3

Imported from the existing handoff package without regenerating the definition.
Use only a 57,304-byte calibration segment covering TCM addresses
`0x08000–0x15FD7`, OS 15184109 / calibration 15183960. The XDF subtracts
`0x8000` from native addresses. It is not for a CTZ or a 1 MiB editor image.

The mapping validation records retain their original confidence. D5100–D5115
are exact sequence/record-family mappings, not marker-differential proofs.
D5233 remains a research item as described in the XDF. The historical raw
`0x10A24` entry is identified as D5197 by the subsequent v0.11 marker evidence.

The target sheets are the existing minimal 1→2 pressure/volume proposal.
Timing, RPM, torque authority, TCC and other shifts stay stock. They are offline
development targets; neither the XDF nor the sheets authorize flashing.

The imported XDF contains an older EFILive save/flash suggestion. That suggestion
is not applicable to this project: the user has no FlashScan. Follow the current
handoff instead. The imported warnings describe the handoff state; subsequent
offline checksum recovery is recorded in `../CHECKSUM_RECOVERY.md`. AL5
programming remains unproven. No edited BIN is flash-ready.

Reference calibration BINs and proprietary EFILive objects are deliberately not
included. Run the tools under `Tools/AL5` with local file paths. Preserve original
v0.3 here; expanded definitions belong in separately versioned files.

## Structural TCC v0.4

`AL5_15184109_15183960_STRUCTURAL_TCC_v0_4.xdf` adds 38 vectors / 646 cells
across D5010–D5013 and D5015–D5018. A–D are unique complete eight-record
families; E, F and H are unique apply/release pairs. The two candidate G pairs
at `0x1333E` and `0x133F2` remain deferred. Pattern names follow the native
export; their operating-mode semantics have not been proven.

Every included vector matches the native export exactly and has the expected
`0x0011` header and `0x24` record stride. This establishes structural confidence,
not marker-differential proof. `TCC_MAPPING_v0_4.json` records the evidence.
The resulting XDF has 173 items; 168 numeric entries pass native comparisons.
The independent v0.3 audit also passes all 130 resolved numeric entries.
No TunerPro GUI validation was performed for the new v0.4 entries.

## Structural TCC/WOT v0.5

`AL5_15184109_15183960_STRUCTURAL_TCC_WOT_v0_5.xdf` adds another 16 vectors
for D5020–D5023 WOT upshift speed. Each two-cell record matches the native export
and is anchored to the preserved WOT RPM family, with a `0x0002` header and
`0x06` stride. All 184 resolved numeric entries pass the independent audit.

87 of 127 native definition IDs are represented, including partial/research
entries; 40 remain absent. D5010/D5015 Pattern G is still missing. WOT downshift
speed and WOT TCC searches have repeated-value ambiguity; do not promote their
candidate matches without structural or differential proof. The v0.5 GUI has
not been checked in TunerPro. See `../CHECKSUM_RECOVERY.md` for the subsequently
recovered offline checksum; the imported v0.3 warnings are historical.

## Structural extended v0.6

`AL5_15184109_15183960_STRUCTURAL_EXTENDED_v0_6.xdf` adds 26 vectors / 228 cells
across D5030–D5034 (WOT temperature and thresholds), D5070/D5071 (minimum and
maximum TCC duty cycle), and D5072 (TCC on-ramp rate). Each complete BE16
column-major table has one match in the stock segment and the expected preceding
dimension header. Separate column vectors retain the native export orientation.
`EXTENDED_MAPPING_v0_6.json` records addresses, scaling and source hashes.

All 210 resolved numeric entries pass the native comparison audit. 95 of 127
native IDs are represented, including partial/research entries; 32 remain absent.
Pattern G remains unresolved. These additions have exact structural confidence;
marker-differential proof, axis semantics beyond the export labels, and TunerPro
GUI validation remain open. No edited BIN is flash-ready.

## Structural WOT/TCC v0.7

`AL5_15184109_15183960_STRUCTURAL_WOT_TCC_v0_7.xdf` adds 32 vectors / 64 cells.
D5064–D5069 now include the complete WOT TCC apply/release families for normal,
tow/haul and 4WD Lo. The eight-record family for each mode has a unique match,
including all gear columns, `0x0002` headers and `0x06` stride.
D5035–D5038 include only downshift Patterns B and C, whose four-record families
are unique. Patterns A and D have identical native values and two matches;
neither has been assigned. `REMAINING_FAMILY_CANDIDATES.json` retains every
tested layout and its matches, including unsuccessful interleaved TCC layouts.

Downshift native Pattern B matches the records next to the preserved RPM
Pattern D address; downshift C matches those next to RPM Pattern B. A/D match
the records next to RPM A/C. Therefore adjacency alone cannot propagate the RPM
labels to downshift records. The new labels follow each native definition's
complete values; their controller mode semantics are still unproven.

All 242 resolved numeric entries pass the audit. 105 of 127 native IDs are
represented, including partial/research entries; 22 remain absent. The six WOT
TCC IDs are complete; the four downshift IDs are partial. New entries remain
structural mappings without marker proof or TunerPro GUI validation.

See `REMAINING_CONTROLS.md` for narrowed scalar and throttle-release candidates
and their firmware-reference evidence. Those hypotheses are deliberately not
added to the v0.7 XDF; representation remains 105/127 native IDs.

## Research supplement v0.8

`AL5_15184109_15183960_RESEARCH_SUPPLEMENT_v0_8.xdf` preserves all named v0.7
tables and adds 25 raw vectors / 425 words from five firmware-selected families.
Forty-five isolated emulator cases verify mode/flag selection, 36-byte stride,
indices zero through four and lookup argument/result handling. These entries
have raw counts and raw-row/selector-index labels in the Research / Raw category.
Native calibration IDs, physical mode names, gear names and row-axis units are
unassigned. The supplement does not increase native ID coverage.

The XDF audit passes all 242 previously resolved native comparisons and bounds/
category/unique-ID checks for the new entries. Their raw words match the local
stock data; TunerPro GUI validation is pending. Use v0.7 as the named-definition
baseline. The research supplement and any edited BIN remain offline only.

## Marker extended v0.9

`AL5_15184109_15183960_MARKER_EXTENDED_v0_9.xdf` adds 41 items from the
successful 83-case offline EFILive report: 16 scalars, 15 throttle-release
vectors, two Pattern G TCC vectors and eight Pattern A/D downshift vectors.
All 283 numeric comparisons pass; 124/127 native IDs are represented. The
three remaining absent IDs are D5053/D5054/D5197 text enums. Existing v0.7
entries are preserved. H0105's high-word width remains inferred and is
explicitly labeled; TunerPro GUI display validation remains pending.

See [marker validation and next single-case test](MARKER_VALIDATION_v0_9.md).
The v0.8 raw supplement remains separate. No edited BIN is flash-ready.

## Marker extended v0.9.1

`AL5_15184109_15183960_MARKER_EXTENDED_v0_9_1.xdf` records the completed H0105
high-word pass. Raw 4000 changed to 160934 with a nonzero high word and an exact
native readback match. All v0.9 encodings are preserved; only the confidence
description and usage warning change. The full audit still passes 283 numeric
comparisons, with 124/127 native IDs represented. See
[completed high-word evidence and GUI checks](MARKER_VALIDATION_v0_9.md).
TunerPro GUI validation and the three enum encodings remain open. No edited
BIN is flash-ready.

## Marker extended v0.10

`AL5_15184109_15183960_MARKER_EXTENDED_v0_10.xdf` adds marker/firmware-confirmed
D5053 and D5054 byte enums (0 Disable, 1 Enable). All earlier encodings are
preserved. The H0105/H0136 titles now use readable kilometer labels instead of
EFILive unit templates. 126/127 native IDs are represented; only D5197 remains
absent. All 283 numeric comparisons pass; the two new text enums have separate
marker checks. Their new GUI displays are pending.

Three independently EFILive-finalized edited fields match our complete checksum
formula, bringing independently sourced examples to five. Read
[v0.10 evidence and the final enum pass](ADAPTIVE_ENABLE_v0_10.md). No edited BIN
is flash-ready while protocol, geometry and recovery remain unresolved.

## Marker extended v0.11 — current named definition

`AL5_15184109_15183960_MARKER_EXTENDED_v0_11.xdf` relabels the existing raw
0x10A24 entry as marker-confirmed D5197. The four validated hexadecimal byte
values are 00 All Enabled, 20 Torque Limit Req Disabled, 40 RPM Limit Req
Disabled, and 60 Torque and RPM Limit Req Disabled. PPEI uses 40, resolving
the earlier unknown change. Keep stock; the raw constant cannot enforce a
discrete dropdown and other byte values are unvalidated.

All 127 native IDs are represented, but this includes partial/research entries.
The improved audit counts 2381 of 2517 unique numeric cells; 136 remaining
cells are D5000/D5005 Patterns E-H. All 283 numeric entry comparisons pass.
[Coverage evidence and the next 24-cell pass](D5197_AND_CELL_COVERAGE_v0_11.md)
describe this distinction. No edited BIN is flash-ready.

## Offline trace of the extra TCC families — 2026-11-03

The completed v0.12 exported-definition coverage is recorded in
[NUMERIC_COVERAGE_v0_12.md](NUMERIC_COVERAGE_v0_12.md). Beyond that exported set,
the two previously unassigned raw families at 0x13A08 and 0x13C30 now have
cruise-conditioned selection, shared speed/gear axes, fixed-point cell scaling,
and a bounded release-reason/state trace. Both contain the same all-0xFFFF
values as their corresponding stock base banks, so stock bank switching alone
does not change the lookup result.

Read [the combined trace](TCC_CRUISE_THROTTLE_RELEASE_TRACE.md) for activation,
source identities, actual extracted-code replay, and the physical-validation
boundary. The named XDF and source calibration bytes are unchanged.

## Cruise TCC v0.13 — current expanded definition

Use `AL5_15184109_15183960_CRUISE_TCC_v0_13.xdf` with the same 57,304-byte
segment format and OS/calibration context. It preserves all 298 v0.12 items
and adds the two traced cruise banks as ten per-gear entries under
`TCC / Cruise Throttle Release`:

- Tow/Haul cruise family header 0x13A08.
- Normal-family cruise header 0x13C30.

Each bank has first-through-fifth selected-gear columns, shown as individual
17-cell vectors to skip the intervening count headers. Speed labels are
0, 16, ..., 256 km/h; physical units are corroborated by shared native
definitions and the speed producer. Values are unsigned BE16 percentages,
`raw * 100 / 65536`. These are firmware-traced alternate-bank identities;
they have no assigned EFILive IDs or direct native marker proof.

All 170 added stock cells are 0xFFFF, exactly 99.99847412109375% (99.998% at
the configured three decimal places). Existing native coverage remains
127/127 IDs and 2517/2517 numeric cells; the complete audit passes across
308 items. See `CRUISE_TCC_MAPPING_v0_13.json` for addresses, stock values
and evidence hashes, and `V0_13_AUDIT.json` for the full audit.

`Tools/AL5/expand_cruise_tcc.py` reproduces the expansion from v0.12 and
validates stock bytes, count headers, cell conversion, preservation of prior
items and complete native numeric coverage. Output paths must be absent.
Stock and PPEI BIN bytes were unchanged. TunerPro GUI validation completed
2026-11-03 in TunerPro RT 5.0.10305.0: all ten cruise gear entries, their
17-row km/h axes (0 through 256 in steps of 16), native offsets and all
170 displayed stock cells (99.998) passed actual visual inspection.
`V0_13_TUNERPRO_GUI_VALIDATION_20261103.json` binds this result to the unchanged
v0.13 XDF hash. The loaded stock-reference copy matched the original stock
digest; original stock/PPEI digests remained unchanged. Editors and the BIN
were closed without saving. Generated XDF/manifest wording about pending GUI
validation records their earlier generation state; the separate GUI report
records this subsequent check. Activation and software-effect limits remain documented in
[the combined trace](TCC_CRUISE_THROTTLE_RELEASE_TRACE.md).
