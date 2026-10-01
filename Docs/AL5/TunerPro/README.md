# AL5 validated core v0.3

Imported from the existing handoff package without regenerating the definition.
Use only a 57,304-byte calibration segment covering TCM addresses
`0x08000–0x15FD7`, OS 15184109 / calibration 15183960. The XDF subtracts
`0x8000` from native addresses. It is not for a CTZ or a 1 MiB editor image.

The mapping validation records retain their original confidence. D5100–D5115
are exact sequence/record-family mappings, not marker-differential proofs.
D5233 and the raw `0x10A24` entry remain research items as described in the XDF.

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
