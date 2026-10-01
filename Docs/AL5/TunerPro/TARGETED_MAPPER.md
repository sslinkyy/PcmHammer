# Targeted offline differential mapper v6

Run `Tools/AL5/AL5_TARGETED_DIFFERENTIAL_MAPPER_v6.lua` in EFILive V8
F9 → Scripting with the existing stock-equivalent AL5 tune open. The tune must
have OS 15184109 and transmission calibration 15183960. The already-installed
read-only AL5RAW CAX8 views must work; this script does not install definitions.
No vehicle or interface connection is needed.

The script derives its raw-view/API helpers from the successful v5.1 mapper.
It opens the source file into a positive secondary descriptor, verifies its
raw image matches descriptor zero, and checks all target dimensions and stock
values before edits. A known D5000 marker checks raw-view coherence first.
Each of 83 cases then changes one numeric cell, records requested and actual
readback plus every changed raw byte, restores the original cell, and requires
the entire captured image to return to baseline. Any failure stops the pass.
The secondary is closed without saving, including on caught errors. A partial
report contains `completed=false` and the error; it is not a successful map.
The script finally checks the GUI raw image is unchanged.

## Run and return evidence

1. Open the same stock-equivalent source used for the successful earlier mapper.
   Unsaved GUI edits will make the secondary-image comparison fail.
2. Load the Lua file through EFILive's scripting interface. Keep the script in
   a writable folder; `EFI_ScriptName` must include its directory.
3. Execute it. Expect many raw captures; progress prints the current case.
4. Return the `AL5_TARGETED_DIFFERENTIAL_MAP_<timestamp>_<NNN>.json` written
   beside the script. Return an error/partial report too if the pass fails.
   If manually interrupted, discard any secondary tune without saving.

Report files contain the source filename and calibration changes. Keep them
local until reviewed; do not commit user BINs or full tune files.

## Coverage and interpretation

`TARGETED_MARKER_CASES_v6.json` records the 83 cases and source SHA-256 hashes.
The cases cover 16 numeric scalar IDs, D5073–D5075 at rows 0/8/16 for every
gear column, D5010/D5015 Pattern G at rows 0/8/16, and D5035–D5038 Patterns
A/D at both High/Low rows. This distinguishes repeated values and tests row
orientation without assuming addresses or single-word encodings.

D5053, D5054 and D5197 remain excluded: they are text enums, and their setter
representation has not been established. No numeric enum encoding is guessed.
Changed-byte lists may reveal aliases or coupled fields; do not automatically
promote a single observed address into an XDF assignment. Compare readback,
all changes, restoration, and existing structural/firmware evidence first.

This is not a checksum generator. Marker images are never saved or exported as
flash-ready BINs. Captures cover 0x08000–0x15FFF using the established CAX8
windows, slightly beyond the 57,304-byte calibration segment. No transport,
erase, program, loader, security-key or tune-save API is called.

## Validation status

The manifest and script guard checks pass offline. The revised script has not
yet been executed in EFILive; actual setter behavior, rounding and secondary
descriptor behavior remain GUI validation requirements. A local Lua test
runtime could not be obtained, so no Lua execution test is claimed.
