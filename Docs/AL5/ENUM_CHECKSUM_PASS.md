# Offline enum and independent checksum evidence pass v7

`Tools/AL5/AL5_ENUM_CHECKSUM_EVIDENCE_v7.lua` uses the existing successful raw
capture/secondary-descriptor engine. Run it in EFILive V8 F9 → Scripting with
the same unchanged stock CTZ and existing read-only AL5RAW CAX8 views. No
vehicle or interface connection is needed. Keep the script in a writable
folder; it writes `AL5_ENUM_CHECKSUM_EVIDENCE_<timestamp>_<NNN>.json` beside it.
Return that report, including any partial/error report.

The installed **EFILive Command Line Reference.pdf**, printed pages 31 and 40,
documents file-descriptor checksum updates and text enum setters. The matching
[official reference](https://content.efilive.com/documents/EFILive%20Command%20Line%20Reference.pdf)
supports this workflow. The existing API-name inventory also confirms both
functions are present. No enum byte encoding or numeric enum value is guessed.

## What runs

1. Validate controller/OS/calibration, stock controls, raw anchors, and checksum
   `4E35D040`. Open a distinct positive secondary descriptor; require captured
   bytes to equal the GUI baseline before any modification.
2. Call `_efiUpdateChecksums` on the secondary stock source and require it to
   preserve the captured baseline. Failure stops the pass.
3. Independently change D5000 row zero 16→17 km/h, D5120 14→15 cm3, then D5194
   89→88 percent. After each edit capture its exact raw difference, call the
   native checksum updater, capture the resulting field/differences, restore
   the original value, update checksums again, and require the complete captured
   raw range to return to baseline before the next case.
4. Set D5053 and D5054 individually from `Enable` to text `Disable`. Require
   exact text readback, capture all raw changed bytes, restore the original
   text, and require the full captured range to equal baseline after each.
   These two enum cases do not call the checksum updater.
5. Verify the GUI captured image is unchanged; close/discard the secondary
   without saving. Report errors and partial results as unsuccessful passes.

No tune-save, device, security, segment import/export or transport APIs are
called. Manual interruption may bypass cleanup: discard the secondary without
saving. The captured range is the established 0x08000–0x15FFF window set; a
successful check describes that captured range, not unobserved tune memory.
Checksum repair here is confined to a disposable descriptor of the known stock
source with controlled edits. Nothing is sent to the TCM or exported as a
flash-ready BIN.

## Verify the returned report

`verify_enum_checksum_pass.py` reconstructs each numeric variant from the
known stock bytes, rejects out-of-range/unexpected changes, checks marker
identity/readback/restoration, and compares all three EFILive-finalized native
fields with `checksum.native_field`. It never corrects the evidence or writes
a BIN. A checksum mismatch is reported explicitly. Enum differences remain
candidates until their field width/bit ownership is reviewed.

This can supply additional independently finalized native checksum examples
if AL5 raw views expose the updater's changes. It does not prove controller
acceptance, physical flash geometry or recovery. At preparation time it has
passed syntax validation but has not been executed in EFILive; no new checksum
or enum mapping result is claimed.

D5197 remains deferred: the existing stock export says `All Enabled`, but its
other exact option labels are not documented by the saved metadata. Its GUI
dropdown labels or EFILive's Copy as Lua Source output are needed before a
targeted text marker is prepared. This pass does not guess those alternatives.
