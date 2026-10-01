# AL5 storage selection and restore — offline evidence

The application preparation path reaches persistent storage before its reset
marker. The selector at `0x22250`, restore caller at `0x2266C`, and update
caller at `0x226F0` were exercised against synthetic, read-only banks. All 15
cases in `STORAGE_SELECTION_EMULATION.json` pass. Every erase/program/copy
primitive is trapped before its first instruction; no hardware is accessed.
`STORAGE_SELECTION_STATIC_EVIDENCE.json` preserves the bounded selector/restore
disassembly with source hashes; update-call evidence is also retained in
`RECEIVE_PREPARATION_STATIC_EVIDENCE.json`.

## Observed decisions

Both bank signatures are checked before returning a cached pointer. The expected
header is `55 32 32 FF`, derived from the ROM words at `0x21422`. The generation
word follows at offset `+4`; the record marker is at `+0x28`. Context data begins
at `+0x2A` and occupies 2546 bytes, including a final BE16 CRC over 2544 bytes.
These offsets do not establish physical erase geometry.

- `0xFFAA` denotes a committed record. When both records are committed, the
  tested selector prefers bank `0x4000`, even if bank `0x6000` has a higher
  generation word. Do not substitute a newest-generation selection rule.
- Bank `0x4000` with marker `0x00AA` is selected as pending before a committed
  second bank. A pending second bank alone does not follow that same path.
- With valid signatures, a nonzero cache can return without record validation.
  The fast path does not refresh the selected-record state word.
- Missing commit markers or invalid signatures reach repair. A bad second-bank
  header can reach an erase of bank `0x4000` even when its record is committed.
  This call is intercepted; repair completion and recovery are unverified.
- Restore copies a committed context into RAM and returns zero. It also copies
  a committed context with a bad CRC. This routine does not validate the CRC
  itself; downstream validation remains to be traced. Pending records are not
  copied by the tested restore caller.
- Updating a selected committed bank first calls erase on the opposite bank:
  selected `0x4000` targets `0x6000`, and selected `0x6000` targets `0x4000`.
  Execution stops at that call, so no completed storage transaction is claimed.

## Saved reference inventory

`STORAGE_REFERENCE_INVENTORY.json` records metadata from the existing saved low
editor image, identified by SHA256. Bank `0x4000` has marker `0xFFAA`; bank
`0x6000` has marker `0x0000`. Both signatures and context CRCs match. Only hashes,
markers, generation words and CRC results are exported; raw headers and context
contents remain local.

This saved image is not a verified current physical backup of the installed
controller. Matching CRCs do not prove recovery or preservation. The file-only
planner links both reports by hash while retaining false preservation, geometry,
recovery and flash-readiness fields, null erase scope and empty packet lists.

## Reproduce and next work

Run `Tools/AL5/emulate_storage_selection.py` with explicit `--low`, `--high` and
`--output` paths in the existing WSL Capstone/Unicorn environment. Firmware hashes
must match the saved evidence. Run `Tools/AL5/storage_inventory.py --source ...
--output ...` with the existing low image, or an explicitly supplied 0x4000-byte
two-bank image using `--origin 0x4000`. The inventory has no transport dependency.

Next trace downstream context validation and the complete update/repair marker
ordering offline. A synthetic storage model and interruption cases may help
test those transitions, but must remain separate from physical flash geometry,
timing and recovery claims. Live boot entry, erase/program and experimental
services remain disabled. The working Mode 0x23 reader is unchanged.
