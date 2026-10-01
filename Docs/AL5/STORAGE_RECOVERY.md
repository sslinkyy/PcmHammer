# AL5 context validation and update interruptions — offline

`STORAGE_RECOVERY_EMULATION.json` passes three validation cases and eighteen
transaction cases. The emulator executes bounded saved firmware callers and the
CRC routine against synthetic banks. Flash routines are not loaded or executed:
host hooks replace erase, program and tail-copy calls with successful atomic
memory changes. This tests caller ordering, not physical flash recovery.

## Context validation after restore

The absolute call to `0x2266C` at `0x5B934` is followed by the CRC routine at
`0xA95D0`, over RAM `0xFF8140` through `0xFF8B2F`. It compares the result with the
BE16 word at `0xFF8B30`. The extracted caller slice starts at `0x5B92E` and stops
before unrelated initialization helpers.

- A committed context with a matching CRC reaches `0x5B96E`.
- A committed context with a bad CRC sets the application marker to `0x8C9B`
  and reaches the wait loop at `0x5B96C`. The emulator stops there; reset/hardware
  consequences are not modeled. The status-mask helper on this path is bypassed.
- A pending record makes restore return nonzero and branches to `0x5BA24`,
  bypassing this CRC-check path. Initialization after that branch is not executed.

Thus the earlier restore-only result did not establish absent CRC validation:
its application caller performs the check. Complete application startup and
recovery behavior remain unverified.

## Update order and synthetic interruptions

The bounded update caller at `0x226F0` makes these seven modeled calls:

1. Erase the opposite candidate bank, modeled as 8192 bytes.
2. Copy the old bank's tail, from offset `+0xA4C` through the modeled bank end.
3. Program the 40-byte header, including an incremented generation word and
   metadata copied from bank `0x4000`.
4. Program record marker `0xFFFE`.
5. Program the 2546-byte supplied RAM context, including its CRC word.
6. Program new record marker `0xFFAA`.
7. Clear the old record marker to `0x0000`.

The caller then clears its cached pointer and returns. Synthetic programming
rejects zero-to-one changes. The 8192-byte bank span is a model assumption from
candidate starts, not verified physical erase geometry. Error statuses, timing,
partial-word programming and interrupted erase are not modeled.

For each active bank, eight cases interrupt before any operation or after each
of the seven completed atomic operations. Each snapshot is passed to the real
selector with a fresh RAM/cache state; every repair call is trapped.

- After erase or tail copy, the new bank has no valid signature. Selection enters
  repair and reaches an erase call targeting `0x4000`, despite the surviving old
  committed record. That repair implementation is not executed.
- After header programming and before the new commit, the old record is selected.
- After the new commit but before clearing the old marker, both are committed:
  the selector prefers bank `0x4000`. This returns the old context when updating
  from `0x4000`, and the new context when updating from `0x6000`.
- After clearing the old marker, selection returns the new context in either
  direction. Both complete modeled transactions also return and clear the cache.

These results rule out assuming that a surviving committed record alone makes
an interrupted update safe. The subsequent `STORAGE_REPAIR.md` traces the repair
caller through successful atomic operations: it rebuilds pending/inactive
records without preserving either context. Physical recovery remains unverified.

## Evidence and next work

`STORAGE_RECOVERY_STATIC_EVIDENCE.json` preserves bounded disassembly and source
hashes for the validation caller slice, update caller and tail-copy wrapper.
Raw bank/header/context contents are not exported. Reproduce with
`Tools/AL5/emulate_storage_recovery.py --low ... --high ... --output ...` in the
existing WSL Unicorn environment; exact saved firmware hashes are required.

The file-only planner hash-links this evidence, explicitly labels the atomic
model limits, and keeps physical recovery and readiness false with zero packets.
Repair ordering and bounded wrapper-error branches are now exercised in
`STORAGE_REPAIR.md`. Next trace pending-record initialization and add
partial-operation fault models only where firmware evidence supports them.
The existing Mode 0x23 reader is unchanged; no live destructive operation is
enabled or performed.
