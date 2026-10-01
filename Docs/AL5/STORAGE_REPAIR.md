# AL5 storage repair ordering and errors — offline

Nineteen cases in `STORAGE_REPAIR_EMULATION.json` pass: six complete modeled
repairs, five repair interruption snapshots, four repairs following interrupted
updates, and four bounded wrapper-error cases. The real selector/repair caller
executes against synthetic protected banks. Host hooks model successful atomic
erase/program effects; no flash implementation or physical controller executes.

## Repair behavior

Invalid bank signatures enter the repair branch at `0x2228C`. Valid signatures
without a committed/pending first record or committed second record reach the
second repair branch at `0x224A0`. Both tested branches follow the same order:

1. Capture the greater generation word plus one, treating an initial `0xFFFF`
   as zero, and copy header metadata from bank `0x4000` into local RAM.
2. Erase bank `0x4000` (8192 bytes in the model).
3. Program a 42-byte header/marker record: ROM-derived signature, generation,
   saved metadata and marker `0x00AA`.
4. Cache record address `0x4028` and set selected state to `0x00AA`.
5. Erase bank `0x6000` and program a 42-byte header/marker record using the first
   bank's metadata, its new generation plus one, and marker `0x0000`.
6. Return the pending record at `0x4028`.

Neither repair branch copies a saved context or tail. With the modeled bank
span, both contexts and tails are erased. An invalid second-bank header causes
this behavior even with a committed first-bank record. Four interrupted-update
snapshots (after erase or tail copy, in either bank direction) also follow this
repair route and lose both synthetic contexts/tails.

This is a reset/reinitialization path rather than demonstrated preservation of
the surviving context. Pending restore returns nonzero; its application caller
branches to initialization at `0x5BA24`, as recorded in `STORAGE_RECOVERY.md`.
Those downstream initialization helpers still need tracing. No claim is made
about the physical truck's resulting state or calibration-writing protocol.

Generation cases reproduce `0xFFFF` normalization and 16-bit wrap: input counts
`0xFFFE/0xFFFE` produce first-bank `0xFFFF` and second-bank `0x0000`. Do not treat
the counters as a universal newest-bank recovery rule.

## Interruptions and returned status

With two initially valid headers and no committed records, interruption after
the first header is programmed selects the new pending first record because
the original second header remains valid. After erasing the second bank,
signature checking enters repair again until its header is rewritten. Before
repair or after the first erase, selection likewise reaches repair. Reboot
selection is stopped at each repair call; the interruption cases themselves do
not execute recursive repair.

One complete case substitutes returned erase status `0x2000` after each
successful atomic modeled erase. The caller continues through both header
writes without branching on that status. This isolates caller status handling;
it does not model failed-erase contents or establish safe handling of an actual
erase failure.

## Program/copy wrapper errors

The bounded error slices at `0x22CAE` and `0x22DA8` are executed with synthetic
status bit 5 clear/set. With the bit set, both write application marker `0x6124`
and reach their wait loops (`0x22CC2` / `0x22DBC`). With the bit clear they reach
the normal continuation (`0x22CC4` / `0x22DBE`). The status-mask helper is
bypassed and execution stops at those endpoints. The RAM flash implementation,
hardware reset and error timing are not exercised.

## Evidence, limits and next work

The selector/repair disassembly is already preserved in
`STORAGE_SELECTION_STATIC_EVIDENCE.json`; program-wrapper code is in
`RECEIVE_PREPARATION_STATIC_EVIDENCE.json`, and copy-wrapper code is in
`STORAGE_RECOVERY_STATIC_EVIDENCE.json`. Reports identify exact source/code
hashes. Only synthetic payload hashes and metadata are exported.

Reproduce with `Tools/AL5/emulate_storage_repair.py --low ... --high ...
--output ...` in the existing WSL Unicorn environment. Physical erase geometry,
partial operations, failed-erase contents, timing and reset/recovery remain
unverified. The dry-run planner links this report by hash, keeps recovery and
readiness false, and emits no packets. The working Mode 0x23 reader is unchanged.

The subsequent `PENDING_INITIALIZATION.md` traces the first default helpers,
rebuilding 2020 context bytes while leaving 526 untouched before `0x55298`.
Next trace remaining initialization and CRC/commit production. Extend partial-operation/error models only from
firmware evidence, and continue resolving physical geometry/preservation and
the programming transport offline. No live destructive operation is enabled.
