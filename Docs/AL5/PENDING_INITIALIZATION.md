# AL5 pending-context initialization — bounded offline trace

Six cases in `PENDING_INITIALIZATION_EMULATION.json` pass. Three bounded paths
are exercised with RAM filled separately with `0xA5` and `0x5A`: primary defaults
at `0x56734`, secondary defaults at `0xC02B0`, and the pending caller from
`0x5BA24` through `0x5BA5E`. These execute real saved firmware helpers against
synthetic RAM and read-only banks, without storage writes or hardware access.

## What is rebuilt

The primary helper copies saved calibration bytes `0x08000–0x08657` into RAM
`0xFF8140–0xFF8797` (1624 bytes). It then loads other calibration-backed fields
and writes constants outside that prefix. Examples proven by code execution:

- Words at `0x0DC36–0x0DC44` populate RAM words within `0xFF887A–0xFF8888`;
  bytes at `0x0DC46/0x0DC47` populate `0xFF88A9/0xFF88A8`.
- RAM words `0xFF888A/0xFF888C` become `0x7FFF`, and words
  `0xFF888E–0xFF889A` are cleared. Numerous individual bytes within
  `0xFF88B5–0xFF893D` become `0x88`; this value is not assigned a field meaning.
- The copy helper `0xA9D0C` takes a bit count: its argument 8 copies one byte
  from `0x0C0AE` to `0xFF88A0`, following clears of `0xFF88A1–0xFF88A7`.
  Its argument 9 copies two bytes in the secondary helper. These are the
  exercised positive counts; no universal length/range policy is inferred.
- Saved calibration words at `0x08196`, `0x0816A`, `0x0816C` and `0x14B52`
  populate `0xFF82D6`, `0xFF82AA`, `0xFF82AC` and `0xFF8B2E` respectively.

The secondary helper rebuilds 44 bytes at `0xFF82DA–0xFF8305`, within the
primary copied prefix. It copies calibration-backed data, uses the two-byte
copy described above, and clears terminators at `0xFF82FB` and `0xFF8305`.
The byte-loop sources for `0xFF82F2–0xFF82FA` are `0x081B2–0x081BA`; sources
for `0xFF82FC–0xFF8304` are `0x081BD–0x081C5`. The latter loop increments its
source pointer before reading, so `0x081BC` must not be substituted as its first
source. Field identity and text semantics remain unassigned.

For the pending path, restore returns 1 without copying the pending bank
context. The caller executes both default helpers, clears RAM
`0xFF8798–0xFF886F`, sets the pointer at `0xFF87BC` to `0xFFB7F0`, and reaches
the next helper at `0x55298`. Execution stops before that helper.

## Coverage and remaining gaps

The primary helper writes 1804 unique context bytes; the secondary helper alone
writes 44. The bounded pending path writes 2020 of the 2546 stored-context bytes.
Its 526 untouched bytes are identical address ranges in both sentinel cases:

- `0xFF8870–0xFF8879` (10 bytes)
- `0xFF889C–0xFF889F` (4 bytes)
- `0xFF88AA–0xFF88B4` (11 bytes)
- `0xFF88FA`, `0xFF88FF`, `0xFF892F` (3 bytes)
- `0xFF893E–0xFF8B2D` (496 bytes)
- `0xFF8B30–0xFF8B31` (2-byte stored CRC)

All untouched bytes retain the synthetic sentinel. The CRC word is not rebuilt
by these helpers, and the resulting synthetic context does not have a matching
CRC. Later helpers or initial RAM clearing may supply these bytes; this trace
does not claim the real controller leaves them undefined. Complete context
initialization, persistence and recovery remain unverified.

## Evidence and next work

`PENDING_INITIALIZATION_STATIC_EVIDENCE.json` preserves only the bounded helper
and caller disassembly, with exact source hashes. The report exports write
coverage, comparisons and hashes, not raw calibration/context contents.
Reproduce with `Tools/AL5/emulate_pending_initialization.py --low ... --high ...
--output ...` using the existing WSL Unicorn environment and saved source files.

The file-only plan hash-links this partial evidence while keeping complete
initialization, physical recovery and write readiness false. Packet lists remain
empty. The working Mode 0x23 reader is unchanged.

The subsequent `PENDING_HELPERS.md` executes all twelve remaining helpers and
links separate preparation CRC generation to an atomic modeled commit. It
still finds sentinel-dependent bytes/bits. Next trace preceding startup RAM
clearing and the actual pending-caller invocation.
Address/constant observations must remain separate from parameter meanings and
physical recovery claims. No live erase/program, loader or experimental service
is enabled or performed.
