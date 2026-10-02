# Captured sender and exit paths: synthetic FIFO observations

[Ten bounded cases](LOADER_SENDER_EMULATION.json) execute the saved sender,
cleanup and selected exit paths in M68020 emulation. Source/generator hashes
accompany the report. MMIO instructions are intercepted before execution;
watchdog/delay helpers return through isolated stubs. Reset and loader restart
stop execution. No adapter, loader upload, live packet or reset is involved.

## Response construction

The sender at `0xFF952E` uses RAM priority at `0xFFFF9A79`, destination at
`0xFFFF9A78`, and source `0x18`. The dispatcher's preceding stores populate the
first two fields from the request priority/source. Synthetic `0x6D`/`0xF0` and
`0x6C`/`0xF1` cases therefore preserve priority and reverse request addressing.
The status builder contributes service `0x76`, zero and the selected status.

The code models control values `0x14` before the first byte, `0x04` before
intermediate bytes and `0x0C` before the last byte. These are observed register
values, not independently established hardware command meanings. Six software
bytes are presented for a three-byte status body. The report exports decoded
fields, lengths and hashes rather than complete frame byte strings.

There is no explicit software checksum append in this sender path. Controller
CRC/checksum behavior, framing and bus arbitration remain unknown. Existing
write traces do not establish a complete post-upload exchange; the preceding
request census cannot validate these sender observations on a physical bus.

## Bounds, timeout and cleanup

- Immediate readiness completes the six-byte response. Five initial synthetic
  busy reads add five iterations and preserve the same software-byte hash.
- Permanent busy status reaches `0xFF9000` after 4,096 watchdog-stub calls and
  4,095 readiness reads, with only the first software byte presented. The loader
  entry is trapped. This is a restart branch, not proven recovery or a successful
  retransmission; iteration counts do not establish elapsed time.
- Raw sender lengths zero and one do not terminate within the three supplied
  body bytes. Both reach a body-read trap before a complete modeled group.
  This is a direct sender-entry experiment, not a dispatched request with such
  a length. Normal observed callers use lengths at least three.
- Cleanup at `0xFF9550` presents two four-byte groups with broadcast destination
  `0xFE`, priorities `0x8C`/`0x6C`, sources `0xF0`/`0xF1` and one-byte body `0x3F`.
  The register behavior is modeled; its physical network effect is unverified.

## Exit branches

The synthetic Mode `0x3C` subtype `0x55` request reaches the shared exit at
`0xFF9236`. It calls the delay helper twice, models control `0x40` plus data zero,
and reaches the reset store at `0xFF924A`. Its absolute short operand `$8000.w`
sign-extends to **MMIO `0xFFFF8000`**, not flash address `0x8000`. The store value
is statically `0xD0C2`; the instruction remains trapped.

Direct finalization-tail entries produce status `0x86` or `0xFF` and then reach
the same reset trap. They bypass the sum verification and completion-marker
programming, so they do not prove either occurred. Both tested tails reset;
neither acknowledgment establishes bootability, completed programming or recovery.

## Reproduction and next work

Run `Tools/AL5/emulate_loader_sender.py --loader <private-captured-loader>
--output <report>` in the existing WSL Unicorn environment. The planner hash-links
the report while keeping transport/reset/recovery verification false, readiness
false, erase scope null and packet lists empty. The C# reader and write rejection
are unchanged.

`LOADER_RECEIVE_EMULATION.md` now bounds receive-loop branches and budget refresh
using synthetic events and seeded timeout counters. Next identify the FIFO
controller/register contract from saved firmware/hardware evidence and connect those results
to complete saved session captures if available. Physical mapping, collateral
preservation, flash timing and demonstrated recovery remain separate blockers.
