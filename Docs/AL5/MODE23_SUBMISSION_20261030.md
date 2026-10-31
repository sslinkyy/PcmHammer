# Mode 23 transmit submission and software discard

This continues `MODE23_BOUNDARY_20261030.md` with the same pinned HIGH firmware.
The new isolated native experiment executes submission `0x70A44..0x70AA4`,
register-write helpers `0x70E58..0x70E92`, and software buffer clear
`0x70EA4..0x70ECA`. Source hashes and observations are recorded in
`MODE23_SUBMISSION_20261030.json`. No adapter or vehicle was accessed.

## Submission is not completion

The real Mode 23 formatter from the previous experiment stages ten bytes.
Submission calls helpers that write command/data pairs to `0xFFFFE800` and
`0xFFFFE801`: command `0x14` with the first byte, `0x04` with each intermediate
byte, and `0x0C` with the last. These are observed register values; their
hardware interpretation has not been independently qualified here.

Immediately afterward, `0x70A9A` clears count A5+`0x16E9`, retaining the staged
bytes. There is no status read or completion wait in the executed path. Two
tests initialize synthetic status `0xFFFFE802` to 0 and 255 and obtain identical
twenty register writes, zero status reads, and count zero. The MMIO page is
inert emulator memory, not a peripheral model. These tests establish software
control flow, not bus transmission, acknowledgement, or physical timing.

Thus all three conditions can hold before physical completion is established:
receive dequeue returns zero, response pending is cleared, and TX software
count is zero. No one of these, or their conjunction, is a proven host-visible
boundary for new requests.

## Software discard is narrower than session invalidation

`0x70EA4` clears count+1 bytes of staging RAM and resets the count. With a
synthetic ten-byte frame, the native routine clears eleven bytes. It does not
access peripheral registers and leaves the Mode 23 pending bit, six-byte
response body, and receive record unchanged. This routine cannot stand in for
controller-wide cancellation or a physical TX drain.

## Status handling remains unidentified as completion

Static inspection of `0x70AA8..0x70C9A` shows status/data consumption at
`0xFFFFE802/803`, receive accumulation and calls into `0x23428`. It does not
justify labeling an observed status bit as a Mode 23 transmit acknowledgement.
`0x70CE0..0x70E30` also reads status bits, updates counters/flags, and can build
and submit `08 FF 18 03`. It is not safe to treat an arbitrary return from that
routine as successful transmission. Those status branches were not emulated;
interrupt delivery, peripheral semantics and timer cadence remain unknown.

## Validation and consequence

Three native submission/discard cases pass. Six Python identity/report tests
cover the accumulated Mode 23 coverage, boundary and submission artifacts.
Existing production C# offline correlation tests pass, including the 10,250
supplemental dwords. These are offline checks only.

The current evidence rules out software-queue emptiness, local pending/count
clearing, and a generic follow-up query as sufficient session boundaries. It
does not prove that ordinary serialized reading fails. A bounded freshness
claim still requires a verified transmit-completion/invalidation mechanism and
the corresponding adapter/USB drain behavior. The next useful trace is the
callers and semantics of the peripheral status handlers, before assigning any
status bit a completion meaning or choosing a delay.

No reader range, retry policy or write gate was changed. The remaining 41,000
bytes have not been acquired; broader live reads and live writes stay disabled.
