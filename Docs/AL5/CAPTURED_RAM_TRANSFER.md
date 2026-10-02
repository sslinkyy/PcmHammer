# Captured RAM-loader transfer contract

The decoded saved traces contain 16 Mode `0x36` request candidates across 17
files: twelve in read traces and four in write traces. All match the length,
RAM bounds and byte-sum checksum established by the existing offline boot
handler at `0x3074`. See [boot RAM-transfer behavior](BOOT_RAM_TRANSFER.md) and
the [captured comparison report](CAPTURED_RAM_TRANSFER.json).

## Write-loader observations

Four write traces contain identical 1590-byte payloads with SHA256
`b545d9b2d078662466ab32d9cdeb5b3c38c840135e8aeca09f33760ec66780fa`.
Their address is `0xFF9000`, end-exclusive address `0xFF9636`, and subtype
`0x80`. Length equals the captured payload length; the trailing byte-sum equals
the sum over subtype, length, address and payload. The range and alignment satisfy
the boot handler's literal bounds. No physical-layer or USB-wrapper checksum
has yet been verified by this comparison.

Subtype `0x80` requests calling the uploaded address in the offline handler.
These captures therefore expose an execute-capable RAM-loader transfer, not a
calibration payload or an established flash algorithm. Each has two preceding
`0x74/0x44` response candidates, consistent with the already emulated Mode
`0x34` arming response. That consistency does not prove the complete physical
application-to-boot transition or its storage side effects.

No subsequent Mode `0x76` response candidate appears in these four traces.
That observation is not a failure diagnosis: execution can change which code
handles subsequent communication. Later services remain listed as metadata in
the report, without assigning successful programming or recovery semantics.
The fifth write trace has no captured Mode `0x36` request under the current
wrapper interpretation. All flash outcomes remain unknown.

## Static entry, not execution

[The bounded entry disassembly](CAPTURED_LOADER_ENTRY_STATIC.json) starts with
interrupt-mask setup, stack assignment to `0xFFA7FE`, hardware-register writes
and a receive/poll loop. It records only the first 160 bytes as instruction
observations, with source/window hashes; raw loader bytes remain in ignored local
files. Calls beyond that window, the dispatcher, flash routines and table data
still require analysis. No uploaded loader bytes were executed, even in an
emulator, and no live transfer occurred.

## Validation and next work

`Tools/AL5/analyze_trace_transfers.py --trace <saved-AL5-HTX> --trace <another>
--output <redacted-report>` compares saved request metadata with the existing
contract. It has no transport, execute option or packet builder. The report
hash-links the earlier boot emulator evidence. Tests cover mismatched lengths,
bad sums, odd/out-of-range addresses, captured write-payload identity, expected
arming responses and preservation of the planner's closed write gates.

Next trace the captured loader dispatcher and every flash-related call offline.
Compare its command fields and responses with the decoded traces, identify
actual erase/program geometry and collateral handling, then build a simulated
transport from verified observations. Matching an upload contract does not
justify sending it to the only TCM. Calibration programming, physical recovery
and live readiness remain false; the direct reader is unchanged.
