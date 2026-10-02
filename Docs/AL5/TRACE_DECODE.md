# Saved AL5 trace container decoding

All 17 existing AL5 HTX files now decode offline. This resolves the container
obstacle in the earlier inventory; it does not establish a working live writer.
The originals and decoded binary payloads remain outside Git. The committed
[report](EFILIVE_TRACE_DECODE.json) contains source/decoded hashes, record counts
and redacted candidate message sequences without VINs, text logs, keys, tune
contents or loader payloads. No installed EFILive executable was run.

## Transform and framing

Static inspection of the installed `EFILive_Hapi.exe` stream constructor and
read routine found a byte transform:

1. Subtract `0x87` modulo 256.
2. Rotate the result left by three bits.
3. XOR with `0xA5`.
4. Decompress as standard zlib.

The [bounded static evidence](TRACE_STREAM_STATIC.json) records the executable
hash and instruction observations at `0x7C3B70` and `0x7C3BB4`, omitting raw
executable bytes. Every saved AL5 file produces a complete zlib stream with no
trailing input. This additive step explains why the previous rotation/XOR-only
probe did not decode them. The historical inventory remains preserved.

The observed decoded signature is `01 00 02 00 01 00 05 00`. Records begin after
a 1024-byte header. An 18-byte record header has little-endian fields: double
timestamp, one-byte channel, two-byte category, two-byte subtype, one-byte kind
(`T` or `B`), and four-byte payload length. This layout consumes every decoded
file exactly, from 187 to 4593 records. Timestamp interpretation as a day count
is used only for relative elapsed milliseconds; absolute times are not exported.
Header metadata and text payloads are omitted from the report.

Two observed binary wrapper shapes contain AL5 message candidates at offset 12:

- Channel 1, wrapper prefix `01 54`, little-endian length at offset 10 and total
  length equal to message length plus 14: host-transmit candidate.
- Channel 2, prefix `01 52`, the same length location and total length equal to
  message length plus 15: device-receive candidate.

Those direction labels are inferences from captured shapes, not an independent
physical bus recording. Wrapper trailers/checksums remain unverified. Other
binary records are retained only in counts, not forced into this interpretation.
Candidates must start with established AL5 address prefixes `6C 18 F0`,
`6D 18 F0` or `6C F0 18`. The committed sequence keeps only these three address
bytes plus the service byte, message length, relative time and whole-message
hash. It cannot be executed as a packet plan.

## Write-trace observations

The five `W` files contain 224, 187, 204, 203 and 202 records, with 32, 12, 32,
31 and 31 candidate AL5 messages respectively. Four show identity/security
traffic, two Mode `0x34` requests and corresponding `0x74` response candidates,
then one 1602-byte Mode `0x36` request candidate. The 15:20:44 file instead has
identity/seed requests without matching AL5 reply candidates under this layout.

These observations distinguish captured preparation/transfer traffic from a
successful calibration write. They do not prove what the large payload does,
that any erase/program command completed, or that the trace contains every bus
message. Firmware comparison, wrapper checksum validation, response semantics
and capture completeness are the next steps. Flash outcome stays unknown.

## Validation and reproduction

`Tools/AL5/decode_trace_containers.py --trace <explicit-local-AL5-HTX>
--trace <another-HTX> --output <redacted-report>` requires supported saved-file
names and headers. Input and decompression are bounded at 16 MiB; truncated,
trailing, oversized, unsupported and malformed record data are rejected.
Synthetic tests cover transform roundtrip, wrapper lengths, corruption and
decompression limits. Captured-file regressions check exact record/message
counts and match all six original inventory hashes. The suite contains 79 tests.

The file-only planner now hash-links the successful saved-container decoding,
while programming transport, erase/program protocol and flash outcomes remain
false/unverified. Erase scope is null and packet lists remain empty. The reader
and C# AL5 gate remain unchanged. Do not perform another flash to obtain a trace
until the existing captured payloads have been analyzed.
