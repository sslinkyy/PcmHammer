# Existing AL5 trace containers

This initial inventory is historical. Subsequent static stream analysis decoded
all 17 existing AL5 files; see [saved-container decoding](TRACE_DECODE.md).
The narrow probe results below remain valid, but the actual transform also uses
an additive byte step. Programming completion remains unverified.

Five September 17 AL5 calibration-write trace files already exist in the user's
local EFILive V8 Trace folder. A September 30 AL5 read trace provides a larger
format comparison. Their originals remain outside Git; the
[metadata inventory](EFILIVE_TRACE_INVENTORY.json) records filenames, sizes and
SHA256 hashes without raw trace contents, VINs, license identifiers or payloads.

The write files are 39,894 to 41,994 bytes, while the comparison read trace is
407,283 bytes. All six share the same first four bytes by hash. Their whole-file
entropy is approximately 7.994 to 7.998 bits per byte. This is compatible with
encoded/compressed data, but does not establish encryption or its algorithm.
Literal known direct-read request/response prefixes were not found. Their absence
does not prove those operations did not occur inside the containers.

The bounded probe tests standard zlib headers at offsets 0 through 255 after
each fixed byte rotation and XOR key. It limits decoded output to 1 MiB and
requires a complete nonempty stream consuming the remaining input. No complete
stream was found for any of these six files. This excludes only the tested
format combinations: other compression, framing, offsets, byte transforms and
cryptographic containers remain unresolved. No packet sequence has been decoded.

## What the filenames establish

EFILive documents `R` as read, `W` as calibration flash and `F` as full flash.
The documented naming order and observed local order differ, so the inspector
accepts both mode/controller orders. These are filename-derived operation labels,
not decoded records or completion status. EFILive saves traces for read/flash
processes and troubleshooting; a `W` trace may belong to an unsuccessful attempt.
Neither file size nor a neighboring read proves a successful program operation.
See [EFILive V8 trace documentation](https://service.efilive.com/kb/articles/v8-trace-files)
and the [V8 reference, Trace Files and Appendix D](https://download.efilive.com/Documentation/EFILive%20V8%20Reference.pdf).

## Reproduction and next step

Run `Tools/AL5/inspect_trace_containers.py --trace <explicit-local-AL5-trace>
--trace <another-trace> --probe-zlib --output <metadata-report>`. It reads bounded
saved files only and reports hashes of any synthetic/common-compression matches;
it never exports decoded payloads or generates vehicle packets. Synthetic tests
verify the probe actually recognizes an encoded complete stream and rejects
output exceeding the limit. Even a compression match does not mark the container
or protocol as decoded.

Next establish the container's actual framing/decoding method or obtain an
interpreted export of these existing traces through documented EFILive support.
No support message was sent. Validate decoded records against the known AL5 read
path before interpreting write traffic. Then distinguish session/loader traffic,
erase/program addresses, acknowledgments and actual completion. Do not invent
those fields from a filename or infer them from the PCM protocol.

The planner hash-links this inventory and keeps format decoding, programming
transport and flash outcomes explicitly unverified. All write gates remain closed.
A new flash is unnecessary for this investigation; no hardware or installed
EFILive executable was used to produce the inventory.
