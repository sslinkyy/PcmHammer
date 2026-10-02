# Captured write-loader dispatcher — static only

The saved 1590-byte write-loader contains erase and word-program routines.
[Static instruction observations](CAPTURED_LOADER_STATIC.json) omit raw payload
bytes and two non-code intervals. No loader code was executed. This extends the
earlier entry-only analysis, not a live programming implementation.

## Dispatch and flash calls

The dispatcher accepts header priority `0x6C`/`0x6D`, destination `0x18`/`0xFE`
and source `0xF0`/`0xF1`. Service `0x36` routes on subtype:

- `0xEE` reaches `0xFF934A`: a flash-ID check, followed by erase calls with
  addresses `0x8000` and `0x10000`. This route bypasses the block byte-sum branch.
- `0x00` reaches the length/address/payload parser at `0xFF9130`. A BE16 byte-sum
  comparison precedes word programming at `0xFF93EA`. The program routine issues
  unlock/program command words, writes one word, polls readback, subtracts two
  from the byte count and advances the destination by two.
- `0xDB` uses the same byte-sum branch but takes a delay path instead of the
  word-program call. A positive status is not sufficient to identify a flash write.
- `0xFF` uses pointers from `0x20046`, checks a BE16 sum including a stored final
  word, then programs `0x4AFC` at `0x1FFFE`. Its meaning beyond this static sequence
  is now bounded by the saved pointer table to the calibration range. This sum
  check does not recompute the native CRC; see `LOADER_GEOMETRY_FINALIZATION.md`.

The flash-ID routine checks words `0x0001` and `0x2258` through a command-mode
sequence, without proving the currently installed chip's identity. The erase
routine polls a toggling bit and an error bit. The bulk program path has an upper
address comparison at `0xFFFFE`; no lower-address or alignment guard appears in
that routine. Zero/odd-length and malformed-buffer cases now have bounded
observations in `LOADER_PARSER_EMULATION.md`; later word iterations remain
unexecuted. Static command addresses are not physical sector sizes.

The status builder at `0xFF9518` sets service `0x76`, a zero byte and a status
byte. Word-program failure and address-bound branches map to status values through
`0xFF94A8`. The subtype-`0x00` parser sends `0x77` for a bad block sum and `0x73`
after the successful branch. These are static observations, not verified wire
acknowledgments. Loader timeout/reset branches and collateral preservation are
also unverified.

## Existing capture census

[The request census](CAPTURED_LOADER_REQUESTS.json) checks all five saved write
traces for the supported host-wrapper shape, including global destination
`0xFE`. Four contain only subtype `0x80` among Mode `0x36` requests; the fifth
contains no Mode `0x36` request. No `0xEE`, `0x00` or `0xFF` command is observed.
This does not prove the absence of destructive activity: interface checksums,
capture completeness and other wrapper shapes have not been established.
The trace filename cannot establish successful programming.

`Tools/AL5/inspect_loader_requests.py --trace <AL5-W-HTX> --trace <another>
--output <report>` reproduces the census without exporting payloads or packets.
Synthetic tests check detection of global-address destructive commands. Saved
evidence tests link static hashes and key instruction observations to the report.

Saved finalize pointers and conditional AMD sector geometry are now documented
in `LOADER_GEOMETRY_FINALIZATION.md`; physical chip identity remains unverified.
Next build a model of the loader parser
with flash/MMIO calls trapped. Do not replay these commands or upload the loader.
The planner links this evidence but keeps erase scope null, readiness false and
all packet lists empty. The direct reader remains unchanged.
