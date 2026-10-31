# Captured AL5 checksum-error and repeat behavior

This follow-up correlates the three previously saved successful EFILive writes.
No adapter, vehicle or application was opened. [Redacted evidence](CAPTURED_WRITE_RETRIES_20261030.json)
pins HTX, GT and parsed USB-envelope inputs. Detailed per-cycle record ordinals,
GT line numbers, hashes and host-relative times remain in each private session's
`retry_correlation.json`; `retry_replay.txt` contains calibration bytes and stays ignored.

## What the captures establish

There are 576 completed block cycles across sessions 02, 04 and 05. Each cycle
ends with `760073` and the full request bytes match between host and GT. Host
requests within each repeated cycle are byte-identical, at the same address.
The exact program wrapper occurrences, including repeats and replies, also
occur in the saved USB-envelope corpus. USB decoding retains its previously
documented packet-size hypothesis; this is not a fresh USB descriptor proof.

54 cycles contain `request -> 760077 -> identical request -> 760073`:
15 in session 02, 20 in session 04 and 19 in session 05. GT independently shows
`11-byte request -> 760077 -> 524-byte request -> 760073` for every one.
The short request contains the Mode 36 header, subtype zero, declared count
512, address, and only the first data byte. Its 12th physical byte validates
as a J1850 CRC. It is therefore not merely a full-length request with an
incorrect final application checksum in this GT record. All 54 short prefixes
match the full host requests, whose application sums and USB outer CRCs validate.

The first `760077` arrives 26–28 ms after the host request timestamp. EFILive
repeats the identical request 101–119 ms after that reply; the subsequent positive
reply arrives 411–437 ms after the repeat. Times are differences within HTX,
not synchronized measurements between USB, GT and host clocks.

Eight additional cycles have `request -> identical request -> 760073`, with no
intervening host reply: 2, 5 and 1 respectively. Host repeat intervals are
1428–1464 ms. GT contains only the eventual full request and positive reply in
those cycles. The observations are consistent with a timeout path but do not
prove why the first request is absent from GT or whether its reception began.

## Interpretation and limits

The native loader model associates `760077` with application byte-sum failure
before word programming. The newly observed short frames offer a concrete
explanation consistent with that path. They do not establish precisely how the
loader treats missing bytes, or whether adapter firmware, transmit buffering,
bus interaction or another factor produced the short frame. A valid VPW CRC
alone cannot attribute its sender or prove electrical non-interference.

These are successful repeats after checksum rejection and no-observed-reply
conditions. They are not demonstrations of interrupted erase, partial flash
failure, stack unwinding, reset recovery or safe automatic retries. The measured
delays are observations, not qualified PcmHammer timeout constants.

## Offline implementation

`AL5CapturedProgramSession` consumes saved requests and exact three-byte loader
reply bodies. It uses `AL5CapturedProgramImage` validation and owns the pending
request. It requires contiguous 512-byte blocks and the observed 510-byte tail.
A checksum rejection retains that exact pending request without advancing the
address or acknowledging any bytes. A following identical request is recorded
as an observed repeat; a changed request is rejected atomically. An identical
request before a reply is separately counted as a no-reply repeat.

Only a `760073` with one pending request records that block as acknowledged.
An orphan/duplicate reply is rejected. Other statuses stop the attempt, and it
cannot resume. Complete acknowledged captured bytes may be compared with explicit
references through the existing offline workflow; no final marker or physical
flash snapshot is fabricated. This replay contract does not prove that a late
wire reply can be safely paired during a live session.

No transport, timer, packet builder or retry sender is added. Live writing,
automatic retry and physical verification remain false. The original native
model coordinator retains its stricter stop rules and is not silently resumed
by a captured checksum-error sequence.

## Validation

- Replayed all three real sessions through production C#: 192 positive replies
  each, exactly 15/20/19 checksum-error repeats and 2/5/1 no-reply repeats.
  Reconstructed hashes match the previous independent Python capture analysis.
- Python tests cover short-frame correlation, duplicate USB occurrence accounting,
  changed-request ambiguity, orphan replies and incomplete traces.
- C# checks cover pending identity, negative-result non-advancement, changed-request
  rejection, orphan acknowledgements and terminal failures, alongside the existing
  capture-image tests.
- Shared library build passed with the existing three async-without-await warnings;
  the production write gate still rejects all 210 combinations before vehicle access.

Next useful work is tracing AutoCal's handling of these complete USB requests
against its short VPW outputs, and extending offline erase/finalize rehearsal
without conflating acknowledged blocks with physical readback or recovery.
