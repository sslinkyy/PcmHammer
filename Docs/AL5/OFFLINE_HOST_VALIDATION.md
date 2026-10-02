# Offline block inspection and batch preflight

`Tools/AL5/host_validation.py` turns the captured-loader parser findings into
checks on supplied synthetic or captured bytes and a logical RAM batch model.
It has no packet constructor, adapter import, erase routine, file output or live
transport. The planner hashes the implementation and retains its write gates.

`inspect_block(frame)` requires a complete module-addressed Mode `0x36` subtype
`0x00` block, exact declared length and block byte sum, nonzero even payload,
word-aligned destination and the entire range within calibration
`0x8000–0x15FD7`. Global destination, erase/finalize/delay/upload subtypes,
truncated headers, checksum errors and range overruns are rejected. This is an
offline acceptance policy, not a verified physical frame or maximum block size.

`simulate_batch(frames, baseline)` validates the calibration baseline and its
native checksum, then preflights every block before any logical edit. Any invalid
later block, empty batch, duplicate or overlapping range leaves the modeled
memory unchanged. Duplication is rejected because retry semantics remain
unverified. The baseline is caller-supplied; its live provenance is not established
by this model. The existing write planner separately checks the expected hash.

Synthetic interrupted-word faults apply one word; timeout and negative-response
faults permit the whole faulting block to have changed before stopping. These
are deliberately conservative possible outcomes, not recovered physical failure
semantics. A failure does not imply unchanged memory, and automatic retry remains
false. The output includes a result hash and native-checksum validity without
exporting a BIN or frame bytes. Synthetic completion still keeps readiness and
physical programming, acknowledgment and block-size verification false.

Seven focused tests cover the observed short/odd/zero-length hazards, full-range
preflight, rejected destructive routes, corrupted block sums, duplication,
overlap and failures after possible edits. They also verify that a malformed
second block prevents the first edit and that modeled completion can leave the
native checksum invalid. No emulator or vehicle is needed for these tests.

The logical model does not erase sectors or model NOR timing. It does not prove
preservation of the conditional 41,000 collateral bytes or persistent banks.
Next connect evidence-derived session and acknowledgment rules to a simulated
transport, while retaining independent physical framing, flash, preservation
and recovery gates. The existing direct reader and C# AL5 write rejection remain
unchanged.
