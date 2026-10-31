# Integrated captured-write rehearsal

Update: [reader coverage and vehicle setup/cleanup](READER_COVERAGE_SETUP_CLEANUP_20261030.md)
extends the original selected-phase replay below. Security and broadcasts are now
included as observations; adapter-local setup remains outside the replay.

`AL5CapturedWriteRehearsal` joins the previously separate captured programming
session to boot/loader, erase, finalization and saved-file verification. It is
production library code with no transport reference, packet builder, timer,
security sender or live enable switch. The working Mode 23 reader and unconditional
AL5 write rejection are unchanged.

## Selected observation sequence

The three successful captured writes each pass the same selected sequence:

1. Two `34` request / `7444` response pairs.
2. A 1,590-byte loader transfer to `0xFF9000`, subtype `80`, with exact envelope
   length, address, byte sum and caller-pinned payload SHA256 checked.
3. Loader OS query `3C 0A` and the captured response for OS 15184109.
4. Erase request `36 EE` and response `76 00 EE`.
5. The existing 192-block capture session, retaining checksum-error and no-reply
   repeats without advancing a rejected block.
6. Finalization request `36 FF` and response `76 00 86`.
7. `AwaitingSavedVerification`, not write completion.

The loader payload SHA256 is the same in all three captures:
`b545d9b2d078662466ab32d9cdeb5b3c38c840135e8aeca09f33760ec66780fa`.
No loader bytes are committed or executed. The OS reply after upload is an
observed identity exchange, not independent proof of loader execution.

The file exporter records selected ordinals and excluded binary-record counts.
Security exchanges, broadcasts, other identification and cleanup traffic are
explicitly excluded from this selected-phase rehearsal. It is not a complete
replacement for EFILive session establishment. Authorization remains unproven
by this replay API, despite the earlier successful EFILive operations.

## Failure and verification semantics

Out-of-order or malformed input is rejected without silently advancing. Pinned
loader mismatch cannot enter erase. Observed negative erase/finalize status and
negative service responses stop the attempt. Explicit interruption closes the
attempt at any phase; it cannot resume. The program sub-session retains its
existing exact-pending-request rules. Captured calibration bytes must match the
validated candidate before entering finalization.

`CompareSavedCalibration` can establish equality to a supplied saved calibration
BIN after finalization. It leaves the rehearsal awaiting verification because
that BIN lacks collateral and the final marker. A mismatch stops the attempt.

`VerifySavedSnapshot` requires the complete 98,304-byte snapshot and an explicit
40,998-byte independent collateral reference. The captured collateral must also
match the supplied reference. The existing workflow checks calibration,
collateral and `4AFC` marker. Exact files yield `SavedImageVerified`; that name
describes the supplied files only. No timestamp, controller identity, physical
readback provenance or recovery capability is inferred. All live readiness and
physical qualification properties remain false.

The captures transfer only 98,302 bytes, so the rehearsal never appends a marker
to make captured bytes masquerade as a physical snapshot. Complete-marker
verification is tested only with explicitly synthetic fixtures. The current
calibration-only backups cannot close this full-snapshot gate.

## Validation

[Evidence metadata](CAPTURED_WRITE_REHEARSAL_20261030.json) records source hashes,
selection counts and production implementation identity. All three private
corpora replay through production C# (427, 440 and 434 selected observations),
with 192 positive block replies and 15, 20 and 19 checksum errors respectively.

Tests cover 11 observed interruption boundaries per capture, premature
finalization/verification, wrong loader identity, negative erase/finalization,
calibration-only non-completion, synthetic full-snapshot success, and damaged
marker rejection. Exporter tests cover order, explicit exclusions and missing
or duplicate loaders. The library build passes with three pre-existing async
warnings; all 210 live-write gate combinations still fail before vehicle access.

Raw corpora and proprietary data remain ignored in `LocalOnly`. No vehicle,
adapter or EFILive process was accessed during this implementation.
