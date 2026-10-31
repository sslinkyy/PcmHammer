# AL5 captured calibration writes, 2026-10-30

Follow-up: [checksum-error and repeat correlation](CAPTURED_WRITE_RETRIES_20261030.md)
identifies the short CRC-valid requests preceding every captured `760077` and
replays the resulting block sequences through PcmHammer's offline session model.

Three complete-duration saved EFILive sessions now establish a concrete observed
write exchange. This is file-only analysis of earlier user-authorized EFILive
operations, not a PcmHammer flash or recovery qualification. Source SHA256 values
and redacted counts are in [the evidence report](CAPTURED_WRITE_SESSIONS_20261030.json).
Private HTX, USB, GT, BIN and replay corpus files remain under `LocalOnly/` or the
user's backup directory; no proprietary loader or calibration payload is committed.

## Observations

Session 02 and session 05 transferred the custom PPEI calibration. Session 04
transferred the second-pass calibration, independently read back with Mode 0x23
and matched byte-for-byte to the saved stock reference. All three transmitted
calibration ranges match their corresponding saved 57,304-byte references.

The observed sequence includes identification, seed/key exchange, two `34` /
`7444` exchanges, a subtype-80 RAM transfer to `0xFF9000`, loader identity
queries, `36 EE` / `7600EE`, subtype-zero program blocks, and `36 FF` /
`760086`, followed by application traffic. These are observations, not a ready
to execute script. The analyzer checks outer wrapper CRC and transfer byte sum;
it does not execute packets or import an adapter.

Each capture contains 192 unique address/payload pairs, covering exactly
`0x08000..0x1FFFD` without gaps or conflicting overlaps. There are 191 blocks of
512 bytes and a final 510-byte block at `0x1FE00`. The block crossing `0x15FD8`
contains both calibration and collateral bytes. The transferred collateral
hash is identical in all three sessions. This does not prove it is an independent
pre-erase backup, or that its content is portable to another TCM. The final
marker at `0x1FFFE` is outside the transferred range; it must not be invented
when reconstructing the captured image.

The earlier offline coordinator's 256-byte region-separated layout remains a
model experiment, not this observed wire layout. No global block-size constant
was changed to falsely equate the two.

## Positive replies, error replies and repeats

Each session has exactly 192 positive `760073` replies. Session 02 additionally
has 15 `760077` replies, session 04 has 20, and session 05 has 19. Earlier capture
summaries called the combined `7600xx` count "programming ACKs"; those totals
must not be interpreted as all-positive acknowledgements. The new report
separates statuses explicitly.

The existing native loader analysis associates `760077` with a bad block byte
sum before word programming; see [loader entry](LOADER_ENTRY_PROGRAM_PATH.md).
All saved host request byte sums nevertheless validate. This is consistent with
a receive/delivery problem, but does not identify where corruption occurred.
No firmware change or electrical diagnosis is justified solely by these files.

The host traces contain respectively 209, 217 and 212 program requests, including
17, 25 and 20 repeated identical requests. GT records each of the 192 unique
blocks once in all three sessions. Thus host repeats, negative replies and GT
observations have different counts. Missing GT occurrences cannot simply be
called missing successful writes or USB duplication. Replies carry no block
address; this analysis does not assign every reply to a request or authorize
automatic retry. Interrupted erase, partial programming, loader stack state and
physical recovery remain unproven.

The separate serial-mismatch session 03 contains no observed erase, program or
finalize request in its saved HTX. That is a trace observation, not a universal
claim about all `$0531` failures.

## PcmHammer integration

`AL5CapturedProgramImage` in the shared production library accepts already
captured subtype-zero messages only. It validates header, declared length,
alignment, range and byte sum before committing any evidence. Identical overlaps
are accepted without inflating covered bytes; conflicting overlaps fail
atomically. Incomplete coverage cannot produce an image. Returned images are
owned copies. There is no packet builder, adapter dependency, send callback or
enable switch.

`AssessReference` compares a complete captured image with explicit calibration
and collateral references and feeds the existing offline workflow. It does
not supply a flash snapshot or synthesize the missing marker, so it cannot
satisfy physical verification or resume a stopped session. The existing reader
and unconditional AL5 rejection in `WriteManager` remain unchanged.

`Tools/AL5/analyze_al5_write_capture.py` creates redacted reports and optionally
a private corpus for replay through the production C# decoder. Specify the
reference SHA256 explicitly. Corpus files contain calibration bytes and must
stay local. These are offline decoding fixtures, not send plans.

## Validation and remaining work

- Three real captured corpora decoded by both Python and production C# with
  identical complete-image hashes; reference calibration matches in all three.
- Three Python tests cover real container boundaries, outer and transfer CRC
  failures, status separation, duplicate requests, gaps and conflicting overlap.
- C# tests cover bounds, corrupt byte sums, atomic rejection, duplicate coverage,
  missing-byte rejection, immutable image ownership and the workflow reference bridge.
- Existing 43 offline workflow checks and 210 null-vehicle write-gate combinations
  pass. Shared library builds with three existing async-without-await warnings.

Next work is per-exchange retry/timing correlation across HTX, USB and GT,
followed by a separately typed observed-operation rehearsal. Do not turn a
`760073` body into a completion signal without the pending-operation context.
Successful EFILive sessions do not qualify a PcmHammer writer or recovery path.
All PcmHammer live AL5 writes and automatic retries remain disabled.
