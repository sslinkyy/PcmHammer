# GT simultaneous E54 read capture, 2026-10-29

The explicit `--all-sources` profile received requests and replies together at
configured VPW 4x while AutoCal completed an E54 read in 1:59. All 128 addressed
data blocks were captured intact. **The capture is incomplete:** three replies
present in EFILive's host trace are missing from the GT log. This profile must
not be treated as a lossless programming capture.

## Observed result

The user confirmed the isolated E54 bench setup and ignition ON before the
read. GT's full five-filter readbacks matched the experimental profile before
LISTEN ONLY was enabled and separately verified. No flash operation ran.

GT recorded 393 frames with valid physical VPW CRCs. The defined HTX window
contains 392 messages: 132 host requests and 260 ECM replies. The GT capture
contains all 132 requests and 257 of those replies, plus four extra frames.

- Missing loader acknowledgment: `6C F0 10 76 80 78`, once.
- Missing block acknowledgment: `6D F0 10 75 01 54`, twice. Unique request/data
  anchors place the absent acknowledgment observations at `0x025000` and
  `0x043000`; both matching data responses are present.
- Extras: `6C FE F1 3F`, `8C FE F0 3F`, `6C 10 F0 3F`, and the post-window
  exit request `6C 10 F0 3C 55`, once each.

The 128 unique data blocks cover `0x000000-0x07FFFD` (524,286 bytes), pass their
additive checksums, and match the preceding reads exactly. Their reconstructed
partial-image SHA256 is
`a53bef772ac8f176296c5923fd3f93ca862ab5148cff292b7fb63eee37dd58ed`.
The final two bytes were not transferred or inferred. EFILive showed all six
segment checksums valid and the user saved `4 lb7 E54_0000.ctz`.

The earlier [source-F0-only capture](AUTOCAL_GT_REQUESTS_20261029.md) contained
129 `8C FE F0 3F` frames; this run contains only one, at startup. There are no
post-block keepalive observations in this all-source log. The E54 loader's
static output path supports investigating this difference, but separate runs
do not prove that every missing keepalive physically appeared on this bus.
The three missing host-trace replies are a direct comparison failure within
this same read. The current evidence does not locate the loss inside firmware,
USB buffering, frame timing, or the electrical bus.

Strict replay consumes all 1,027 capture lines and reconstructs 393 network
and 74 adapter frames, with zero adapter errors, outgoing guard violations or
undecoded bytes. Thus serial framing success and zero adapter error reports do
not establish capture completeness.

## Filter configuration and cleanup

The observed GT filter controls share enable readbacks and mask bytes. The new
option enables exact FROM first, then writes the enabled zero-bit mask last.
It requires these complete readbacks immediately before LISTEN:

```text
TO       00 00 01
FROM     01 10 01
TO RANGE 02 00 00 00
FR RANGE 03 00 00 00
MASK     04 00 00 00 01
```

The command allowlist still excludes network ON and vehicle sends. The new
restoration path restores the exact settings first and the shared mask last,
then compares all nine final GET payloads. They match the original snapshot;
network OFF is separately verified and the adapter's speed setting returns to
1x. Hidden stored-state restoration is explicitly unknown. The user confirmed
ignition OFF, and the 15-second shutdown countdown completed.

```powershell
python Tools/AL5/obdx_capture.py capture --port COM9 --api dvi --speed 4x --all-sources --seconds 240 --output LocalOnly/autocal_all_sources_20261029_01/gt_all_4x.jsonl
```

Raw logs, matching HTX, CTZ and offline receipts remain ignored under
`LocalOnly/autocal_all_sources_20261029_01`; the companion [JSON report](AUTOCAL_GT_ALL_SOURCES_20261029.json) pins
them. The offline comparator keeps missing and extra frames visible. Its
strict result is failure even though all addressed read data was captured.

The next capture investigation must explain the missing short replies and
post-block traffic before claiming complete flash-session monitoring. This
experiment establishes simultaneous reception for this read, not lossless
monitoring, speed-transition continuity, electrical noninterference, AL5
programming or recovery. Live AL5 writes remain disabled.
