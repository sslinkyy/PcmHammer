# OBDX Pro GT capture-only tool

`Tools/AL5/obdx_capture.py` is a standalone companion to PcmHammer's offline
AL5 tools. It does not use the normal PcmHammer device initialization or alter
the Mode 0x23 reader, UI, or AL5 write gates. Python 3.10+ is required; no
third-party packages are needed. Live USB serial access uses Windows APIs.

## Authority and command boundary

Every outgoing DVI packet goes through an adapter-local command allowlist with
validated payload shapes before
serial write. Vehicle-send commands 0x10 and 0x11, ordinary network-ON mode 1,
resets, firmware updates, unknown commands and generic ELM/hex strings are
blocked. The only ELM operations are `AT@1` identification and `DXDP1` API
selection, after exact GT identity confirmation. There is no reset, automatic
API guessing, automatic command retry, or automatic bus-speed negotiation.

Inspection queries adapter identity/settings and finishes by requesting network
OFF and checking readback. This also disables a network left enabled by another
application. API selection may leave the adapter in DVI mode. Close other serial
applications before opening the tool; it opens the selected COM port exclusively.

Capture first requests OFF, selects VPW, disables all five header filters,
selects the caller's fixed 1x/4x speed, enables CRC validation/CRC display and
device timestamps, then requests **LISTEN ONLY (2)** and verifies its readback.
It requests OFF on completion, cancellation, or configuration failure. A failed
cleanup acknowledgment is recorded as an unknown adapter state and is an error,
never a successful cleanup. Do not retry after such a failure without inspecting
the adapter state. Software guards do not independently prove physical silence.
After verified network OFF, capture restores the recorded timestamp, all five
VPW header filters, CRC-validation policy, CRC-display and speed settings, with
checked acknowledgments. Restoration failure is an error. This protects the
existing reader's expected frame layout and preserves nondefault adapter filters.
Network ON is never restored. Selecting VPW remains the capture protocol choice.

The manufacturer [OBDX VT reference, v1.06](https://obdxpro.com/Downloads/ReferenceManuals/OBDX%20Pro%20VT%20Reference%20Guide%20v2.pdf)
documents the DVI framing, adapter queries, timestamp field, filters, speed
selection and OFF/ON/LISTEN ONLY values (pages 17–29). It is a VT reference,
not proof of every behavior in GT firmware. GT version interpretation follows
the existing `Apps/PcmLibrary/Devices/OBDXProDevice.cs` four-byte format; raw
responses are retained instead of assuming VT identity/capability widths.

## Commands

Run from `Tools/AL5`. Outputs must be new files; existing files are never replaced.

```powershell
py -3.13 -m unittest -v test_obdx_capture

# Adapter-only inspection; DVI is the observed current API on the user's GT.
py -3.13 obdx_capture.py inspect --port COM9 --api dvi --output GT_identity_new.jsonl

# Decode a retained raw binary DVI receive stream entirely offline.
py -3.13 obdx_capture.py decode --input receive.bin --timestamps --output decoded_new.jsonl

# Replay original receive chunks from a saved tool JSONL log, without serial access.
py -3.13 obdx_capture.py replay --input GT_identity_new.jsonl --output replay_new.jsonl

# Adapter-local setting round trips; network stays OFF and each value is restored.
py -3.13 obdx_capture.py probe --port COM9 --api dvi --output GT_probe_new.jsonl
```

The capture command is implemented but has **not been run on hardware**:

```powershell
py -3.13 obdx_capture.py capture --port COM9 --api dvi --speed 1x --seconds 60 --output capture_new.jsonl
```

Do not use this example as a verified programming-capture procedure. Live testing
should start with ordinary traffic/read-only diagnostic exchanges. The capture
command never requests a vehicle service, unlock, speed change in a controller,
loader upload, erase, programming, or reset. Selecting 4x changes only the logger
setting; it does not make the AL5 switch speeds.

## Recording and offline validation

JSONL contains the UTC session start, tool SHA256, adapter-local outgoing bytes,
raw serial receive chunks with host monotonic timestamps, decoded DVI packets,
raw four-byte adapter timestamps, errors and cleanup status. The raw chunks
remain available even when framing fails. CRC bytes remain in the received VPW
payload when enabled; DVI checksums are validated separately. The decoder stops
on corrupt framing rather than inventing resynchronization. Truncated trailing
frames fail the run. It accepts uint16-length 0x09 frames without silently
truncating them to PcmHammer's usual block size.

Timestamp byte order, wrap interpretation, physical CRC behavior, real sustained
throughput and dropped-frame reporting are not independently validated. Host
timestamps describe serial receipt, not the exact time on the bus. The fixed
speed setting cannot automatically follow EFILive's potential 1x/4x transitions.
CRC-invalid frames may be discarded by the adapter before the PC sees them.
No output is described as a proven complete programming capture.

Offline tests use a simulated transport, not a simulated AL5 flash. They cover
the outgoing-command boundary, GT identity checks, adapter-only inspection,
listen-only setup/readback, configuration failure, cancellation, failed cleanup,
checksum corruption, truncation, every split position in a combined short/long
frame stream, the maximum uint16 receive length and raw timestamp preservation.
These tests do not establish real firmware or bus behavior.

`replay` ignores previously decoded rows and reconstructs only original
`serial_rx` chunks. It retains the ending source-line number for fragmented
frames, source host timestamps, original-result status, outgoing-command guard
audit and source SHA256. Verified frames are emitted before a later corrupt frame
fails; partial facts are not discarded. Checksum-valid timestamp-status packets
update the layout for following bytes, including coalesced packets in one chunk.
This follows the documented setting semantics; it is not physical timestamp
verification or automatic VPW speed tracking. Missing source results remain
explicitly unknown, and replay success never establishes capture completeness.

`probe` verifies network OFF before changing timestamp, speed and CRC-display
settings. It checks each alternate-value readback, restores the saved value and
rechecks network OFF. It neither enables reception nor selects LISTEN ONLY.
It tests configuration round trips, not actual 1x/4x reception or physical silence.

## Connected-device observations, 2026-10-11 UTC

COM9 enumerated as an STMicroelectronics USB virtual COM port. The first ELM
identity attempt received `7f0241013c`, a checksum-valid DVI error, and stopped
without reset. An explicit DVI inspection then observed:

- Name: `OBDX Pro GT`; model raw bytes `4754`.
- Firmware: `1.0.2.0`, raw `01000200`.
- Hardware: `1.0.0.0`, raw `01000000`.
- OBD/PC capability fields: raw `0f` each; detailed bit interpretation unverified.
- Selected protocol: `0101` (VPW); speed `0600` (1x).
- Timestamp setting `0300`; CRC display `0800` (both off).
- Network state initially `0201` (ON); adapter-local OFF acknowledged and final
  query returned `0200` (OFF).

Original raw inspection JSONL remains under `LocalOnly/OBDXCapture/`, outside
Git, including the unsuccessful initial attempt and successful OFF verification.
No capture mode, vehicle messages, adapter reset, firmware update, controller
speed switch or AL5 programming was performed. Listen-only mode on this exact
firmware and complete programming/recovery capture remain unproven.

## Follow-up validation

Twenty-two offline tests pass after adding exact filter/CRC restoration, JSONL
replay, source-status preservation and the adapter-local probe. Replaying the
retained successful OFF inspection reconstructed 15 adapter packets from 16 raw
receive chunks, with zero vehicle packets and zero outgoing guard violations.
These are real retained adapter replies, not simulated programming traffic.

The new live local-setting probe could not open COM9 (`WinError 2`). A subsequent
PnP inventory contained no USB virtual COM port for the GT. No probe bytes were
sent and no setting changed. The failed attempt and replay output remain under
`LocalOnly/OBDXCapture/`. Reconnect the GT to complete those adapter-local checks.
Actual listen-only reception, rate/overflow behavior, speed transitions and
programming/recovery capture remain unverified. No speed-follow heuristic was
added on the basis of incomplete vendor documentation.
