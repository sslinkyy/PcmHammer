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

Capture first requests OFF and verifies readback, selects VPW, disables the four
destination/source exact/range filters, sets an enabled zero-bit header mask,
selects the caller's fixed 1x/4x speed, enables CRC validation/CRC display and
device timestamps, then requests **LISTEN ONLY (2)** and verifies its readback.
Each configuration change requires both an echo acknowledgment and a separate
matching status query before listening is enabled. It requests OFF and verifies
readback on completion, cancellation, or configuration failure. A failed
cleanup acknowledgment is recorded as an unknown adapter state and is an error,
never a successful cleanup. Do not retry after such a failure without inspecting
the adapter state. Software guards do not independently prove physical silence.
After verified network OFF, capture restores the recorded timestamp, all five
VPW header filters, CRC-validation policy, CRC-display and speed settings, with
checked acknowledgments and status queries. Restoration failure is an error. This protects the
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
py -3.13 -m unittest -v test_obdx_capture test_obdx_speed

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

`probe` verifies network OFF before changing each selected adapter setting's
Boolean flag. It preserves filter IDs/ranges/masks, checks each alternate-value
readback, restores the saved value and
rechecks network OFF. It neither enables reception nor selects LISTEN ONLY.
It tests configuration round trips, not actual 1x/4x reception or physical silence.
Use repeatable `--setting <name>` arguments to check only named settings; omit
them to check all nine settings. A mismatch stops the probe after restoration.

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

## Reconnected GT: real adapter-local checks

The same COM9 USB device reappeared. Its response to ELM identification was again
the checksum-valid DVI error `7f0241013c`; subsequent explicit DVI identification
confirmed GT firmware 1.0.2.0. Network OFF was verified before setting changes.

Real alternate-value/readback/restoration checks passed for eight settings:
timestamp enablement, destination filter enablement, source filter enablement,
destination range enablement, source range enablement, 1x/4x speed selection,
CRC validation and CRC display. These observations establish adapter settings
only. They do not establish frame reception at either speed or physical silence.

The mask-filter check **failed**: setting `0400ff0000` received an echo with that
payload, but a separate GET returned `0400ff0001`. The original `0400ff0001` was
restored and read back; network remained `0200` (OFF). This could be a setter or
query implementation issue; the evidence does not identify which. No alternative
mask values or firmware updates were tried.

Capture initially failed before requesting LISTEN ONLY when this discrepancy occurred.
This was the initial fail-closed response to the disable-flag discrepancy. The
follow-up below replaces mask disabling with a separately verified neutral mask.
The previous echo-only configuration checks were insufficient to establish filter
state. All capture settings and restorations now use separate matching readbacks.
An offline test reproduces the observed echo/GET disagreement and proves no
LISTEN ONLY command is issued. Twenty-four offline tests pass.

Original reconnected probe/replay records remain in `LocalOnly/OBDXCapture/`.
The complete probe stops at the mask discrepancy, preserving earlier successful
checks; CRC validation was checked independently afterward with `--setting
crc_validation`. Logs and replay retain the failed outcome instead of converting
it into a successful capture. No vehicle messages, reception enablement, reset,
firmware update, speed change in a controller or programming was performed.
The [bounded local-check report](OBDX_LOCAL_CHECKS_20261011.json) pins the source
log SHA256 values and outgoing-command audits without publishing device serials.

## Mask investigation and capture fix

The manufacturer's reference explains that `00 00 00` mask bits require none of
the received header bits to match (section 2.31), and specifies the same three
mask bytes in the DVI mask setting (section 3.11.5). Capture therefore does not
need the GT's unresolved mask-OFF flag: it can use `0400000001`, with an exact
separate readback, while disabling the other four filters.

`mask-probe` performs three bounded adapter-local cases with network OFF and
restores the exact original mask after each case. On this GT firmware 1.0.2.0:

- Original mask with OFF: `0400ff0000` echoed, GET `0400ff0001`.
- Zero bits with OFF: `0400000000` echoed, GET `0400000001`.
- Zero bits with ON: `0400000001` echoed, GET `0400000001` (exact match).

These observations show that mask bytes can change and are reported correctly,
while the returned flag remains ON for these cases. They do not establish whether
the setter ignores OFF, the getter misreports the flag, or some other firmware
rule applies. The tool preserves the distinction; it does not normalize a
mismatched flag into a successful setting check.

Capture now requests the enabled zero-bit mask and verifies the entire payload.
Any nonzero mask or other readback mismatch still fails before LISTEN ONLY.
The existing original-mask restoration remains exact. No firmware change or
vehicle service is needed for this configuration fix.

```powershell
py -3.13 obdx_capture.py mask-probe --port COM9 --api dvi --output mask_probe_new.jsonl
```

Twenty-six offline tests pass, including a model of the observed flag replies,
successful zero-mask capture configuration, refusal when mask bytes fail to
change, and stopping when original-mask restoration fails. The real mask probe
was run with the network OFF throughout; neither capture nor LISTEN ONLY was run.
The original mask `0400ff0001` and network `0200` were read back after all cases.
Actual receive coverage, dropped frames, rate changes and physical filtering
behavior still need separate reception validation. The source-pinned
[mask report](OBDX_MASK_CHECKS_20261011.json) records the cases and outgoing audit;
raw logs remain ignored under `LocalOnly/OBDXCapture/`.

## Offline speed-transition handling

Replay now annotates recorded speed settings and generic PcmHammer negotiation
candidates, preserving the distinction between adapter configuration, echoes,
separate GET readbacks and unknown physical bus speed. It marks possible capture
gaps without switching anything. See [speed evidence and validation](OBDX_SPEED_TRANSITIONS.md)
for framing rules, source scope and limitations. Forty-five offline tests pass;
actual receive/transition behavior and live automatic following remain unproven.
