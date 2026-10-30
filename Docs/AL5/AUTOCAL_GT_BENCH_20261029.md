# AutoCal V2 / GT E54 bench read comparison, 2026-10-29

OBDX Pro GT received every ECM response in the defined high-speed window of
an AutoCal E54 read: 260 messages matched the independent EFILive host trace
byte-for-byte and in order. This includes all 128 long data responses. The
monitored read completed successfully in 1:59, versus 2:00 with GT network OFF.
This qualifies the tested fixed-4x, ECM-direction read capture. It does not
qualify AL5 flashing, recovery or continuous two-direction monitoring.

## Setup and authority

The user confirmed the isolated E54/LB7 bench ECM, powered harness and Y
splitter. AutoCal V2 supplied the normal EFILive read operation; GT was the
listener. The truck/AL5 was not involved. The baseline left GT physically
connected with its network OFF. Therefore this compares inactive versus
LISTEN ONLY operation, not attached versus physically disconnected hardware.

- EFILive V8: 8.4.93, application build 808 and HAPI/trace build 770;
  AutoCal ACV2 firmware 2.08.221.
- GT: firmware 1.0.2.0, hardware 1.0.0.0, DVI over COM9 at 115200 baud.
- ECM: E54, OS 15189044, hardware 12209950, calibration ID 15189043.
- GT capture: VPW fixed 4x, FROM `10`, CRC validation/display and timestamps ON,
  LISTEN ONLY `02` confirmed by separate readback; bounded to 300 seconds.
- GT's client sent only allowlisted adapter-local commands. AutoCal performed
  its standard read sequence, including security access, RAM read-loader
  transfer and speed negotiation. No flash erase/program operation was started.

## Read and capture results

The baseline host trace contains 129 block requests and 128 data responses.
One request at `0x021000` was retried after timeout. The monitored trace contains
128 requests and 128 data responses, with no duplicate block requests. The
other timeout labels occur in setup/drain/cleanup; they are not failed data
blocks. A single pair of successful reads does not establish a failure rate
or prove absence of electrical interference.

Both traces contain 128 contiguous blocks covering `0x000000` through
`0x07FFFD`, totaling 524,286 bytes. All block additive checksums pass. Every
covered byte matches between the two reads and the saved October 15 MT09 v3
image. The final two bytes at `0x07FFFE-0x07FFFF` were not transferred; they
are neither filled from the old image nor claimed verified. EFILive's baseline
summary marked all six segment checksums valid. The user's saved baseline
container is retained privately as `baseline_LB7_E54_0000.ctz`.

The GT log contains 260 ECM-originated frames: 128 data blocks, 128 block
acknowledgments and four other session/loader replies. Physical VPW payload
lengths, including the final CRC byte, are 130 x 7, 1 x 8, 1 x 10, 1 x 4107
and 127 x 4109 bytes. All 260 CRC-8 SAE J1850 checks pass independently
(polynomial `1D`, initial `FF`, final XOR `FF`, nonreflected).

For comparison, only the GT's physical VPW CRC byte is removed. The remaining
messages match all 260 expected ECM responses in order, from the first reply
after the host trace's A1 speed-start request through the final data block.
There are zero missing, extra or reordered messages relative to that trace
window. Identical short acknowledgments have no unique identity, so this cannot
exclude offsetting physical loss and duplication. All 128 addressed data blocks
appear exactly once. Wrapper direction is inferred from the recorded
host/device wrappers; the host trace is not an independent electrical waveform
recording.

Strict replay reconstructs 260 network frames and 57 adapter frames from all
837 JSONL lines, with no adapter errors, outgoing guard violations, undecoded
bytes or incomplete source consumption. Capture exits successfully, confirms
network OFF, and restores all nine saved settings; speed returns to 1x.

## Evidence and reproduction

The companion [JSON report](AUTOCAL_GT_BENCH_20261029.json) pins the private
logs, analysis helpers and receipts. Raw logs and tune binaries remain under
ignored `LocalOnly/autocal_usb_20261029_bad23509`; no user binary is committed.
The existing production capture/replay code was used without changing its
command allowlist or the AL5 write gate.

The actual capture invocation, after manual setup verification, was:

```powershell
python Tools/AL5/obdx_capture.py capture --port COM9 --api dvi --speed 4x --source-id 0x10 --seconds 300 --output LocalOnly/autocal_usb_20261029_bad23509/gt_ecm_4x.jsonl
```

`capture_started` and LISTEN ONLY readback were observed before starting the
AutoCal read. Offline replay uses the saved file and opens no serial port:

```powershell
python Tools/AL5/obdx_capture.py replay --input LocalOnly/autocal_usb_20261029_bad23509/gt_ecm_4x.jsonl --output LocalOnly/new_replay.jsonl
```

## Remaining boundaries

The fixed-4x listener deliberately misses 1x startup/return traffic, and FROM
`10` excludes AutoCal requests. No automatic transition following or simultaneous
two-direction filter is established. The configured speed and successful
traffic correlation support this session's 4x reception; physical pulse timing,
IFR behavior, loading and absolute electrical silence were not scope-measured.
Malformed-signal handling, saturation/overflow, disconnect behavior, other
controllers and actual flash capture remain unqualified. Live AL5 writes and
recovery readiness remain disabled.
