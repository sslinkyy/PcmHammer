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
destination/source exact/range filters, sets a zero-bit header mask while preserving its reported flag,
optionally enables the caller's exact `--source-id` filter,
selects the caller's fixed 1x/4x speed, enables CRC validation/CRC display and
device timestamps, then requests **LISTEN ONLY (2)** and verifies its readback.
The explicit diagnostic `--retain-invalid-crc` option instead disables adapter
CRC validation while keeping CRC display enabled; the default remains enabled.
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

The [powered bench battery](DUAL_ADAPTER_BATTERY_20261022.md) established that
an explicit source filter receives traffic on this GT, whereas all-filters-off
received none. For example, `--source-id 0x10` receives ECM-originated frames;
it does not also capture the tester's requests. Exact source/destination
reception is demonstrated at 1x. The [AutoCal/E54 bench read comparison](AUTOCAL_GT_BENCH_20261029.md)
also establishes fixed-4x ECM-direction reception of all 260 responses in the
covered host-trace window, including 128 long data blocks. Unfiltered,
range-filter, continuous speed-transition and full two-direction capture
remain unqualified.

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

The capture command has been run on the confirmed isolated bench with an
explicit exact-source filter. For a new run, first verify the adapter port/API,
bench setup and independent traffic source:

```powershell
py -3.13 obdx_capture.py capture --port COM9 --api dvi --speed 1x --source-id 0x10 --seconds 60 --output capture_new.jsonl
```

Do not use this example as a verified programming-capture procedure. Live testing
should start with ordinary traffic/read-only diagnostic exchanges. The capture
command never requests a vehicle service, unlock, speed change in a controller,
loader upload, erase, programming, or reset. Selecting 4x changes only the logger
setting; it does not make the AL5 switch speeds.

## Recording and offline validation

For an otherwise unchanged bench read, `capture --serial-diagnostics` optionally
records Windows driver status before and after every serial read, including empty
and failed reads. It preserves raw error masks, queue snapshots, read durations
and sequence numbers linking nonempty reads to `serial_rx` records. Polling uses
`ClearCommError`, which clears error flags but does not clear received bytes.
These are sampled driver values, not adapter-buffer measurements or continuous
queue high-water marks; zero sampled errors cannot establish losslessness.
The default transport, timeouts, filters and CRC policy are unchanged.

The separate `capture --vpw-error-counters` option reads and clears counters
at indices 0–12, only with verified network OFF before listener configuration
and after capture cleanup. This query set was observed on GT firmware 1.0.2.0;
index 13 from the VT reference was rejected. It is not a complete inventory of
GT counters. Raw replies and requested indices are retained without assigning
unverified GT fault meanings. Unsupported or malformed
pre-capture replies prevent LISTEN; a post-capture query failure still attempts
settings restoration. Verify query support on the specific adapter before using
this option for a capture. Neither diagnostic option sends vehicle messages.
The VT guide's DVI section 3.2 supplies a candidate map, including index 1
`ReadSOFLongerThenMax` and index 4 `ReadCRCIncorrect`. Its ELM map differs after
index 9, and its counter command advertises 0–13. The
[investigation report](ACK_GAP_INVESTIGATION_20261030.md#manufacturer-counter-definitions-and-their-limits)
records that discrepancy. The VT names do not establish GT-specific semantics;
whole-run counts cannot identify an individual missing frame, especially across
the initial 1x traffic seen by a fixed-4x listener.

The separate diagnostic `capture --retain-invalid-crc` option requests adapter
CRC validation OFF (`0700`) with a separate checked GET before LISTEN. CRC
display remains ON (`0801`), preserving each received physical CRC byte for
offline inspection; DVI framing/checksum validation is unchanged. The journal's
`capture_started` record includes the requested policy, checked effective policy
and raw CRC-validation readback. A mismatch blocks LISTEN. Normal completion
restores the saved CRC policy after verified OFF. Cancellation and errors attempt
the same cleanup; the log must establish what succeeded. An existing malformed
or truncated DVI stream can prevent settings restoration after OFF cleanup, so
restoration must not be assumed for failed captures. Vehicle transmissions remain blocked.

This option tests whether adapter CRC rejection hides missing short ACKs. In the
[completed ordinary E54 read](ACK_GAP_INVESTIGATION_20261030.md#all-source-read-with-invalid-crc-retention),
395 frames included one ACK with an invalid physical CRC: logged body
`6C F0 10 75 01 54` and received CRC `56`, versus HTX body `6D F0 10 75 01 54`.
The actual logged body's calculated CRC is `10`; the HTX body's is `56`. The
enclosing DVI frame remains checksum-valid. All 128 block slots had ACK-shaped
responses (127 valid and one malformed), but the loader ACK was still missing.
Cleanup verified network OFF and restored CRC validation ON (`0701`).

This makes CRC rejection a plausible explanation for earlier block-ACK gaps;
it does not locate the changed bit or prove the cause of each earlier omission.
Invalid physical CRCs remain invalid evidence. Literal comparison still reports
two missing messages and five extras, including the malformed ACK. The strict
comparison rejects the validation-OFF profile and invalid frames; the option
does not qualify a lossless capture or silently repair received data.

`analyze_capture_delivery.py` summarizes optional driver telemetry and checks its
association with logged bytes. Older logs report this telemetry as unavailable,
not zero errors. Raw-byte accounting and diagnostic coverage remain separate.
When the capture declares trailing CRC bytes, it also records each network
frame's observed/calculated CRC, mismatch ordinals and unchecked frames. This
layout declaration is not independent bus evidence. CRC-invalid payloads retain
their original hashes and byte mappings; complete byte accounting does not make
them valid messages or qualify reception.
See the [short-ACK investigation](ACK_GAP_INVESTIGATION_20261030.md) for the
repeatable three-message gap and the evidence still needed to locate it. Three
all-source reads each miss one loader ACK and two block ACKs; both source-10
controls capture all 260 expected ECM responses. The diagnostic control reports
candidate CRC index 4 = 0 versus 2 in the all-source repeat, while index 1 = 1
in both. The CRC-retention result narrows the block-ACK investigation while the
loader-ACK omission and physical source of the malformed header remain unresolved.

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
With default CRC validation, CRC-invalid frames may be discarded by the adapter
before the PC sees them. Disabling that policy does not establish that every
invalid frame will be forwarded or that no other rejection path exists.
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
for framing rules, source scope and limitations. Fifty offline tests pass;
actual receive/transition behavior and live automatic following remain unproven.


## Powered bench follow-up, 2026-10-22

The mask flag now read back OFF after an ON echo. Capture preserves the
currently reported flag and verifies zero mask bits rather than requiring ON.
See [dual-adapter bench observations](DUAL_ADAPTER_BENCH_20261022.md): SX
captured a short 1x request/reply exchange; GT delivered zero listener frames.
Neither adapter is qualified for capture during programming.

## Source-F0 read and filter coupling, 2026-10-29

The [source-F0 bench report](AUTOCAL_GT_REQUESTS_20261029.md) records a successful
AutoCal E54 read, 263 captured frames, and a bounded OFF-only filter probe.
The actual firmware readbacks show coupled exact-TO/exact-FROM/mask flags;
exact-filter writes also change the mask bytes. Earlier sections above are
historical observations, not evidence of independently stored filter controls.

Compare closed files without hardware access:

```powershell
python Tools/AL5/compare_vpw_read_capture.py --capture CAPTURE.jsonl --trace E54_R.htx --source-id 0xF0 --output NEW_COMPARISON.json
```

This command requires raw correlated configuration readbacks and retains every
captured frame. It reports the expected-request subsequence separately from
strict equality; extra frames cannot produce a strict pass. A source address
does not establish physical transmitter identity.

The diagnostic filter-link probe uses OFF-only adapter commands:

```powershell
python Tools/AL5/probe_obdx_filter_links.py --port COM9 --api dvi --output NEW_FILTER_LINKS.jsonl
```

It queries every filter after each change and verifies all nine final GET
payloads against the original snapshot. Matching GETs do not prove hidden
stored-state restoration. No receive or programming qualification follows from
this settings probe; a restoration mismatch remains a failed result.

The explicit experimental `--all-sources` option enables the shared filter,
then sets its three mask bytes to zero last. Before LISTEN it requires all five
filter GETs to match the observed coupled profile; setup mismatches fail closed.
It is mutually exclusive with `--source-id`. Restoration writes the mask last
and compares all nine final GET payloads, reporting observable restoration only.
The vehicle-send and network-ON command guards remain unchanged.

```powershell
python Tools/AL5/obdx_capture.py capture --port COM9 --api dvi --speed 4x --all-sources --seconds 240 --output NEW_ALL_SOURCE_CAPTURE.jsonl
```

This is a fixed-speed, explicitly selected experiment. It does not follow speed
transitions automatically and does not authorize or perform a flash operation.
The [actual simultaneous bench run](AUTOCAL_GT_ALL_SOURCES_20261029.md) captured
all 128 data blocks but missed three short replies present in the matching HTX.
It therefore establishes reception in both directions, not a complete capture.

## Separating recorded-byte completeness from electrical behavior

The [USB/serial comparison workflow](USB_CAPTURE_COMPARISON.md) adds an offline
classic-PCAP comparator and records the USBPcap setup/restart checkpoint. It
compares selected USB bulk-IN data with the entire raw serial log without
trimming or repairing either stream. Actual USB capture remains to be validated.

`analyze_capture_delivery.py` reuses strict replay and accounts for every saved
receive byte against the reconstructed DVI frames. It maps network frames to
their original `serial_rx` lines and byte offsets, preserving host timestamps
and uninterpreted adapter timestamp bytes. Run it only on closed DVI logs:

```powershell
python Tools/AL5/analyze_capture_delivery.py --capture CAPTURE.jsonl --address 0x025000 --address 0x043000 --output NEW_DELIVERY.json
```

The receipt includes chunk sizes, host arrival gaps, frame assembly spans and
the neighboring frames around each selected address or zero-based `--ordinal`.
Host arrival times describe ReadFile delivery and logging, not USB transaction
times or VPW pulse widths. Complete byte accounting can exclude replay dropping
a recorded complete DVI frame; it cannot exclude losses before `serial_rx`.
An absent selection or unsuccessful replay cannot produce a successful exit.

On the saved 2026-10-29 all-source run, all 532,830 recorded receive bytes map
exactly to 467 DVI frames, including 393 network frames, with zero unaccounted
bytes. The three missing acknowledgments are absent from the recorded input
before decoding. This narrows the investigation to the path before that logging
boundary; it does not distinguish adapter, driver, host servicing or bus effects.

The FNIRSI 2C53P confirmed for this bench can support short waveform comparisons.
Its [manufacturer manual](https://cdn.shopify.com/s/files/1/0694/8310/2426/files/2C53P-_Manual.pdf?v=1715670710)
documents shared channel grounds (printed page 32), BMP screenshot saving
(page 22), and a restriction on charging from equipment under test (page 33).
Continuous raw-sample capture/export has not been established. Use battery power
with USB disconnected and the CH1 probe ground clip at a verified bench ground;
CH2 and the multimeter COM lead are not substitutes for that clip.

Further read-only qualification should compare GT unplugged, attached with its
network OFF, and LISTEN ONLY, with the same harness, image, AutoCal settings and
completed ignition/reset sequence. Keep the scope probe position fixed and use
matched repeated controls. Compare same-read HTX messages, addressed data,
checksums, retries and transfer timing alongside measured levels, edges and
glitches. These are bounded observations: screenshots do not prove every bus
frame was captured, and a shared bus waveform alone does not identify which
device drove it. No electrical qualification or additional live test is claimed
by this offline tool. Live AL5 writes remain disabled.

### First baseline with the scope connected, 2026-10-29

The user reported the scope connected to the isolated E54 bench harness. AutoCal
completed another ordinary high-speed read in 2:00, with all six segment
checksums valid. GT was physically attached and separately verified OFF before
and after the read; its nine setting readbacks were unchanged. The user saved
`5 lb7 E54_0000.ctz`, confirmed ignition OFF, and the shutdown countdown completed.

The matching HTX has the same 392-message transfer-window sequence as the earlier
all-source run. All 128 unique data blocks have valid checksums, cover the same
524,286 bytes, and match the earlier partial image; there are no repeated read
requests or transfer-window timeout labels. Host-trace addressed-transfer time
is 114.006 seconds versus 113.938 seconds previously. These individual runs do
not establish a statistically meaningful timing difference or electrical effect.

The user did not freeze the scope display. No waveform screenshot was retained
for analysis, so this read establishes no measured pulse width, signal quality
or electrical noninterference. A repeat needs the scope capture controls and
settings checked first. Raw evidence and a reproducible comparison helper remain
under `LocalOnly/scoped_bench_20261029_01`. The comparison receipt
`gt_off_trace_comparison.json` has SHA256
`8f88363db1d25291a418423f971685a4259db3efefbcf4b0a19d1e5412ed1cd5`.

### Repeat baseline and scoped LISTEN read, 2026-10-29

The repeat GT-OFF read completed in 2:00 with six valid segment checksums and
was saved as `6 lb7 E54_0000.ctz`. Its HTX contains the same 392-message transfer
sequence and 128 data blocks as the preceding baseline. The user supplied two
scope photographs, labeled `4.bmp` and `5.bmp` on the display, at CH1 5 V/div,
20 us/div, X10, DC. Coarse visual estimates show a low near 0 V, plateau near
7 V and brief leading peaks near 10 V, assuming the physical probe matches the
X10 menu setting. Pulse durations are consistent with 4x VPW; these photographs
are not calibrated cursor measurements or a timing-compliance result. They are
retained with provenance under `LocalOnly/scoped_bench_20261029_02`.

With the user confirming unchanged scope settings and probe placement, a
matching ordinary AutoCal read ran with GT in the experimental all-source 4x
LISTEN profile. It completed in 1:59 with six valid checksums and was saved as
`7 lb7 E54_0000.ctz`. Its HTX transfer sequence and data match the repeat OFF
baseline exactly. Addressed transfer took 113.947 seconds versus 113.958 seconds;
there were no repeated read requests or transfer-window timeout labels.

The GT again captured all 128 data blocks but missed three short acknowledgments:
one loader acknowledgment and block acknowledgments associated with 0x02D000
and 0x068000. The earlier all-source run missed block acknowledgments at different
addresses. The same four extra messages remain visible. All 393 captured frames
have valid physical CRCs; all 532,830 recorded receive bytes map to 467 DVI frames
without unaccounted bytes. Strict comparison still fails, and the missing frames
are absent before decoding the recorded serial input. This does not identify
where upstream loss occurred.

The capture ended normally, all nine setting readbacks matched their original
values, and a separate inspection verified the GT was already OFF. The user
confirmed ignition OFF and the shutdown countdown completed. The corrected
LISTEN waveform photographs, labeled `16.bmp` through `19.bmp`, are retained at
20 and 100 us/div. An earlier submitted batch was confirmed by the user to be
reopened baseline images and is excluded from LISTEN evidence.

At matching scales, the corrected photographs show approximately 7-8 V high
plateaus and a return near the low/reference level, with leading overshoot and
rounded falling tails in both conditions. No obvious gross waveform
deterioration is apparent in these sampled windows. These are different pulse
sequences photographed at different angles and exposures; exact edge-time or
small voltage changes cannot be determined. Shared-bus photos cannot attribute
transmission or exclude disturbances elsewhere. The subsequent GT-disconnected
read and three-condition waveform comparison are recorded below; small loading
changes from physical attachment remain unresolved.
Neither electrical noninterference nor lossless monitoring is established.
Live AL5 writes remain disabled.

Raw evidence and reproducible receipts remain under
`LocalOnly/scoped_listen_20261029_01`. The strict comparison receipt
`listen_capture_comparison.json` has SHA256
`0fd5dbaeee14743cd66edea37eb5a15592bdc838c2540a15f3b5f5eccbb391a7`;
the baseline comparison `listen_vs_scoped_off_02.json` has SHA256
`9aec288560115d18e3163b5a28dad6b212dcfa2c001e4c4d8aa42e619585ba60`.

### GT physically disconnected control, 2026-10-29

The user confirmed unplugging only the GT OBD leg with ignition OFF, leaving
AutoCal, the splitter and scope connected, then turning ignition ON for another
ordinary high-speed E54 read. No GT serial session or capture was opened for this
control. The read completed in 2:01 with all six segment checksums valid and was
saved as `8 lb7 E54_0000.ctz`. Ignition OFF and the completed shutdown countdown
were confirmed afterward.

The HTX transfer contains exactly the same 392-message sequence, 128 unique
addressed requests and data blocks as both the attached/OFF and LISTEN reads.
The same 524,286 observed image bytes match, with valid block checksums and no
repeated read requests. Seven literal timeout records occur outside the transfer
window. Addressed transfer took 115.004 seconds, 1.046 seconds longer than the
OFF control and 1.057 seconds longer than LISTEN. Individual runs cannot establish
the cause or significance of this timing variation. The final two flash bytes
remain unobserved.

This control shows matching read data and retry counts across the three
conditions in the compared software traces. It does not establish electrical
noninterference, and the GT all-source capture still misses acknowledgments.
Private evidence remains under
`LocalOnly/scoped_unplugged_20261029_01`; the reproducible comparison receipt
`unplugged_vs_off_and_listen.json` has SHA256
`008452a01e0e3debd49212199797531d20a675fab5bbf402beb3891b3b22dda0`.

The user subsequently supplied disconnected-GT photographs labeled `24.bmp`
and `26.bmp` at 20 us/div, and `28.bmp` and `31.bmp` at 100 us/div. CH1 remains
5 V/div, X10, DC. At matching scales, the high plateaus are approximately
1.4-1.6 vertical divisions above low, about 7-8 V if physical probe attenuation
matches the menu. Leading overshoot, rounded falling tails and return near the
displayed reference remain present with the GT physically absent. No obvious
gross amplitude collapse, clipping or persistent level shift is apparent across
the unplugged, attached/OFF and LISTEN windows.

The mere presence of these peaks and tails therefore cannot be attributed to
GT monitoring. A smaller GT contribution is not excluded. These are different
packet windows photographed at different perspectives and exposures, so exact
edge-time, overshoot and small voltage differences cannot be established. Nor
can short photographed windows exclude rare unwanted transmissions elsewhere.

The bounded outcome is no observed read-data or retry degradation and no obvious
gross waveform deterioration in these isolated-bench E54 high-speed read tests.
All-source monitoring still fails the strict lossless comparison; this work
does not qualify AL5 programming or recovery. No further hardware action was
performed during the photograph analysis. Original photographs and the combined
scope/software evidence receipt `scope_three_condition_comparison.json` are
retained in the same private directory; the receipt has SHA256
`4e24b83a29a3b15fb35f157e704b40c96183c05e9af04085f2b458bad114a58b`.
