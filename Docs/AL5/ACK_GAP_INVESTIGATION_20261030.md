# Missing short acknowledgments — October 30, 2026

The two earlier fixed-4x, all-source E54 captures missed **one read-loader ACK and
two block ACKs**. A third diagnostic repeat below reproduced that count. The
earlier source-10-only capture and the new diagnostic source-10 control each
received all **260 expected ECM responses**, including these ACK types. This establishes a repeatable
configuration-associated symptom, not a failure in every
monitoring mode or proof of a specific firmware defect.

A fourth all-source experiment disabled adapter CRC rejection and retained one
malformed block ACK. All 128 block-request slots then had either a valid ACK or
that malformed ACK; the loader ACK was still absent. This provides direct
evidence of a bad received ACK body and makes CRC rejection a plausible cause
of earlier block-ACK omissions. It does not establish the origin of the bad bit
or explain every earlier omission.

The findings below were derived from saved files. The additional offline
instrumentation does not enable controller writes or flash operations. Live AL5
writes remain disabled. Any subsequent adapter check is recorded separately.

The next investigation step is the
[USB/serial comparison](USB_CAPTURE_COMPARISON.md). USBPcap 1.5.4.0 was installed
and its files/signatures verified with the bench OFF. A Windows restart and the
first simultaneous USB/serial capture remain pending; no new hardware result is
implied by the offline comparator or its fixture tests.

## What the existing evidence establishes

The earlier all-source run omitted block ACKs associated with `0x025000` and
`0x043000`; the scoped repeat omitted those at `0x02D000` and `0x068000`. Each
address's ACK is present in the other run and in the source-10 control. Identical
block ACK bytes are usually received, so a static filter excluding that ACK
content alone cannot explain the omissions.

The missing reference records are complete receive-shaped HTX binary records:
channel 2, category 7, subtype 2, wrapper `0152`, route `1000`, six declared
message bytes, and a complete 21-byte wrapper. Their complete wrapper forms also
occur on successfully captured ACKs. They are not text records, excluded local
device queries, truncated wrappers or byte-pattern matches inside a data block.
This rebuts a parser-selection artifact. It cannot independently prove physical
emission of each missing instance or exclude synthesis inside AutoCal/EFILive.

Both failed captures contain all 128 addressed data blocks and no repeated
addressed read requests. The missing messages are short ACKs, not lost data
blocks. Replaying the latest raw serial chunks produces exactly the same 393
network and 74 adapter frames as the live decoded rows. All 532,830 logged
receive bytes are accounted for by those DVI frames. There is no evidence of
the decoder silently discarding a recorded complete ACK.

## Timing and delivery comparisons

- Across the two all-source runs, all **252 captured block ACKs** share a
  `ReadFile` chunk with their request. Those chunks contain the usual **32
  bytes** of request-plus-ACK framing. The **four missing block ACKs** leave an
  isolated **18-byte request chunk**; the missing ACK would be a complete
  **14-byte DVI frame**. A `ReadFile` chunk is not a USB packet.
- Missing block ACKs appear **5–6 ms** after their requests in HTX, within the
  **5–8 ms** range for captured controls. HTX request-to-data intervals at the
  missing cases are **878–887 ms**, within the controls' **805–920 ms** range.
  These are software trace times, not measured VPW edge times.
- The preceding long response in each missing case arrives as **4096+21 logged
  bytes**, with zero recorded assembly span. The next request arrives
  **109–125 ms** later. Successful cases also have those patterns; no distinctive
  preceding host stall was found.
- The following data frame has zero recorded assembly span at two missing
  events and **93/125 ms** at the other two. Successful controls also exhibit
  these spans. A delayed fragment does not uniquely predict the missing ACK.
- Under an explicitly unqualified big-endian interpretation, request-to-data
  raw adapter-tag differences at missing events are **4779, 4843, 4857, 4860**,
  inside the captured controls' **4744–4908** range. No clock units, timestamp
  capture point or physical timing claim is assigned to that arithmetic.

Both missing loader ACKs follow the same **1186-byte host upload**. Each
all-source capture records the upload and three following short frames in one
1231-byte receive chunk, but omits the loader ACK. The exact-source-10 control
does not forward that host upload and does capture the loader ACK.

The earlier source-F0-only run also contains 129 `8C FE F0 3F` frames, whereas
the first all-source run has only the startup instance. This separate-run
keepalive difference is useful context, not proof that every absent keepalive
was physically transmitted in the all-source run.

## Working explanation and unresolved alternatives

The pattern is consistent with admitting/forwarding the preceding traffic
exposing a receive-rearming or output-servicing problem: bidirectional mode
admits both a request and its quick reply, and a long forwarded upload precedes
the consistently missing loader ACK. **This is a hypothesis.** The filter
configuration and amount of forwarded traffic change together. These files do
not distinguish adapter filtering, VPW receive/CRC rejection, adapter output
buffering, USB/driver delivery or a pre-logging host loss.

The logger does not purge or reset receive buffers during capture. It records
raw bytes before decoding, and issues no adapter commands during the steady
listening interval. Its synchronous JSON writing can delay the next read, but
the old logs do not measure that delay separately or contain driver queue and
overrun snapshots. Complete replay is not evidence of zero upstream loss.

The [Microsoft serial status API](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-clearcommerror)
can report driver overflow/error flags and queue state; polling clears the error
flags. The [timeout documentation](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-commtimeouts)
also distinguishes return-on-first-byte settings from the existing timeout
tuple. The latter was not changed on the basis of this unproven hypothesis.

The [OBDX VT reference, version 1.06](https://obdxpro.com/Downloads/ReferenceManuals/OBDX%20Pro%20VT%20Reference%20Guide%20v2.pdf)
documents CRC validation and indexed VPW error counters in sections 3.11.7 and
3.11.14. Reading a counter resets it. This is a VT reference, not proof that the
GT implements the query, its error meanings or its counting behavior. Zero
reported adapter errors in old captures cannot exclude suppressed receive faults.

### Manufacturer counter definitions and their limits

The VT guide does provide a candidate index map in DVI section 3.2, PDF page 19.
Its names are reproduced here to distinguish the manufacturer's definitions from
the raw GT observations:

- 0: `ReadBusInactive`; 1: `ReadSOFLongerThenMax`; 2: `ReadSOFShorterThenMin`.
- 3: `Read2BytesOrLess`; 4: `ReadCRCIncorrect`.
- 5: `ReadFilterTOdoesNotMatch`; 6: `ReadFilterFROMdoesNotMatch`.
- 7: `ReadRangeFilterTOdoesNotMatch`; 8: `ReadRangeFilterFROMdoesNotMatch`.
- 9: `WriteFrame_IdleFindTimeout`; 10: `NotEnabled`; 11: `READONLYMode`;
  12: `ReadFrame_AwaitingSendPC`.

The same guide's ELM section 2.33 instead inserts `ReadFrame_NotEnabled` at
index 10 and shifts the remaining names to 11–13. The DVI counter command in
section 3.11.14 advertises 0–13 without resolving that discrepancy. GT firmware
1.0.2.0 accepting 0–12 and rejecting 13 is consistent with the DVI list; it does
not validate the GT's counter semantics. Indices 1 and 4 have the same names in
both lists. The OFF-state changes at index 10 are compatible with the DVI name,
but are not proof of its implementation or an overflow count.

Static metadata inspection of the manufacturer's OBDXWindows 1.0.3 library found
no corresponding fault-name constants among the examined 395 constant rows.
Its assembly version `1.0.2.0` is not a GT firmware identity. The library was not
loaded or executed. Reference provenance and the conflicting maps are retained
in `manufacturer_reference/reference_findings.json`; GT counts remain raw indices
in the capture log.

## Next discriminating evidence

The capture tool now supports opt-in `--serial-diagnostics` and
`--vpw-error-counters`; their boundaries and limitations are documented in the
[capture guide](OBDX_CAPTURE.md#recording-and-offline-validation). Raw serial
bytes precede telemetry and decoding in the journal. The delivery analyzer
checks sequence/byte/timestamp association, preserves failed observations and
reports legacy telemetry as unavailable. A separate metadata correction now
recognizes mode-1 addressed read requests; it does not repair missing frames.

Offline fault injection also exposed an unrelated cleanup defect: persistent
journal-write failure could prevent the OFF command from being sent. Cleanup
now attempts only the guarded OFF SET/GET despite journal failure, then reports
the failure. A failed transport cannot be reported as verified OFF. The two
successful captures under investigation did not encounter journal failure.

The diagnostic all-source repeat and source-10 control below preserve CRC
validation and transport timeouts while adding this observability. Both have
complete driver telemetry without sampled errors. Only the all-source run has
two counts at candidate CRC index 4; both have one at candidate overlong-SOF
index 1. These counts do not identify individual frames. In particular, index 1
cannot identify the missing loader ACK, because the control received that ACK.

The explicit diagnostic `--retain-invalid-crc` option provides another discriminator.
It disables adapter CRC rejection with a checked `0700` readback before LISTEN,
while preserving CRC display (`0801`), raw bytes, DVI checksum checking and the
vehicle-send guard. Default captures still require validation enabled (`0701`).
The journal records requested and checked effective CRC policy, and cleanup
restores the original policy after verified OFF. A mismatched readback blocks
LISTEN. The live diagnostic result is recorded separately below.

An otherwise matching ordinary all-source read tests whether missing
ACKs become visible with invalid physical CRCs. Such frames must remain invalid
evidence, not be silently repaired or counted as a lossless capture. Strict
capture qualification still fails closed with adapter CRC validation disabled.
Fixed-4x listening also receives the startup interval without following the
initial 1x exchange, so startup errors remain a confound for whole-run counters.

An independent GT USB receive-endpoint recording would distinguish bytes that
reached USB but not the raw JSONL from omission upstream of USB. ACKs absent at
USB would still require an independent physical VPW recording to distinguish GT
omission from the application reference. Repeated source-10/all-source A/B reads
can strengthen the configuration association but cannot alone identify the loss
stage. The existing short scope photographs are not that independent full-bus
recording. No programming test is needed for this investigation.

## Retained evidence

### Adapter-local counter support check

After the user confirmed the bench OFF with both adapters connected, an OFF-only
preflight identified the GT on COM9 as firmware `1.0.2.0`. Network state was
`0200` before inspection and again after cleanup. No LISTEN, network ON,
vehicle-send command or firmware update was performed.

Indices 0–12 returned the expected three-byte reply shape. Their historical raw
counts were `[255, 1, 4, 23, 2, 0, 0, 0, 0, 0, 5, 0, 0]`. The index-13 query
returned adapter error frame `7F 02 33 07 44`, so the full VT-profile check failed
and stopped. The supported query set in the capture tool was consequently
restricted to the observed indices 0–12, with no automatic probing or fallback.
This establishes reply support, not fault meanings or completeness of the counter
inventory. These old accumulated values cannot be attributed to the three ACK
omissions; the reads also clear the queried counters under the documented
semantics. A fresh before/after observation is needed for attribution.

The new driver telemetry covered all 38 reads and 76 status snapshots in this
local check, with no sampled driver error flags and maximum sampled input queue
of 20 bytes. This verifies recording/analysis on real adapter-local traffic,
not sustained VPW capture or losslessness. The complete raw exchange and failed
preflight result are retained as `gt_counter_preflight_01.jsonl` below.

A second OFF-only check completed the 0–12 query set and verified OFF afterward.
All counts were zero except index 10, which returned 52. Its observation followed
the first by 256.141 host-clock seconds and 38 recorded local requests, including
the second index-10 query. The next pre-capture observation was 54 only 92.484
seconds later. These observations do not establish a periodic increment rule or
identify dropped traffic. The raw second check is `gt_counter_preflight_02.jsonl`.

### Third all-source read with diagnostics

After the user confirmed the isolated E54 bench supply and ignition ON, AutoCal
performed the same ordinary high-speed read while the GT listened at fixed 4x.
The read completed successfully in **2:00**, all six segment checksums passed,
and the saved file was observed as `9 lb7 E54_0000.ctz`. Ignition OFF was confirmed
and EFILive's shutdown countdown completed. GT cleanup verified OFF and all nine
observable setting readbacks matched their originals. No flash operation ran.

The strict comparison again finds **3 missing ACKs and 4 extra messages** among
393 captured network frames. The loader ACK is absent; this time the two missing
block ACKs are associated with **0x05A000** and **0x070000**. All 128 data blocks
are present and valid. The full 392-message HTX transfer sequence and observed
data equal the attached/OFF baseline exactly, with 128 unique read requests and
no repeats. There is no observed read-data or retry degradation.

All **533,006 logged receive bytes** map to **497 DVI frames**: 393 network and
104 adapter frames. The additional adapter frames are diagnostic queries.
All **2,507 reads / 5,014 driver snapshots** correlate with the raw byte log,
with no failed reads or sampled error flags. Maximum sampled input queue is
651 bytes and the largest recorded gap between serial read calls is 16 ms.
These are host observations, not continuous queue bounds or proof of USB delivery.

The complete driver windows bracketing the missing loader ACK and both missing
block ACKs likewise show no sampled error flags, failed reads or recorded host
stall. At 0x05A000 the request is the final 18 bytes of a 2,923-byte read containing
the preceding data tail. At 0x070000 it is an isolated 18-byte read. All 126
captured block ACKs share a read with their request. Thus an isolated request
chunk is not required for the gap. Both missing block ACKs have ordinary 6 ms
request-to-ACK intervals in HTX.

Raw post-capture counts at indices 0–12 are
`[19, 1, 0, 177, 2, 0, 0, 0, 0, 0, 38, 0, 0]`;
the pre-capture counts were zero except index 10 = 54. These cover listener setup,
startup and shutdown traffic as well as data transfer. Fixed-4x listening does
not follow the initial 1x exchange, so counters cannot automatically be assigned
to the three missing messages. Their firmware-specific meanings remain unqualified.

Private evidence is in `all_sources_diagnostics_01/`. Capture SHA-256:
`5a5c5b36772dd1a1e453281723f9965b65f6528a2f4a8412307b50039a6491e2`.
Matching HTX SHA-256:
`3764abc2276b18b44ea848213611545413fe62a1760387ae11ddcabf102c73a6`.
Independent timing review and gap-window receipts are pinned below. The combined
capture, speed, comparison and delivery suite passes **103 offline tests**;
simulation does not qualify firmware behavior or programming.

### Source-10-only diagnostic control

The matching control used the same fixed 4x speed, serial diagnostics, counter
queries and default CRC validation, with the exact source filter set to `0x10`.
AutoCal's ordinary E54 read completed in **2:00** with all six segment checksums
valid. The user confirmed ignition OFF and EFILive's shutdown countdown
completed. GT cleanup verified OFF and observable settings restoration
succeeded. The saved file was confirmed as `10 lb7 E54_0000.ctz` by the user,
EFILive window title and filesystem, and retained with a completion receipt.

The strict comparison passes: **all 260 expected ECM responses**, including the
loader ACK, all 128 block ACKs and all 128 data responses, appear in order with
valid physical CRCs. This is the second successful source-10 control against
three all-source runs that each omit three short ACKs. It establishes agreement
for this selected source and host-trace window, not a complete full-bus capture.

The control's full 392-message HTX transfer sequence also matches the attached/OFF
baseline exactly. All 128 data blocks and 524,286 observed image bytes match;
there are 128 unique read requests, no repeats or malformed requests, and no
addressed-transfer timeout text. Request-to-final-data time is 114.078 seconds
versus 113.958 seconds in the baseline. These individual runs do not establish
a meaningful speed difference. The final two flash bytes remain unobserved.

All **529,347 logged receive bytes** map to **347 DVI frames**: 260 network and
87 adapter frames. All **2,480 reads / 4,960 status snapshots** correlate with
the byte log, with no failed reads or sampled driver errors. Maximum sampled
input queue is 724 bytes, output queue is zero, and the largest recorded gap
between serial reads is 16 ms. This does not measure the adapter FIFO or exclude
losses outside the selected source/window.

Raw post-capture counts at indices 0–12 are
`[75, 1, 0, 129, 0, 136, 0, 0, 0, 0, 141, 0, 0]`;
the pre-capture counts were zero except index 10 = 219. Candidate CRC index 4
is **zero**, compared with **two** in the all-source repeat. Candidate overlong-SOF
index 1 is **one in both runs**, despite the loader ACK being present here.
The nonzero index 5 in this source-filtered control also cautions against treating
the VT filter names as proven GT behavior. No one-to-one fault-to-frame attribution
follows from these whole-run counts.

Private evidence is in `ecm_diagnostics_01/`. Capture SHA-256:
`dedfc26f60e363dd4636ee8fdb3f3f4e8830fa449dcb0e342e88fd0f080e8199`.
Matching HTX SHA-256:
`b8bc6eb82ea8b7f367206831a20176e6978537612b7519c46bbd8b1245767bec`.
The strict comparison receipt SHA-256 is
`102d728ccde83d47980a39182944b16a35a27fc035a00831645af10806df98e1`;
the delivery receipt SHA-256 is
`a8e46f961794bf2d175212c5983fcb15314bdeb71804027444f2577709038e6d`.
The capture, speed, comparison and delivery suite passes **109 offline tests**
with the CRC-retention option and per-frame offline CRC evidence. These tests
do not establish live behavior.

### All-source read with invalid-CRC retention

The user confirmed the isolated bench ready for another ordinary E54 read.
The GT used the same fixed-4x all-source profile and diagnostics, with the
explicit `--retain-invalid-crc` option. Separate GETs verified CRC validation
OFF (`0700`) and CRC display ON (`0801`) before LISTEN. AutoCal completed the
read in **1:59**, all six segment checksums passed, and the saved file
`11 lb7 E54_0000.ctz` was confirmed by its window title and the filesystem.
The user confirmed ignition OFF and the shutdown countdown completed. GT cleanup
verified OFF and all nine observable settings restored, including CRC validation
ON (`0701`). No flash operation ran.

The capture contains **395 network frames: 394 with valid physical CRCs and one
with an invalid physical CRC**. The bad frame is zero-based network ordinal 71,
between the valid request and data response associated with address `0x014000`:

- Logged VPW body and CRC: `6C F0 10 75 01 54 56`.
- Matching HTX ACK body: `6D F0 10 75 01 54`, whose calculated CRC is `56`.
- Calculated CRC over the actual logged `6C ...` body: `10`, not its received `56`.

The bodies differ only in bit 0 of the first byte (`6C` versus `6D`). The enclosing
DVI frame has a valid DVI checksum, and the malformed body is present in the raw
serial log before analysis. It is not a decoder-created header or an omitted
physical CRC byte. Its neighboring request/data association identifies the
block slot; it does not independently prove physical transmitter identity or
where the bit changed.

All 128 block-request slots have an ACK-shaped response: **127 canonical,
CRC-valid block ACKs and this one malformed ACK**. The loader ACK remains
missing. Literal comparison, retaining every frame without repair or exclusion,
still reports **2 missing messages and 5 extras**: the missing loader ACK and
canonical block ACK, with the malformed frame added to the four previously
observed extras. Strict qualification correctly fails both the validation-OFF
profile and the bad physical CRC. This is not a lossless result.

All **533,034 logged receive bytes** map to **499 DVI frames**, including the
395 network frames. The **2,488 reads / 4,976 driver snapshots** correlate with
the raw log, with no failed reads or sampled driver errors. Maximum sampled
input queue is 2,986 bytes, output queue is zero, and the largest recorded gap
between reads is 16 ms. These samples do not measure adapter buffering or prove
uninterrupted host/USB delivery.

The matching HTX still contains the same 392-message sequence and 128 data
blocks as the attached/OFF baseline. All 524,286 observed image bytes match;
there are 128 unique requests, no repeats and no addressed-transfer timeout
text. Request-to-final-data time is 113.891 seconds versus baseline 113.958
seconds. The final two flash bytes remain unobserved.

Raw post-capture counts at indices 0–12 are
`[73, 1, 1, 163, 0, 0, 0, 0, 0, 0, 43, 0, 0]`;
pre-capture counts were zero except index 10 = 158. Candidate CRC index 4 stays
zero even though offline validation finds a bad CRC while rejection is disabled.
That count cannot be treated as an unconditional tally of malformed bus frames.
Whole-run startup and shutdown traffic remain mixed into these counts.

The retained malformed ACK, together with the two candidate CRC counts in the
default all-source repeat, supports CRC rejection as an explanation for block-ACK
gaps. A separate run cannot prove that the earlier missing instances had this
same defect, and the bit-error location remains unresolved: physical reception,
adapter handling and other earlier stages are not independently distinguished.
Disabling CRC rejection did not recover the loader ACK. The next useful evidence
is a continuous independent bus/USB reference or firmware-specific receive-path
information, rather than silently correcting the header or calling this complete.

The October 30 check of public manufacturer material found no documented fix
for this short-ACK symptom. The [GT product page](https://obdxpro.com/product/obdx-pro-gt-obd2-diagnostics-and-tuning/)
advertises 4x VPW and DVI, without a lossless monitoring guarantee. The
[official J2534 changelog](https://github.com/OBDX-Pro-Admin/J2534/blob/af5de5203e5d2164b3270e8d245cb8cbee56082a/J2534%204.04/OBDX%20Pro%20GT/changelog.txt)
contains host API fixes; its API version must not be confused with GT firmware
`1.0.2.0`, and this capture tool does not use that J2534 library. The public
[Downloads page](https://obdxpro.com/downloads/) requires an account for the
updater and does not expose a current GT firmware changelog. A relevant firmware
fix therefore remains unknown. No update, driver installation or vendor contact
was performed. A firmware-specific changelog or manufacturer analysis of the
retained malformed DVI frame would be useful next evidence.

Private evidence is in `all_sources_crc_retained_01/`. Capture SHA-256:
`5dddddb7197f30eab4beec57d1ee04f8cdb0fe865fd31b1b3e2932e3a85d4754`.
Matching HTX SHA-256:
`56da008381808521c5457912936f1d22858ffdfb2c3d11360735ff7e7fe5d40a`.
The independent forensic receipt `crc_retained_forensic_review.json` has SHA-256
`b43640971955ab6bce2b885df787424dd898f59cf5875674b90473fa4e8f2d47`;
the delivery receipt has SHA-256
`4ddb299749b1fe42078cf6c61f461142367a3fddcfe73e2eb7d7de37a17f5116`;
the completion receipt has SHA-256
`aabecc1659dfad32e2205a17ab4bade49f5745b905f3fc2f467967e4eabf6a67`.

The ignored private evidence under `LocalOnly/ack_gap_20261030/` includes
reproduction scripts and pinned input/parser provenance:

- `reference_review/reference_review.json` — SHA-256
  `50dc0b756e67d7b91bae1f35a239d8cfd4c5298db837dcaa5dcbc09dac4f0788`.
- `timing_review/ack_timing_review.json` — SHA-256
  `fa194147cd407bad1a9b516ad37e8324cf12d919001c73d4343aa4b11fa61ddb`.
- `timing_review/differentiators.json` — SHA-256
  `2806b659232141a37cb87d6e78462cd97ba232ea2654057212e30acc109bf086`.
- `timing_review/diagnostic_ack_timing_review.json` — SHA-256
  `1bbe405e30f2988b26602832a4f73ce5af0b4bbdf294404cf42039623d229b2f`.
- `timing_review/diagnostic_gap_driver_windows.json` — SHA-256
  `67f980dc593db974f6ada511b6ca225fe44ce4015ce69b9e4bf2922fcc1056c5`.
- `manufacturer_reference/reference_findings.json` — SHA-256
  `6c164fef660e16565f4f1aac776a4cc1f22dfaf8048a910785ec09be6d133c1e`.

The private traces and tune images are not reproduced in this report; only the
short ACK bytes needed to explain the CRC finding are shown.
These hashes pin the investigation inputs/results; they do not make the full
comparison independently reproducible without those retained files.
No electrical noninterference, complete all-source capture, AL5 programming or
recovery qualification follows from these results. Live AL5 writes remain disabled.

## USB-boundary follow-up

The [simultaneous USB and serial read](USB_CAPTURE_COMPARISON.md#simultaneous-usb-and-serial-read--2026-10-30)
reproduced the same malformed `6C F0 10 75 01 54 56` ACK at block `0x073000`.
All 533,034 recorded successful USB bulk-IN bytes matched the complete raw
serial RX stream. The malformed byte and valid-checksum DVI envelope are
already present in the USB completion data, placing this observed discrepancy
before the downstream COM reader/logger and decoding. GT reception, firmware
and stages before USBPcap remain unresolved; this does not prove what appeared
on the VPW wire.

The loader ACK remains absent. There are again 127 valid block ACKs and one
malformed ACK, with all 128 data blocks and 524,286 observed image bytes equal
to baseline. EFILive completed in 1:59 with six valid checksums. USB qualification
still fails conservatively on a zero-data non-success completion at serial
close, and the supervisor retained a final status-publication failure after
child exit zero. Both limits remain in the saved reports. No flash ran.
