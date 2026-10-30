# PcmHammer writer USB comparison

The GT can act as PcmHammer's E54 writer while USBPcap records its USB traffic.
This is a different experiment from using the GT as a passive listener beside
AutoCal. USBPcap observes bytes delivered over USB; it cannot recover a VPW
message the GT never forwards or independently establish what was on the wire.

`Tools/AL5/pcmhammer_usb_capture.py` compares a saved PcmHammer debug log with
selected GT bulk-IN completions. It performs no hardware access. Supply the
recorded USB bus, device address and IN endpoint, and explicitly inspected DVI
byte windows after any adapter bootstrap text. Separate CLI opens can introduce
additional bootstrap spans. Every excluded span remains in the report with its
length and hash; the parser never resynchronizes silently.

The comparison preserves message order, duplicates, malformed bytes, short
acknowledgements and PCAP offsets. It distinguishes logged Mode 36 test transfers
(`44`), ordinary copies (`00`), execute transfers (`80`), and Mode 3D/05 erase
requests. These TX classifications describe the debug log, not independently
verified USB OUT delivery. A copy can target RAM or flash. Neither a request nor
a matching RX stream alone proves successful flash programming.

Run the tool with `--help` for its required file and selection arguments. Output
creation is exclusive. For focused offline validation, from `Tools/AL5` run:

```powershell
python -B -m unittest test_pcmhammer_usb_capture test_usb_serial_capture -q
```

The 27 tests passed on October 30, 2026. They cover stream fragmentation,
duplicate and reordered replies, explicit excluded spans, timestamp changes,
malformed messages, USB completion errors, resource limits and exclusive output.
They do not qualify hardware behavior.

For a bench experiment, identify the exact controller and adapter, retain a fresh
full backup and pin the writer/kernel inputs before programming. Keep one owner
of the GT serial port: the passive `obdx_capture.py` process must not run beside
PcmHammer using that same GT. Capture setup must complete before PcmHammer opens
the port. Preserve capture cleanup failures alongside any useful captured bytes.

PcmHammer's `--test-write` transfers packets without erasing/programming flash.
The current AL5 checkout's ordinary `--write` selects the full-image operation
and skips matching sectors; writing an unchanged backup is not proof of actual
programming. This comparison tool does not add a force option or change any
writer. Live AL5 writes remain disabled.

## Isolated E54 test-transfer observation — October 30, 2026

The [result receipt](E54_GT_TEST_WRITE_USB_20261030.json) pins the inputs and
preserves the qualification limits described below.

The user selected GT/PcmHammer at 4x with USB capture and confirmed the spare
E54/LB7 bench powered at a steady 13.8 V. The GT identified firmware 1.0.2.0;
PcmHammer queried OS 15189044 and adapter voltage 13.74 V. AutoCal was not
operated. Only PcmHammer owned COM9 during controller operations.

A fresh 524,288-byte full read completed in 2:06.380. All seven flash ranges
matched the controller's CRCs. PcmHammer then ran `--test-write` against that
exact backup, completing in 32.075 seconds. It sent 96 distinct 1,024-byte test
blocks covering calibration addresses 0x008000–0x01FFFF. Every write request
succeeded on its first attempt. The calibration CRC remained `712EFE11`.

The saved USB OUT stream contains the same 136 network requests as the test
log, in the same order. They include 96 Mode 36/subcommand 44 test blocks, each
with a valid block checksum. There are no Mode 3D/05 erase requests and no
Mode 36/subcommand 00 ordinary copies in this test phase. The kernel upload
uses subcommand 80, copying into RAM and executing there. This was not a flash
erase/program operation.

USB IN contains all 97 short upload acknowledgements logged by PcmHammer:

- One loader acknowledgement: `6C F0 10 76 80 78`.
- Ninety-six test-transfer acknowledgements: `6C F0 10 76 44 00`.

The full test-phase comparison retains 110 logged replies versus 111 USB
network messages. No logged reply is missing from USB. The extra message is
a second cleanup reply, `8C F0 10 54`, following the final logged reply. It is
retained, not trimmed to manufacture exact whole-stream equality.
Each of the 96 test ACKs appears after its complete USB OUT request and before
the next request in PCAP record order. The independent OUT audit also finds
840 submissions paired with 840 successful completions across the full run.

The complete USB IN capture retains nine zero-data, non-success completions
with status `0xC0010000`, around CLI bootstrap/port-close transitions. There
are no selected URB pairing issues. The explicit DVI comparison window also
retains four adapter-error replies during the following autodetection boundary.
Neither these records nor the extra cleanup reply is removed. The strict
whole-window qualification remains false; the positive finding is the observed
delivery and ordering of every expected test acknowledgement.

A second full read completed in 2:06.580, again with all seven CRC ranges
matching. All 524,288 bytes equal the pre-test backup, with zero differences.
Both images have SHA-256
`a3b010af7e04df03be699198920aac26ba0645c2ad608e72eacf0bc3970beb58`.

After PcmHammer closed its port, the adapter-local inspection verified GT
network OFF (`0200`) and speed 1x (`0600`). USBPcap stopped through its owned
pipe, exited zero, retained no process ownership, and reported no stderr or
receipt-publication error. The final PCAP is 1,841,652 bytes, SHA-256
`30641e9e013c16f3407ffac9882ad40b7d01d4e9d2f71d8bee31e200db8dfbc3`.

The private evidence is under
`LocalOnly/usb_capture_setup_20261030/e54_gt_pcmhammer_write_01/`, including
the PCAP, before/after BINs, four operation logs, final OFF inspection and
capture receipt. The test-write log SHA-256 is
`c8d004ece9066c1a3e3fed4eb63d6912a013b6afcafe6962f8b49e374026d955`.
`analysis_final/usb_phase_final.json` pins both USB directions;
`analysis_final/test_ack_order.json` retains all 96 request/ACK record ranges.
The final snapshot equals the original PCAP byte-for-byte. These private
references preserve reproducibility without publishing the tune or USB payloads.

This establishes delivery of these short replies through an actively used GT
and its USB path. It does not reproduce the passive, all-source EFILive read
experiment: that workflow's Mode 75 block acknowledgements are absent here.
The loader ACK previously missing from passive captures is present in this
active-interface test. That non-erasing test did not qualify actual flash
programming, AL5 writing/recovery, electrical noninterference, or lossless
passive capture.

## E54 writer verification correction — October 30, 2026

Preparation for the actual E54 calibration rewrite exposed a host verification
bug in a separate recovery checkout. An initial successful CRC comparison could
leave a stale success flag after a forced rewrite and subsequent mismatches. The
retry loop also ended after its fifth write pass without verifying that final
pass. Those conditions could make the host's success report unreliable.

The correction resides in
`C:\Codex Projects\Car Tuning\recovery_tmp\PcmHammer-source`, based on commit
`5bf98c8aa1a9f815eaf972040c75f7ec8f698eca` with preexisting local modifications.
It was not implemented in this AL5 checkout. The changed production file is
`Apps/PcmLibrary/KernelWriter.cs`; a new
`Apps/Tests/KernelWriterSessionTests.cs` is included by the existing test project.
All 691 other files in the 693-file original source manifest stayed unchanged.
The preexisting work was retained, without staging or committing it.

Success now depends on the current CRC comparison. A forced identical calibration
receives one erase/write pass followed by verification. Up to five write passes
are permitted, with a comparison after each pass, including the fifth. Unknown
CRC results, cancellation observed after comparison, and a write result carrying
Success status with a false value terminate the operation without reporting
successful flashing.

For E54 real writes, after failure the host avoids resetting a kernel that was
already running on entry or for which erase may have been attempted. The
uncertain state is marked
before the erase call, including a refusal, timeout or exception. An unsuccessful
operation then adds neither a calibration erase nor a cleanup/reset command.
Verified success permits normal cleanup. Compare and non-erasing TestWrite retain
their existing cleanup, as do other controller types. This host behavior does not
establish that a controller can recover after a reset or power loss.

The bounded offline suite executed 21 new tests through production
`KernelWriter.Write` and an in-memory `IKernelSession`, plus 20 existing write
policy tests. All 41 passed against the fixed DLL. The same 21 new tests produced
14 failures against the original DLL, reproducing the stale success and missing
final verification defects as well as the E54 failure cleanup behavior. These
counts describe these two classes, not the entire legacy test project.

The tests use the real Intel28F400B range layout. They check that a forced
calibration rewrite erases and writes only 0x008000–0x01FFFF, and cover matching
and mismatching CRCs, the fifth-pass verification, timeout, cancellation, erase
and write failures/exceptions, an existing uncertain recovery kernel, OS-check
refusal, restricted writes, and Compare/TestWrite controls. A fake session's
OS-check refusal demonstrates host gating; it does not exercise the complete
live OS-identification exchange. The runner invokes the retained MSTest methods
and assertions by reflection because the older installed adapter lacked a test
host extension. These classes use no test lifecycle attributes.

The private evidence is under
`C:\Codex Projects\Car Tuning\private_builds\e54_forcecal_fix_20261030_01\`.
`KernelWriter.before.cs` and `KernelWriter.after.cs` preserve exact source bytes;
`only_this_fix.diff` separates this task's changes from the preexisting local
work. `test_sources/`, `run_tests.ps1`, and `README.md` retain the test sources and
offline reproduction instructions. `red_results.json`, `green_01/results.json`
and `fix_receipt.json` preserve the results and build/source provenance.

The CLI Release build completed with no errors and three existing warnings.
The fixed `PcmLibrary.dll` SHA-256 is
`7fdba116d1ba4adb4849dca6bcbd74cd2ad3ad1c8488c8e23829d08954cb7021`;
the built `pcmhammer-cli.exe` SHA-256 is
`b623c47ba99934f1f44d8109a0310b9f0c158472e593ad9e4fa65161ed89c0c8`.
The task-only diff SHA-256 is
`c8a83bbdb7323c7ea4874a901e1df586091dba1da40031e3576361c0feb4953d`;
the passing test receipt SHA-256 is
`a1723623a16df4e272495e9ffbf170d4eb77dd097cfc333af49875e78fda4f50`.

The correction and these offline tests do not enable AL5 programming, prove
interrupted-flash recovery, or establish lossless passive monitoring. The actual
E54 programming and USB observations are documented in the following section.

## Isolated E54 calibration rewrite — October 30, 2026

The [actual-write receipt](E54_GT_ACTUAL_WRITE_USB_20261030.json) pins the
programming, readback, USB audit and host-fix inputs. This experiment used the
corrected recovery-checkout writer described above. It did not enable an AL5
writer or use AutoCal. PcmHammer alone owned the GT's COM9 port.

Immediately before programming, all seven controller ranges matched the saved
full backup. The user confirmed the isolated spare E54/LB7 bench at a steady
13.8 V; the writer measured 13.77 V, identified OS 15189044 and Intel28F400B, and
used VPW 4x. The selected operation was calibration-only with a forced pass
against the unchanged backup, so matching data did not skip programming.

The write completed in 51.2235447 seconds and exited zero. It issued one
Mode 3D/subcommand 05 erase at 0x008000, then 96 Mode 36/subcommand 00 copy blocks
of 1,024 bytes covering 0x008000–0x01FFFF. The host reported every write request
succeeded on its first attempt. After programming, the current controller CRC
matched the file's calibration CRC, `712EFE11`, before normal cleanup/reset.

The saved USB OUT submissions contain the same 144 network requests as the write
log, in the same order. Their 96 calibration payloads and block checksums match
the corresponding backup bytes. The one erase and all 96 programming requests
each have one correctly routed, zero-status reply after the complete request
and before the next operation in PCAP record order. USB IN retains all 98 short
acknowledgements associated with upload and programming:

- One loader acknowledgement: `6C F0 10 76 80 78`.
- One erase acknowledgement: `6C F0 10 7D 05 00 00`.
- Ninety-six programming acknowledgements: `6C F0 10 76 00 00`.

The write phase contains 112 logged replies versus 113 USB network messages.
No logged reply is missing. The extra message is a second trailing cleanup
reply, `8C F0 10 54`, which remains in the report. Across the complete capture,
the audit retains five zero-data IN completions with non-success status
`0xC0010000`. Four separate adapter-error replies in bootstrap intervals outside
the actual-write phase also remain retained. The actual-write phase has no
adapter-error replies. The audit matches 549 OUT submissions to 549 completions
with no OUT pairing/status issues. Agreement with USB OUT submissions alone does not prove
physical bus transmission. The successful programming responses and independent
readback provide the separate controller evidence for this run.

A separate full read used the AL5 checkout's existing E54 reader, rather than
the corrected writer binary. It completed in 2:06.6636531 and exited zero. All
524,288 bytes matched the original backup, with zero differences. Both images
have SHA-256
`a3b010af7e04df03be699198920aac26ba0645c2ad608e72eacf0bc3970beb58`.
All seven flash ranges ultimately matched their CRCs. That read's CRC phase
retained seven no-response/requery events: two each for 0x060000, 0x040000 and
0x020000, and one for 0x008000. Two additional generic timeout lines belong to
the reader's bootstrap and are counted separately. These were host query retries,
with no reported CRC mismatch. This is not a claim that
the complete write/readback session had no retries.

The saved USB timings are consistent with the readback host's short receive
wait. In that reader source, `OBDXProDevice.Receive()` calls `ReadDVIPacket()`
without the configured timeout, selecting its 1,000 ms default; the ReadCrc
scenario specifies 3,000 ms. The separate recovery-checkout writer already
passes the configured receive timeout. USB shows the prewrite verification made
seven CRC queries for seven replies, while the post-write reader made fourteen
queries for seven replies. The 128 KiB replies arrived about 2.318 seconds after
the first complete request and the 96 KiB reply about 1.740 seconds afterward.
These observations explain the retry pattern without treating it as a CRC
mismatch; they do not demonstrate that the physical bus lost a response.

After the reader closed, the adapter-local inspection left GT network OFF
(`0200`) and speed 1x (`0600`). USBPcap closed through its owned pipe and exited
zero, with no retained process ownership or stderr. The supervisor reported
that peer closure cannot prove all driver-buffer contents were drained; that
limit remains in the saved receipt. The final PCAP is 1,016,188 bytes, SHA-256
`56143d5b8008c642f121ae388dddf55cfc64571309277832df9f51128a4145bb`.

Private controller images, logs and capture bytes remain under
`LocalOnly/usb_capture_setup_20261030/e54_gt_actual_write_01/`, with the original
backup retained in `e54_gt_pcmhammer_write_01/`. The public receipt records their
digests and the exact writer, library and E54 kernel inputs without including
the tune or raw USB payloads.

`analysis_final/actual_usb_audit.json` records the phase windows and ordered
request/response comparisons. `analysis_final/supplement/session_supplement.json`
retains bootstrap boundaries, adapter-local cleanup and CRC query timing.
`analysis_final/final_receipt.json` pins those reports and their audit scripts.
The last reader cleanup reply is carried into the adapter-local cleanup window,
where it also appears in the serial log; that inspection sends zero network TX
commands. This boundary reply is retained, not discarded to improve agreement.

This establishes a completed calibration erase/program operation and exact
full-image readback for this E54 bench run. USB observations concern the GT
acting as the active interface. They do not reproduce passive all-source
EFILive capture or its Mode 75 acknowledgements. AL5 programming and recovery,
interrupted E54 recovery, electrical noninterference and universal lossless
monitoring remain unqualified. Live AL5 writes remain disabled.
