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
active-interface test. Actual flash programming, AL5 writing/recovery,
electrical noninterference, and lossless passive capture remain unqualified.
