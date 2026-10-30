# USB and serial comparison for the short-ACK investigation

The ordinary AutoCal E54 read on October 30 recorded **533,034 identical bytes**
at the selected USB bulk-IN completion boundary and in the raw serial log. The
malformed short ACK is already present in that USB data. This places the
observed discrepancy before the COM reader/logger; the physical receive path
and GT firmware remain unresolved. The loader ACK is still absent, and complete
capture is not qualified. Detailed results and qualification limits are below.

This experiment compares the GT's USB bulk-IN completions with every raw
`serial_rx` byte saved by `obdx_capture.py` during one ordinary AutoCal E54 bench
read. The [previous CRC-retention run](ACK_GAP_INVESTIGATION_20261030.md) contained
`6C F0 10 75 01 54 56`, where the matching HTX ACK began with `6D`. The enclosing
DVI checksum was valid. The read-loader ACK remained absent.

This comparison adds an observation before the COM reader/logger. It does not
observe VPW directly: USBPcap records Windows USB requests and completions, not
individual physical USB packets. Equal recorded streams would place the same
malformed bytes at both observation points; they would not distinguish GT
reception, firmware handling, or the physical bus. See the official
[capture limitations](https://desowin.org/usbpcap/capture_limitations.html).

## Setup checkpoint — 2026-10-30

The user completed the interactive installation of USBPcap 1.5.4.0 from the
[official release](https://github.com/desowin/usbpcap/releases/tag/1.5.4.0).
Installer SHA-256:
`87a7edf9bbbcf07b5f4373d9a192a6770d2ff3add7aa1e276e82e38582ccb622`.
Its Authenticode signature was valid before launch. The installed command-line
program and driver also have valid signatures and file version 1.5.4.0:

- `C:\Program Files\USBPcap\USBPcapCMD.exe`, SHA-256
  `8b13173e9453fda9914d707c732880de44081e20e1113b3a2c827abd7a28b15d`.
- `C:\Windows\System32\drivers\USBPcap.sys`, SHA-256
  `f340a8cf2f127be2e6b558586b76b51ba5e8c58c462a8d9eecc1955771cb2974`.

Before installation, the USB class had no UpperFilters or LowerFilters and no
USBPcap service key. After installation, UpperFilters contains `USBPcap`,
LowerFilters remains absent, and the USBPcap system driver reports stopped with
manual start. A PC restart is still pending at this checkpoint; installation
does not establish that capture works on this machine. The installer, registry
backup, source snapshots and verification receipts are private under ignored
`LocalOnly/usb_capture_setup_20261030/`.

The bench remains OFF. No capture program or serial session was started during
setup. No flash operation or USB-device restart was requested. Before resuming,
the user should save other work and restart Windows normally, leaving the bench
OFF. USBPcap's [installation guide](https://desowin.org/usbpcap/) requires a restart.

## Resume after restarting

1. Verify a new boot time, installed driver state, and USBPcap signatures. List
   capture interfaces and the device tree without opening a COM port:

   ```powershell
   $usbPcapCmd = 'C:\Program Files\USBPcap\USBPcapCMD.exe'
   & $usbPcapCmd --extcap-interfaces
   & $usbPcapCmd --extcap-interface $verifiedHub --extcap-config
   ```

   Set `$verifiedHub` only from the returned interfaces. Avoid no-argument
   USBPcapCMD, which can offer to restart all USB host controllers if filters
   are unavailable. Do not use that restart path.

2. Correlate the GT with VID `0483`, PID `5740`, serial `208534783845`, its current
   COM port, and its device address on the selected hub. The prior COM9 and any
   previous USB address are historical, not defaults. Retain the enumeration
   evidence separately. If identity is ambiguous, resolve it before capture.

3. Obtain the user's current bench connection and ignition state before adapter
   access. Start USB capture before the serial session, selecting only the
   verified GT device address. Keep AutoCal and other device payloads excluded:

   ```powershell
   & $usbPcapCmd -d $verifiedHub --devices $verifiedGtAddress -s 1048576 -b 16777216 -o $newPcapPath
   ```

   Do not add `-A`, `--capture-from-new-devices`, or `--inject-descriptors`.
   The 1 MiB snapshot and 16 MiB buffer are finite limits, not evidence of
   lossless capture. Verify the stop mechanism before starting a read. The
   program reads lowercase `q` as a console key event, so redirected stdin is
   not a dependable stop mechanism. There is no duration option. The later
   post-restart check below uses an owned duplex output pipe for normal exit;
   the command above alone does not provide that supervision. Do not rely on
   killing the capture process.

4. Preserve the previous diagnostic GT receive profile: fixed 4x, all sources,
   CRC-invalid frames retained, serial diagnostics and VPW error counters.
   Only AutoCal performs the ordinary E54 read. GT vehicle transmissions and
   live AL5 writes remain disabled. Record read completion, HTX, tune filename,
   ignition shutdown and GT OFF/settings restoration as in earlier runs.

5. Keep USB capture running through serial cleanup and close, allow a quiet
   tail, then stop it gracefully. Preserve the whole PCAP and JSONL; do not
   remove setup, cleanup, duplicates, or mismatching prefixes to force equality.

The exact CLI options and stopping behavior were checked against the
[1.5.4.0 command source](https://github.com/desowin/usbpcap/blob/1.5.4.0/USBPcapCMD/cmd.c).
The installation checkpoint did not verify hardware capture. The later
post-restart checks below establish startup, adapter-local reception and exit.

## Offline comparison

`Tools/AL5/compare_usb_serial_capture.py` opens files only. It supports original
classic PCAP with USBPcap link type 249; PCAPNG is explicitly rejected. First
inventory the recorded endpoints:

```powershell
python Tools/AL5/compare_usb_serial_capture.py --pcap CAPTURE.pcap --output NEW_INVENTORY.json
```

Then select the bus, device and bulk-IN endpoint from the retained identity and
inventory evidence; these values must not be guessed:

```powershell
python Tools/AL5/compare_usb_serial_capture.py --pcap CAPTURE.pcap --serial CAPTURE.jsonl --bus VERIFIED_BUS --device VERIFIED_ADDRESS --endpoint VERIFIED_IN_ENDPOINT --output NEW_COMPARISON.json
```

Receipts preserve full input and implementation hashes, selected-record offsets,
URB pairing findings, failed transfers, endpoint inventory, and bounded context
at the first byte difference. Successful selected completions are concatenated
in file order and compared literally with all logged `serial_rx` bytes. No
alignment, trimming, header repair, or deduplication occurs. Output files are
created exclusively. Inputs have an explicit per-file memory limit.

`literal_byte_agreement` is separate from
`selected_stream_agreement_qualified`. The latter additionally requires complete
record structure, successful serial-log termination, valid selected transfers,
nonempty data, and no unresolved URB pairing. Pending or orphaned URBs can arise
at capture boundaries; they retain uncertainty rather than proving loss.
Normal endpoint cancellation at COM close can also leave a failed completion;
keep it in the receipt and investigate its boundary context instead of calling
it an ACK loss or deleting it to obtain a pass.
Wall-clock timestamp regression is a timing warning and does not reorder data.
Classic PCAP has no capture-drop statistics, so even a qualified equality result
does not prove USB capture losslessness or physical VPW completeness.

Interpret differences only after checking identity, session boundaries and
truncation. If a malformed DVI ACK is already present in complete selected USB
data, it predates the COM reader/logger. If the corresponding USB data is correct
but the serial data differs, investigate the downstream host path. Neither case
alone proves that the GT changed a bit on the physical bus. An absent ACK in both
streams also leaves upstream reception and capture completeness unresolved.

The tests exercise file and CLI boundaries with synthetic PCAP/JSONL fixtures,
including endian variants, malformed lengths, duplicates, failed transfers,
selection, boundaries and exact mismatches. They do not qualify real USBPcap
capture or AL5 programming/recovery.

At the pre-restart checkpoint, all 12 new comparator tests passed, as did the
109 existing capture, speed, HTX-comparison and delivery tests. The parser also
accepted the saved CRC-retention JSONL with its successful terminal record and
reconstructed all 533,034 raw receive bytes from 496 rows. That checked
compatibility with a real saved serial log; there was not yet a matching USB
PCAP from hardware.

## After restart — 2026-10-30

Windows reports a new boot at 01:45:42 Pacific, the USBPcap driver is running,
and both installed signatures remain valid. The user confirmed that AutoCal
and GT remain on the isolated E54 splitter with bench supply and ignition OFF.
The GT remains COM9 with USB instance
`USB\VID_0483&PID_5740\208534783845`.

An elevated, enumeration-only query maps the GT to `\\.\USBPcap2`, device
address **4**, and AutoCal to address 2. These are observations for this boot
and attachment, not permanent defaults. The Windows PnP address property was 6;
it must not be substituted for USBPcap's enumerated device address. The full
private receipt is `postrestart_elevated_inventory_02.json` in the setup folder.

Unelevated `--extcap-config` returned no device values despite exit code zero.
The tagged source silently permits this outcome when hub access fails; an empty
result does not establish an empty hub. Windows PowerShell's direct invocation
also failed to retain output from the GUI-subsystem executable. Explicit process
creation with redirected output and waiting for process completion resolved the
enumeration issue.

The initial console-stop experiments failed to provide usable console input to
the GUI-subsystem child. They used fixtures, not a vehicle capture. The working
capture supervisor instead launches elevated `USBPcapCMD` from consoleless
`pythonw`, with a private duplex, overlapped stdout pipe and `-o -`. It retains
the original child process handle, drains the pipe, then closes its own endpoint.
The tagged [reader implementation](https://github.com/desowin/usbpcap/blob/1.5.4.0/USBPcapCMD/thread.c)
handles the broken pipe by exiting its read loop normally. No process kill is
used. A native offline fixture preserved all 65,537 test bytes and exited zero
after observing broken-pipe error 109. These fixture results alone did not
qualify real capture.

Before the powered read, failure cleanup was changed to close the owned pipe
before attempting a failure receipt, retain the original child handle until
exit, and attempt file and handle cleanup independently. Four native fixture
checks covered normal operation and injected receipt-publication, fsync and
close failures. Each preserved the fixture bytes, observed normal child exit,
and released the observed native handles; injected failures remained failures.
The private validation receipt is `pipe_cleanup_validation_01.json`. No USB
device was accessed by those checks.

## Adapter-local USB check — 2026-10-30

With bench supply and ignition OFF, the first real capture opened and exited
normally at its 60-second limit before any queries ran. Its 24-byte header-only
PCAP establishes startup/exit, not receive coverage. The repeated check tied
one existing DVI `inspect` session to capture startup, after verifying a classic
PCAP header with link type 249. No vehicle network was enabled.

The GT identified as hardware `1.0.0.0`, firmware `1.0.2.0`, and reported network
state `0200` before and after inspection cleanup. The 5,065-byte PCAP contains
108 USB records, all for bus 2 / device 4. Actual endpoint inventory selects
bulk-IN endpoint `0x82`; no AutoCal device payload was recorded. All **156 receive
bytes** from 21 serial rows equal the recorded successful USB completions
literally, including setup and inspection. There was no trimming or alignment.

One zero-data bulk-IN completion at serial close has status `0xC0010000`,
consistent with cancellation. All selected submissions/completions are paired.
The conservative comparator keeps `selected_stream_agreement_qualified=false`
because of that status, despite exact byte agreement. The complete file has no
structural truncation. The owned capture then observed a one-second quiet tail,
closed its pipe, and exited zero with empty stderr. This does not establish
lossless VPW monitoring, physical noninterference, or complete driver-buffer
drain at stop.

Private evidence is under `LocalOnly/usb_capture_setup_20261030/usb_local_smoke_02/`.
The PCAP SHA-256 is
`22aab5dbbd80542c0f470a786f9a403a04de483d40d2ca1c9c90e46d143bd0fa`.
The equal 156-byte streams have SHA-256
`fb94e21274875c2fcc33fc35d578ed8891c0a2b9afdfcb3a6b6fba9a2d425c24`.
The short check cannot explain the prior missing ACKs. The subsequent ordinary
read retained its own inventory, serial log, PCAP, HTX and cleanup receipts.

## Simultaneous USB and serial read — 2026-10-30

The user confirmed supply and ignition ON on the isolated E54/LB7 bench.
USB capture started before opening COM9, and the serial log confirmed fixed
4x LISTEN ONLY, the experimental all-source filter profile, CRC-invalid frame
retention, serial diagnostics and error-counter sampling before EFILive began
its ordinary `E54_R.obj` read. No GT vehicle-send command or flash operation ran.

EFILive completed in **1:59**, displayed six valid segment checksums, and the
user switched ignition OFF before the 15-second shutdown countdown. The saved
tune is `12 lb7 E54_0000.ctz`. GT cleanup succeeded: network `0200` and all nine
observable settings matched their originals, including CRC validation `0701`.

All **533,034 recorded successful bulk-IN bytes** from bus 2 / device 4 /
endpoint `0x82` equal every raw serial RX byte, including setup and cleanup.
The equal streams have SHA-256
`80afc2c4e773c190b9d4231c901c344880e385d8078c7bd410d89ed57bf5a724`.
No alignment, trimming, duplicate removal or header repair was applied.

The short-ACK defect recurred between the request and data response for block
**0x073000**, versus `0x014000` in the previous CRC-retention run:

- Recorded VPW payload including CRC: `6C F0 10 75 01 54 56`.
- Corresponding repeated HTX ACK body: `6D F0 10 75 01 54`.
- Calculated CRC for the recorded `6C` body: `10`, not the recorded `56`.
- DVI envelope: `08 D9 3A 95 8C 07 6C F0 10 75 01 54 56 30`, whose checksum
  is valid. Its raw stream span is `[478839, 478853)`.

The DVI command byte occurs in PCAP record 6601 at file offset 763128. The
remaining 13 bytes occur in record 6603 at `[763215, 763228)`. Record numbers
are one-based; byte offsets are zero-based. The malformed VPW first byte is
inside the second completion, not on a completion boundary. Independent serial
mapping places the same envelope at JSONL line 2635, chunk offsets `[18, 32)`.
This identifies the malformed bytes in the retained USB data without relying
only on a decoded-frame report.

There are **395 network frames: 394 CRC-valid and one invalid**. All 128 block
slots contain an ACK-like observation: 127 valid and one malformed. The loader
ACK `6C F0 10 76 80 78` remains absent. Literal HTX comparison retains two
missing messages and five extras. The HTX's 392-message sequence is identical
to the attached/OFF baseline, with 128 unique addressed requests, no repeats,
and all 128 data blocks / 524,286 observed image bytes unchanged. The final two
flash bytes remain unobserved. This is still not a lossless capture.

The delivery log has 2,562 reads and 5,124 status snapshots, with no failed
reads or sampled driver errors. Maximum sampled input queue is 570 bytes;
maximum between-read gap is 16 ms. First addressed request to final data is
113.745 seconds, versus baseline 113.958 seconds. These sampled observations
do not measure adapter buffer high-water marks or establish losslessness.

The PCAP contains one paired zero-data non-success completion, status
`0xC0010000`, at serial close (record 7541). No selected URB pairing or structural
truncation issue was found. The comparator conservatively leaves
`selected_stream_agreement_qualified=false` because of that completion.

There is also a distinct capture-supervisor failure: after a one-second quiet
tail, pipe closure, PCAP flush/close and child exit code zero, publishing the
final status hit `PermissionError [WinError 5]` while replacing `receipt.json`.
Cleanup released the retained handles and ownership is false, but the original
receipt remains `state=failed` / `graceful_stop_observed=false`. The saved file
hash and byte comparison are retained facts; this is not reported as a wholly
successful supervisor run.

An offline held-reader test reproduced the same Windows error. The private
receipt I/O boundary now retries only sharing/access contention for a bounded
one-second window, retaining contention counts and failing if it persists.
The focused test succeeded after reader release, rejected a persistent lock
after 1.016 seconds, and completed 100 publications with 3,099 concurrent reads
without reader errors. A native pipe fixture then verified normal exit and all
65,537 expected bytes with the updated helper. The actual lock holder during
the read remains inferred; this fix was not retested on hardware. The original
failed receipt and capture files remain intact. Evidence is in
`receipt_sharing_test_04/result.json` and `pipe_publication_native_01/receipt.json`
under the private setup folder.

The recorded equality excludes the downstream COM reader/logger and DVI/JSONL
parsing as the introduction point for this observed malformed byte. It does
not separate physical VPW reception, GT firmware handling, and stages before
the software USB observation. The missing loader ACK's cause remains unknown.
Electrical noninterference, USB/VPW losslessness, AL5 flashing and recovery
remain unqualified; live AL5 writes remain disabled.

Private evidence is under
`LocalOnly/usb_capture_setup_20261030/e54_usb_read_01/`:

- `capture.pcap`, 858,094 bytes, SHA-256
  `4cc48979595dcc8b2a3d2865e872b1db195ed657c27924c4d928342613478ff0`.
- `gt_all_crc_retained_4x.jsonl`, SHA-256
  `69932950b420a44451c34ef25850bac0a8eee03ef9715d7735c3d02fad705c47`.
- `crc_retained_E54_R.htx`, copied from `20261030_023220_E54_R.htx`, SHA-256
  `49e0b14e2e5deb3581baca6c00f8ac29e264e2006d999aa017e4c736c448987f`.
- `usb_serial_comparison.json`, SHA-256
  `b4d67b8d3f500f8f818fa9576b0b3adb46d7972ac69584ae891f44cd91a94e63`.
- `usb_ack_correlation.json` maps the malformed envelope to PCAP and JSONL
  offsets and preserves the supervisor failure alongside the byte agreement;
  SHA-256 `ac5d4ed377aa407c0a49dbfd8ae74d1d54be3ccb4a515e006d1654aa076ddf12`.
- `aggregate_result_summary.json` collects delivery, HTX, counters, settings,
  completion and qualification facts; SHA-256
  `0dc9794b2687a4904ea6b5dc2fd3aeb28d4b431dc63e9eda76d4c838a60991b5`.
- `read_completion.json` records the six displayed checksums, ignition/shutdown
  confirmation and saved CTZ provenance. The tune's SHA-256 is
  `de96c9d2d6a6e0f3b8d85d21840ac82d808174e0c0085b6aac621663b352bc19`.
