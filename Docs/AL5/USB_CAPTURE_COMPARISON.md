# USB and serial comparison for the short-ACK investigation

The next experiment compares the GT's USB bulk-IN completions with every raw
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
   lossless capture. Use a console with a verified graceful-stop path: the
   program reads lowercase `q` as a console key event, so redirected stdin is
   not a dependable stop mechanism. There is no duration option. Verify capture
   start/stop operation before beginning the read; do not rely on killing it.

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
The first hardware capture remains unverified at this checkpoint.

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

At this checkpoint, all 12 new comparator tests pass, as do the 109 existing
capture, speed, HTX-comparison and delivery tests. The parser also accepts the
saved CRC-retention JSONL with its successful terminal record and reconstructs
all 533,034 raw receive bytes from 496 rows. This checks compatibility with a
real saved serial log; there is not yet a matching USB PCAP from hardware.
