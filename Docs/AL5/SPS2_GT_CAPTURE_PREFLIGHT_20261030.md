# SPS2 / GT capture preflight (2026-10-30)

Status: preparation only. No capture, vehicle request, driver change, subscription purchase, or flash was started. AL5 live writing remains disabled.

## Coverage evidence

OBDX lists Techline Connect SPS2 as supported through its J2534 driver. Tech2Win uses a separate D-PDU interface; Tech2Win installation alone does not establish SPS2 readiness.

- https://obdxpro.com/j2534-software/
- https://obdxpro.com/setup/
- https://obdxpro.com/downloads/

The ACDelco TDS public Resources > SPS Calibration Information action returned: "You must be logged in to use SPS Calibration." The user has no TDS account. VIN-specific AL5 coverage is therefore unverified, not rejected. The saved VIN was located in private E54 logs; no fresh vehicle identification was performed. Service number 15768288 and CIN 18000W00027 remain the user-provided AL5 identifiers.

https://www.acdelcotds.com/subscriptions

The public page displayed SPS2 single-vehicle access at USD 51, expiring at the earlier of 30 days or a programming count equal to the vehicle's programmable-module count. No item was added to the cart. Pricing and entitlement must be checked again before purchase. This does not prove a complete flash image, a forced rewrite of an unchanged calibration, or recovery capability.

## Read-only local inventory

- 32-bit PassThruSupport.04.04 registration: OBDX Pro - GT.
- FunctionLibrary: C:\Program Files (x86)\OBDX Pro\J2534\OBDX Pro GT\OBDXGT_J2534.dll.
- DLL file version: 1.11.9585.24471; SHA256: da13c7d84621af78f76c228383a16b2b0e4d3d45961da2fc90ae3a62897e395a.
- J1850VPW and J1850VPW_PS flags are 1. These are advertised capabilities, not a successful SPS2 hardware test.
- ConfigApplication points to OBDXGT_J2534Config.exe in that directory, but the file is absent. EnableLogging is 0. Neither registration nor logging was changed.
- Tech2Win 2.4.02 and GT Tech2Win driver 1.8.9713.20025 are registered.
- No Techline Connect/SPS installation was found in the checked uninstall records and GM program/data directories; this is not an exhaustive disk inventory.
- USBPcap 1.5.4.0 is installed. Only command help was run.

## Capture preparation

Tools/AL5/prepare_sps_usb_capture.py writes a JSON plan only. It never launches a process or opens an adapter. Without a current hub/address pair it emits no capture arguments. Explicit binding selects one USB address, descriptor injection, 65535-byte snap length and a 16 MiB capture buffer. Output creation refuses overwrite.

The generated private plan is LocalOnly/sps2_capture_preparation_20261030/capture_plan.json. It is deliberately unbound. Three offline unit tests pass, covering the unbound state, single-device arguments and invalid/partial bindings.

Before an authorized capture:

1. Confirm VIN-specific TCM coverage after the user signs into TDS. Record offered controller and calibration identities without initiating programming.
2. Establish Techline installation and GT driver compatibility, including the missing configuration utility. Do not change the driver during programming.
3. Verify fresh GT USB topology and identity; do not reuse an earlier USB address. Confirm the capture output is growing before any separately authorized SPS communication.
4. Give SPS exclusive ownership of GT. Do not open its serial port with PcmHammer or a GT listener concurrently. USBPcap observes the USB connection independently.
5. Retain raw USB traffic, SPS logs, selected calibration metadata and operation/shutdown timestamps. Stop only the owned capture process after cleanup.

USB traffic cannot by itself prove lossless physical-bus monitoring. The J2534 driver's traffic must be decoded from this session; prior PcmHammer DVI byte-window assumptions cannot be applied blindly. A successful SPS event would still need coverage analysis to establish what flash regions were actually written.

## Installed SPS2 recognition follow-up (2026-10-30)

Observed Techline Connect 26.9.11.0 Production OCF, SPS2 26.10.5.0. Its welcome screen reports "Diagnostic Tool Ready!" and "J2534 OBDX Pro;OBDX Pro GT;04.04;". The user confirmed the adapter is not connected to the truck. Windows reports the expected GT USB instance present and OK on COM9. No Auto Detect VIN, tool selection or programming control was clicked.

The displayed VIN is blank and the vehicle selectors show Chevrolet / 2003 / Medium Duty Truck / ANY / LB7. These are not validated vehicle identification and must not be used as confirmation of truck fitment.

Fresh inventory preparation: LocalOnly/sps2_capture_preparation_20261030/enumerate_sps_gt_01.ps1, copied from the existing verified inventory procedure with a fresh receipt filename. Not launched; no elevation requested, USB capture started or serial port opened. The plan-only unit suite passes three tests.

Capture readiness is blocked by the console stop self-test. A correctly hidden CREATE_NEW_CONSOLE launch of the existing supervisor reached the fixture but the fixture exited before AttachConsole. surrogate_ready.json records NULL standard input and console_mode_valid=false. Evidence: LocalOnly/usb_capture_setup_20261030/sps_stop_selftest_02. No USBPcap process was involved. The older console launch assumption must be repaired and the clean-stop fixture passed before relying on this helper for programming capture. This is a capture-helper failure, not an SPS2/GT recognition failure.

## Capture-helper correction and offline qualification (2026-10-30)

The previous follow-up selected the obsolete console supervisor. The existing duplex-pipe supervisor is the supported path (see USB_CAPTURE_COMPARISON.md). Its native fixture now passes when launched with pythonw.exe and DETACHED_PROCESS. python.exe with CREATE_NO_WINDOW did not satisfy the consoleless precondition on this machine. Microsoft documents that GUI standard handles may be absent and that console handles require an appropriate inheritance/attachment relationship:
https://learn.microsoft.com/en-us/windows/console/getstdhandle
https://learn.microsoft.com/en-us/windows/console/console-handles

Corrections:

- The private console helper now refuses direct execution before any launch; its shared definitions remain importable by the pipe helper. No old evidence was removed.
- The pipe helper launch instructions now require pythonw.exe with DETACHED_PROCESS. Fixture-only stop modes permit exercising explicit stop files and duration expiry without hardware.
- prepare_sps_usb_capture.py identifies the pipe supervisor and its receipt-based stop mechanism. Proposed child arguments now match its 1 MiB snap length, 16 MiB buffer and duplex stdout output. They are not standalone shell capture instructions. Descriptor injection is not included in this supervisor invocation; the older plan's direct-file arguments are superseded.
- validate_sps_capture_stop.py is a repeatable Windows offline runner using only native fixtures. It has no hardware launch mode and retains fresh evidence directories.

Validation: seven native cases passed (ready stop, external stop, duration stop, wrong-session stop rejection, receipt-publication failure, fsync failure, file-close failure). Every case retained all 65,537 expected fixture bytes with SHA256 237356e18b503616912abb8ffaed3a72591e397d4ac294c4637917d48a3f529d and observed native child exit 0 after pipe closure. Wrong-session and injected-failure cases remain reported as failures, not successful captures, while still cleaning up their child. The three fault cases also verify all tracked native handles are closed. Three capture-plan unit tests pass. No USBPcap or fixture process remained in the final process check.

Private evidence: LocalOnly/usb_capture_setup_20261030/sps_stop_validation_59207daabea248d4800ecc5f0732e2a3.json, including helper hashes and each receipt path. Earlier failed console receipts remain intact. The helper changes reside in the existing ignored LocalOnly directory; the runner and plan correction are tracked.

The offline shutdown blocker is resolved. This establishes fixture byte retention and process cleanup only, not real USB capture, complete driver-buffer drain or programming readiness. The truck remained disconnected; no adapter was opened and no flash was started. Fresh elevated USB topology inventory and an actual USB capture check remain required before a later programming capture.

## Real GT-only USB capture smoke test (2026-10-30)

User confirmed GT directly connected to the truck, USB connected, ignition OFF and AutoCal disconnected. No SPS connection controls were used and no adapter command was sent by the capture workflow. User manually approved elevation separately for USB inventory and capture.

Fresh signed-USBPcap inventory identified the expected GT on USBPcap2, address 27. A ten-second capture (plus bounded five-second drain) using the corrected detached pythonw pipe supervisor completed successfully: 8,206 bytes, 178 records, USBPcap exit 0, supervisor exit 0, graceful_stop_observed=true, ownership_retained=false, empty stderr and all cleanup operations successful. No USBPcap/PcmHammer process was present in the final check.

The offline parser consumed the entire classic PCAP with no structural, pairing or timing findings. All records belong to bus 2/device 27: endpoint 0x01 has 44 submissions and 44 completions; endpoint 0x82 has 45 submissions and 45 completions, carrying 308 completion bytes. The 44 OUT payloads are identical, 3a0200fec5. IN payloads comprise 44 seven-byte responses, one split across two USB completions. Command 0x3A is the ReadVoltage command family in Apps/PcmLibrary/Devices/OBDXProDevice.cs; the exact 0xFE variant was not decoded here. Existing host-to-adapter polling was observed while SPS2 was open; attributing it to SPS2 is an inference, not process attribution from USBPcap.

The capture helper did not achieve a full one-second quiet tail because polling continued. It stopped at its bounded drain deadline with zero pipe bytes available, and explicitly retains unknown inflight/driver-buffer state. Successful capture startup, data recording and clean process shutdown are verified; losslessness and physical VPW behavior are not established. No flash started.

Evidence: LocalOnly/usb_capture_setup_20261030/sps_gt_usb_smoke_01/{capture.pcap,receipt.json,pcap_inventory.json}; PCAP SHA256 fd46df78e2851cb8515512f557a7a25663e55fe1d464714273b86757b6e56c14. Inventory and launcher receipt are under LocalOnly/sps2_capture_preparation_20261030. The short capture is stopped; a fresh recording must be active before later authorized SPS identification/programming.
