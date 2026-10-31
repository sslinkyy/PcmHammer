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
