# PCCS native CAN route versus saved AL5 resident firmware

## New command-level comparison

`compare_pccs_resident_can.py` executes the existing pinned x86 PCCS WriteData
model, then hands each generated ordinary payload to the saved M68K AL5
resident dispatcher model. This is a deliberate offline payload handoff, not
an end-to-end CAN session. The report records both source hashes and the
resident code digest in `PCCS_RESIDENT_CAN_COMPATIBILITY_20261030.json`.

With CCP and QuickWrite disabled, native PCCS builds command `22`, a BE24
address and up to four data bytes. Fifteen comparison cases cover addresses
`0x8000`, `0x8004`, `0x20000`, `0x20004`, and `0x1FFFC` under injected resident
identifiers `0x3F8`, `0x3F9`, and the rejected `0x2F8`. Both accepted identifiers
reach the trapped word-program primitive with exactly the intended address,
count and synthetic data. The send-helper output echoes command/address with
the injected zero primitive status. The wrong identifier reaches neither
primitive nor response helper.

This connects two previously separate native findings: the PCCS writer payload
and AL5 resident programming dispatcher agree at the command level, including
an application-region address. It is stronger evidence than a shared LCT name.
It does not establish flash execution or successful programming. PCCS success
callbacks and the controller primitive status are independently synthetic;
controller replies are not fed through the PCCS receive parser in this test.

The saved LOW image is hash-pinned editor evidence, not an independently read
current boot backup. Its resident dispatcher accepts a CAN-style message object
and its send helper uses standard/extended identifiers and message objects,
as previously described in `RESIDENT_COMMAND_DISPATCH.md`. The handoff bypasses
the actual wire-ID decoder, CAN peripheral and all transport. It must not be
used as a packet recipe.

## Interface requirements supported by local evidence

The native PCCS connection loader resolves RP1210 ClientConnect, SendMessage,
ReadMessage and SendCommand exports. Its ordinary CAN formatter supports
29-bit IDs, and the optional initial probe uses an 11-bit format. The analyzed
CAN branch sets a local bitrate field to 250000; that is host intent, not a
measurement of this AL5's bus. See `PCCS_DRIVER_FILTERS_BUS.md` and
`PCCS_FALLBACK_TRANSPORT_TRANSITION.md` for source anchors and limits.

A fresh parse of installed Devices.xml finds 15 `TCM_1K2K3rd` records, all
Protocol=CAN, displayed as J1939. Specific catalog candidates include:

- Softing CANusb, library SOFTUSB, device 111.
- NEXIQ USB-Link 2, library NULN2R32, device 1.
- DPA 5 USB, library DGDPA5MA, device 1.
- Noregon DLA+WL 2.0, library DLAWIR32, device 100.
- Vector CANcaseXL/VN16xx, library VECTCDXL32, devices 21/55.

These are installed software catalog entries, not buying recommendations or
physical qualification for this exact module. The local readme also names
NEXIQ USB-Link2, DPA5 and Noregon DLA+ Wireless 2.0 driver requirements. Those
historical versions are not asserted to be current supported releases.

WRW_OPT.INI currently says SOFTUSB.DLL, CAN, Device=1. That file selection is
not an observed loaded driver or hardware connection; its Device=1 differs
from the catalog's Softing device 111. No setting was changed. A working vendor
installation must supply the device ID expected by its actual driver, rather
than blindly copying a catalog or configuration value.

The catalog does not list OBDX Pro GT, OBDLink SX or AutoCal. Their ability to
handle some CAN traffic would not by itself supply the RP1210 API PCCS expects.
No compatible PCCS bridge for those adapters has been established here.

## What is still needed for the user's module

The saved firmware provides a plausible resident CAN programming endpoint.
It does not identify which connector pins expose it, whether this truck's
harness routes those pins to an accessible connector, or whether the installed
TCM's hardware/transceiver and boot state match this path. Do not assume CAN is
available at OBD pins 6/14 simply because the program offers CAN.

The exact GM/Allison hardware or service part number is the next identifying
input needed to resolve the physical module/harness question. Software OS and
calibration numbers do not substitute for it. Before a full-flash capture we
also need the application-to-resident entry sequence, physical identity reply,
matching file/erase scope, and a compatible driver/interface. Nothing in this
test qualifies interruption recovery or preservation of the boot region.

## Validation

The fifteen native payload cases pass with every flash primitive and send
helper intercepted. Two new identity/report tests and the existing native
writer, driver-connect and transport-envelope suites pass (18 tests, no skips).
No PCCS application, DLL, adapter or controller was executed. All changes are
offline; live writes remain disabled.
