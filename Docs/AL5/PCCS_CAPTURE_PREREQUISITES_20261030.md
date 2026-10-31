# PCCS as an independent AL5 flash capture source

## Current installation recheck

The installed Winrw32.exe still matches analyzed SHA-256
`13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.
`PCCS_CAPTURE_PREREQUISITES_20261030.json` records a fresh read-only inventory
and Controller.ini hash. No application, driver, utility or vehicle ran, and
no installed configuration was changed.

There are 49 installed FIL files. Neither generic `APPANDCAL_UTILITY.FIL`
nor `ERASE_APP_UTILITY.FIL` is present. No `SPX1850.DLL` was found inside the
installed PCCS tree; this is not a system-wide absence claim.

Five Transmission FIL references in Controller.ini point to nonexistent
`C:\Program Files\...\DownloadApp\util` paths. Same-basename files exist at
the installed DownloadApp location for CALONLY, APPONLY and POONLY; none was
found for generic APPANDCAL or BootProg. These are candidates, not compatible
replacements. The Correct Boot value `B47` is retained separately as a non-FIL
setting, not treated as a missing pathname. Configuration values do not prove
which branch executes for standard LCT.

## Route assessment from retained native evidence

The existing [J1850 preparation analysis](PCCS_J1850_PREPARATION_COMPATIBILITY.md)
shows explicit programming-control disablement for TJ1850. The
[later-control investigation](PCCS_J1850_REENABLE_ADDRESS_MAPPING.md) finds
the J1850 exclusions persist in examined refresh handlers. Fresh native tests
against the current executable confirm these selected gates and the controller
target-forwarding behavior. The ordinary writer forwards controller index 3,
where TJ1850 read/security use address 0x18; no qualified mapping was found.
QuickWrite also contains a direct CAN-envelope path.

The [Softing UI trace](PCCS_SOFTING_UI_TRANSPORT.md) shows why choosing CANusb
and J1850 is not evidence of an actual VPW programming route. Re-running its
native tests does not open a driver or prove physical compatibility.

The retained installed-help analysis in [LCT programming](PCCS_LCT_PROGRAMMING.md)
describes LCT programming over CAN and excludes writes for the documented SPX
VPW box. The [native writer analysis](PCCS_NATIVE_LCT_WRITE.md) identifies a
standard-LCT native path separate from some FIL branches. Therefore the absence
of generic APPANDCAL is not, by itself, proof that all standard-LCT application
programming is impossible. Conversely, supplying it would not resolve the VPW
restrictions, target mapping, or controller compatibility.

## Practical conclusion

This installation is not yet an established alternative AL5 VPW flash source.
Enabling disabled buttons or correcting utility paths would not prove that it
can execute the same programming protocol as EFILive. No such edits were made.

The plausible independent route to investigate is native standard-LCT CAN
programming. Before proposing a capture, it needs evidence for the exact AL5
hardware's CAN programming endpoint, supported PCCS driver/interface, matching
controller identity and file content, and the selected operation's application
versus calibration erase/write ranges. None is supplied by the LCT label alone.
Application-plus-calibration also must not be described as a complete boot-area
backup or interrupted-flash recovery.

Allison DOC remains a diagnostic/session reference; no new DOC programming
implementation was established in this pass. The successful EFILive VPW
captures remain the demonstrated programming evidence for this controller.

## Reproducible offline checks

`audit_pccs_capture_prerequisites.py ROOT --output REPORT` reads installed files
without executing them. Unknown executable hashes, same-basename utility files,
and even a present SPX DLL never mark a route qualified. Two new tests cover
these cases and missing inputs.

The new audit tests plus the existing J1850 refresh, preparation, target and
Softing UI tests passed: 22 tests, no skips, with the pinned executable and
Unicorn available. Expected overwrite-rejection tests emit argparse errors;
the suite completed successfully. Live writes and broader live reads remain
disabled; no PcmHammer transport behavior changed.
