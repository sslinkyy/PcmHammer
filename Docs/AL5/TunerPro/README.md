# AL5 validated core v0.3

Imported from the existing handoff package without regenerating the definition.
Use only a 57,304-byte calibration segment covering TCM addresses
`0x08000–0x15FD7`, OS 15184109 / calibration 15183960. The XDF subtracts
`0x8000` from native addresses. It is not for a CTZ or a 1 MiB editor image.

The mapping validation records retain their original confidence. D5100–D5115
are exact sequence/record-family mappings, not marker-differential proofs.
D5233 and the raw `0x10A24` entry remain research items as described in the XDF.

The target sheets are the existing minimal 1→2 pressure/volume proposal.
Timing, RPM, torque authority, TCC and other shifts stay stock. They are offline
development targets; neither the XDF nor the sheets authorize flashing.

The imported XDF contains an older EFILive save/flash suggestion. That suggestion
is not applicable to this project: the user has no FlashScan. Follow the current
handoff instead. Native four-byte checksum synthesis and AL5 programming remain
unproven. No edited BIN is flash-ready.

Reference calibration BINs and proprietary EFILive objects are deliberately not
included. Run the tools under `Tools/AL5` with local file paths. Preserve original
v0.3 here; expanded definitions belong in separately versioned files.
