# TCM Hammer

TCM Hammer is the transmission-controller section inside the Windows PCM Hammer application. Current support focuses on Allison AL5. Adapter selection, cancellation and logs use the existing application infrastructure.

## Available commands

The top-level TCM Hammer menu groups the AL5 identity probe, direct Mode 0x23 calibration read, offline BIN comparison, and offline saved-flash assessment. Read operations require an initialized adapter and are disabled while another operation runs. File-only operations remain available without an adapter. The calibration reader covers 0x08000..0x15FD7 (57,304 bytes), not a complete flash backup.

## Source and research

All existing AL5 assets belong to this section. Their paths remain stable so scripts, tests and prior evidence references continue to work:

- [Shared AL5 implementation](../../Apps/PcmLibrary): AL5-prefixed reader, checksum/inspection, security evidence and offline programming-session classes.
- [Offline tools and capture utilities](../../Tools/AL5): Python/native emulation, captured-session analysis and C# safety tests. Capture utilities have their own explicit device-access boundaries; this menu does not launch them automatically.
- [Read-only kernel research](../../Kernels/AL5-ReadOnly): offline runtime, entry/transport and ownership work.
- [AL5 research and evidence](../AL5): retained protocol, SPS/EFILive, mapping, checksum, verification and recovery documentation.
- [Reset-cause and retained-marker audit](../../Tools/AL5/audit_a12_reset_routing.py): source-pinned offline reset routing and software transmission attribution.
- [Temporary A12 alias model](../AL5/A12_RECOVERY_MODEL.md): conditional reset-to-boot-session emulation; physical recovery remains unverified.

The offline writer rehearses loader entry, erase, programming, finalization, verification and failure handling using retained evidence. It has no authorized live write path. Creating this section does not enable kernel upload, execution, erase, programming or automatic retries.
