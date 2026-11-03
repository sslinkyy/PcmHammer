# TCM Hammer

[Resident reply freshness](RESIDENT_REPLY_FRESHNESS.md) joins native scheduling, submission, status events and startup-state clearing. Interface reset can requeue an old reply; physical freshness remains unqualified.

[Resident pre-entry bank reads](RESIDENT_PREENTRY_BANK_BACKUP.md) traces a bank-first alternative before programming preparation, with native dispatcher coverage and a file-only resident-bank exporter. Live reads and writes remain disabled.

[Security and backup continuation](SECURITY_AND_BACKUP_PATH.md) adds a profile-bound security exchange and an ordered correlated original/prepared acquisition path with a file-only exporter. Physical qualification and live operations remain disabled.

[Four write qualification priorities](FOUR_WRITE_QUALIFICATION_PRIORITIES.md) records the asynchronous execution binding, mandatory original/prepared backup distinction, and remaining physical gates while the spare is in transit.

[Calibration writer candidate](CALIBRATION_WRITE_CANDIDATE.md) describes the constructed calibration-write lifecycle, custom-BIN rehearsal and full preservation comparison. The [30-point writer-first plan](PRE_ARRIVAL_30_POINT_PLAN.md) and [first-write bench run sheet](FIRST_WRITE_BENCH_RUN_SHEET.md) organize the remaining qualification work without repeating completed offline campaigns on arrival.

[Writer dispatch checkpoint](WRITER_DISPATCH_CHECKPOINT_20261102.md) adds immutable send/reply ownership, stage boundaries, profile/deadline checks, production Vehicle/GT integration tests and the GT send-result fix.

TCM Hammer is the transmission-controller section inside the Windows PCM Hammer application. Current support focuses on Allison AL5. Adapter selection, cancellation and logs use the existing application infrastructure.

## Available commands

The top-level TCM Hammer menu groups the AL5 identity probe, direct Mode 0x23 calibration read, offline BIN comparison, offline saved-flash assessment, and offline calibration-write preparation/export. Read operations require an initialized adapter and are disabled while another operation runs. File-only operations remain available without an adapter. The calibration reader covers 0x08000..0x15FD7 (57,304 bytes), not a complete flash backup.

[Write qualification plan](WRITE_QUALIFICATION_PLAN.md) records the application-to-boot chain, historical reader-to-writer validation and remaining physical gates.

[Calibration sector policy](CALIBRATION_SECTOR_POLICY.md) specifies the offline erase allowlist, span checks and collateral/marker preservation contract.

[Preparation status paths](PREPARATION_STATUS_PATHS.md) distinguish native errors/readback mismatches and pending frames. [Spare bench qualification](SPARE_TCM_BENCH_QUALIFICATION.md) defines the future hardware gates.

[Full-flash reader rehearsal](FULL_FLASH_READER.md) covers the complete fixture, reset-derived native copy, inherited runtime state and pre/post-entry provenance.

## Source and research

All existing AL5 assets belong to this section. Their paths remain stable so scripts, tests and prior evidence references continue to work:

- [Shared AL5 implementation](../../Apps/PcmLibrary): AL5-prefixed reader, checksum/inspection, security evidence and offline programming-session classes.
- [Offline tools and capture utilities](../../Tools/AL5): Python/native emulation, captured-session analysis and C# safety tests. Capture utilities have their own explicit device-access boundaries; this menu does not launch them automatically.
- [Read-only kernel research](../../Kernels/AL5-ReadOnly): offline runtime, entry/transport and ownership work.
- [AL5 research and evidence](../AL5): retained protocol, SPS/EFILive, mapping, checksum, verification and recovery documentation.
- [Reset-cause and retained-marker audit](../../Tools/AL5/audit_a12_reset_routing.py): source-pinned offline reset routing and software transmission attribution.
- [Temporary A12 alias model](../AL5/A12_RECOVERY_MODEL.md): conditional reset-to-boot-session emulation; physical recovery remains unverified.

The offline writer rehearses loader entry, erase, programming, finalization, verification and failure handling using retained evidence. It has no authorized live write path. Creating this section does not enable kernel upload, execution, erase, programming or automatic retries.
