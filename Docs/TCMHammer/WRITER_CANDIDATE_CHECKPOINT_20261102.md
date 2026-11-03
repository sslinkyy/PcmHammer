# Calibration writer candidate checkpoint: 2026-11-02

The primary deliverable is now the calibration writer candidate. The revised 30-point plan assigns points 1-24 to writer implementation/validation and points 25-30 to backup, capture and bench qualification preparation.

## Implemented and exercised

- Shared `AL5CalibrationWriteCandidate` binds the captured EFILive loader, constructed 195-request plan, fixed setup/cleanup actions and an explicit full saved reference.
- The dynamic-key boundary has no default captured-key replay. Checksum retry review returns only the retained rejected packet; timeout or malformed observations stop the candidate.
- Independent-file comparison checks calibration, collateral and completion marker and separately reports changes to persistent banks and other protected regions.
- The offline tool exports candidate inputs, hashes, generated programming packets, expected bytes and a substituted-payload saved-session rehearsal. It does not compare its own expected image and call that independent verification.
- A frozen package helper copies the already built app/tool, source and evidence and performs a quick hash-only check on arrival. It never launches the application, tests, capture or hardware.

## Validation performed

All three retained calibration captures pass the integrated writer tests. Each has 192 positively acknowledged blocks, with 15, 20 and 19 checksum rejections respectively. There are 224, 232 and 227 interruption checkpoints including captured repeats and phase boundaries; these are offline observations, not distinct physical recovery tests. Modified checksum-correct calibration data passes generated-payload rehearsal for each capture.

Forty-two native-loader/program/finalization/interruption tests pass with pinned loader/LOW/HIGH inputs and native cases enabled. These still use suppressed flash/MMIO operations and synthetic effects where documented by the models. They do not qualify physical programming or recovery.

The Windows build succeeds with existing warnings. The exact application `PcmLibrary.dll` matches the library used by the 210-combination AL5 write-gate test, which rejects all combinations before vehicle access. No app was launched. Seven native capture-supervisor cleanup cases pass, plus 29 capture planning/parser tests. Six package-integrity tests check corruption, missing/added files, source drift, output preservation and path/authority rejection.

The offline exporter reaches AwaitingSavedVerification with 192 positive program observations for the retained control/reply template. Re-running into an existing output is rejected without changing evidence; partial references are rejected before outputs are created.

## Remaining gates

The source is a transport-free writer candidate compiled into PcmHammer; the UI has no live AL5 writer command and no enabled live adapter executor. Fresh target/security, physical entry/reset/watchdog/transport, original pre-entry preservation data, independent physical readback and a demonstrated recovery procedure remain unqualified. The bench harness pinout must match the actual spare; no guessed wiring instructions have been added.

This checkpoint supports immediate staged bench qualification once the spare and required setup are available. It does not establish that the first bench session can safely erase/program the spare. Only a source change, hardware mismatch or observed failure calls for targeted additional offline checks.
