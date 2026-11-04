# Four write qualification priorities

Continuation note (2026-11-04): [current work status](WORK_STATUS.md) consolidates later backup, finalizer and watchdog results. These priorities do not replace the newer evidence owners.

The [security and backup continuation](SECURITY_AND_BACKUP_PATH.md) connects session-bound saved security and correlated acquisition epochs to this executor. It preserves the physical qualification boundaries below.

The spare is still in transit. This checkpoint prepares an unchanged-calibration bench candidate; it does not authorize live upload, execution or writes.

## 1. Connect the executor with staged stops

`WriteManager.WriteAL5UnchangedCalibrationAsync` now reaches the explicit AL5 execution gate. That public gate returns `LiveDisabled` before accessing the vehicle, inputs or cancellation token. There is no force flag or environment override.

Behind that gate, the internal asynchronous executor binds the dispatcher to the production Vehicle send/receive methods. Scripted-port tests exercise this binding through the real OBDX framing. Boundaries remain before the security key, programming entry, loader upload, erase, and after erase before data. The last boundary is already destructive and is not a safe entry test.

The first-write executor accepts only calibration bytes matching the original reference. The separate offline candidate still supports custom-BIN rehearsal. Security evidence and checksum retries require explicit review; no captured key becomes a fresh-controller default.

Each I/O link belongs to one session. A timeout or cancellation retains the outstanding transport task and its owner. Late completions can be observed, but cannot restart the stopped dispatcher. The binding does not clear queues, reset hardware, dispose an active port or retry an uncertain send. Reply time starts at send completion; total-session time still includes the send.

## 2. Qualify the arriving spare

Record its actual hardware/service identity and use matching wiring information before power. Then qualify ordinary identity, fresh security, entry, watchdog and safe exit in stages. Saved captures and scripted responses establish neither the spare's identity nor fresh security support. Algorithm 50 is not generalized. A separately reviewed live binding is still required before these stages can run.

## 3. Retain original and prepared backups; demonstrate recovery

Programming entry can change persistent banks at `0x4000..0x7FFF`. The executor pauses before erase until all 16,384 saved prepared-bank bytes are explicitly supplied. It retains the original full reference and its hash, plus a separate prepared-bank hash and changed-byte count. The expected post-write image uses the prepared banks while preserving the original reference for restoration. Later bank changes fail the preservation comparison.

Supplying a file does not prove independent acquisition. Historical reconstructed references, calibration-only reads and modeled memory cannot close this gate. Obtain qualified original coverage before programming-style entry, then qualify the prepared state and full independent post-write readback. Never fill unknown bytes with SPS data, zeroes or erased values and call that a backup.

A12 recovery, physical address mapping and vendor recovery remain unproven. Record available external-flash equipment or repair access and demonstrate an applicable recovery method on the spare before intentional interruption experiments. A spare alone does not prove recovery.

## 4. Unchanged calibration first

After the physical gates and reviewed live binding, run one unchanged-calibration write with capture, validate finalization and cleanup, and compare independent readback against calibration, collateral, marker and protected-region expectations. Only then consider a custom calibration. The installed truck TCM is not the experimental target.

## Validation and arrival packet

The execution-binding suite covers three capture-derived sessions in both adapter-ack orderings, stage boundaries, pending-task ownership, faults, cancellation races, deadlines, backup review and preservation mismatch. Ambiguous no-reply repetitions are explicitly omitted from derived sessions; this is not an exact replay or proof of lossless capture. All physical verification/readiness flags remain false, including after a matching saved comparison.

Run `dotnet run --project Tools/AL5/ExecutionBindingTest/ExecutionBindingTest.csproj -- --receipt RECEIPT LOADER FULL_REFERENCE TEMPLATE CALIBRATION [TEMPLATE CALIBRATION ...]` with retained local evidence. The test has no hardware mode. Existing dispatcher, captured-candidate and generic writer-gate regressions remain required for changes to their shared code.

Freeze the app, source, receipts and capture helpers together. On arrival verify the sealed hashes, then follow the [bench run sheet](FIRST_WRITE_BENCH_RUN_SHEET.md). Repeat only checks justified by changed source, target mismatch or observed failure.
