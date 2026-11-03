# AL5 calibration writer candidate

Updated 2026-11-02. Writing is the main workstream in the [30-point plan](PRE_ARRIVAL_30_POINT_PLAN.md). This is a compiled, transport-free candidate, not an enabled live writer. No adapter or controller is accessed by the tools below.

## Implemented candidate

`AL5CalibrationWriteCandidate` joins the captured EFILive VPW 1x lifecycle to the constructed packet plan and an owned full saved reference. It pins the 1,590-byte write loader SHA-256 to `b545d9b2d078662466ab32d9cdeb5b3c38c840135e8aeca09f33760ec66780fa` and requires the calibration's native checksum and family anchors.

The candidate constructs fixed setup/boot/identity/cleanup requests from the existing parser's own rules. A dynamic security key remains a missing-evidence action: the candidate neither generates a generic key nor defaults to replaying the captured pair. A recorded exchange can be rehearsed without becoming fresh authorization.

The programming plan has 195 unique requests: loader, erase, 192 data blocks and finalization. Data covers 0x8000..0x1FFFD using the selected calibration plus explicit collateral bytes. The marker is finalized separately. Host destination policy does not prove the captured loader's physical effects or chip protection.

A checksum rejection exposes the exact retained packet for explicit offline retry review. A timeout is a stop. Captured repeats without a preceding reply remain counted uncertainty; they do not establish a live retry policy. Invalid observations latch a stop in the candidate. Stopped sessions cannot resume.

After cleanup, comparison requires all 1 MiB of saved readback. Calibration, collateral and marker are assessed separately. Persistent-bank changes outside the erase sectors are counted separately from other protected changes. Even if preparation legitimately changes those banks, the candidate does not silently accept the difference as preservation. Expected images are predictions, not backups or independent readback.

## Offline preparation command

From the repository root:

```powershell
dotnet run --project Tools/AL5/WriteCandidateTool.csproj -- LOADER.bin CALIBRATION.bin FULL_REFERENCE.bin NEW_OUTPUT_DIRECTORY SAVED_CONTROL_TEMPLATE.txt
```

The optional final argument is an existing selected capture corpus in `T HEX` / `R HEX` format. Programming payloads are constructed from the new inputs; control/reply observations remain from the saved template. This is labeled a substituted-payload offline rehearsal, not evidence of a successful custom flash. The tool does not fabricate independent readback to complete its own verification.

Outputs include the 195 requests, complete reference, calibration, loader, expected full image, hashes, rehearsal trace and candidate report. Existing output directories are rejected. These artifacts can contain proprietary firmware or vehicle-specific evidence; retain them privately under `LocalOnly`, not in the public source repository.

Without a template, the tool constructs the plan and remains at Setup. With a complete matching control/reply template, it must reach AwaitingSavedVerification with 192 positive program replies. Neither result authorizes execution.

## Validation

`CapturedProgramImageTest.csproj -- --writes` now tests the candidate with all three retained calibration captures. It checks generated control packets, the dynamic-key boundary, checksum retry ownership, a changed checksum-correct calibration, corruption in calibration/collateral/marker/persistent/other protected regions, and interruptions at every captured pending program block plus phase transitions. The synthetic full reference is explicitly not an original controller backup.

The Windows PcmHammer build includes the shared candidate. The TCM Hammer menu retains its existing read/file commands; no live writer button or upload backend is enabled. `GateTest.csproj` accepts `AL5CandidateLibraryPath` so the rejection test can run against the exact frozen application library instead of a stale default build.

## First bench qualification, without another broad offline cycle

Before arrival, freeze the compiled app/tool, exact sources, validation reports and capture helpers with `freeze_bench_candidate.py seal`. On arrival, `verify` checks their hashes without compiling, emulating or accessing hardware. Source drift is reported explicitly if `--repo` is supplied. Only changed or failed areas require new offline checks.

Proceed through the [bench run sheet](FIRST_WRITE_BENCH_RUN_SHEET.md). Fresh security, physical programming entry/watchdog behavior, a qualified preservation baseline, live transport execution and recovery remain hardware/implementation gates. This checkpoint does not claim that plugging in the spare immediately permits a flash.
