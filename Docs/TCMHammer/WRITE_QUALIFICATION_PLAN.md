# TCM Hammer AL5 write qualification

The [calibration writer candidate](CALIBRATION_WRITE_CANDIDATE.md) now joins constructed setup/programming/cleanup actions, a custom-BIN rehearsal and complete saved preservation comparison. Follow the [writer-first 30-point plan](PRE_ARRIVAL_30_POINT_PLAN.md); the [bench run sheet](FIRST_WRITE_BENCH_RUN_SHEET.md) reuses completed offline evidence rather than scheduling a broad arrival-day rerun.

Updated 2026-11-02. This checklist distinguishes completed offline work from remaining physical qualification. Live upload, execution, erase/program operations and automatic retries remain disabled. Historical images, modeled outcomes and captured acknowledgements do not authorize writes.

[Calibration sector policy](CALIBRATION_SECTOR_POLICY.md) now implements destination limits and full-sector baseline ownership in the offline EFILive profile.

## 1. Application to boot entry

Implemented `emulate_application_reset_chain.py` and its regression suite. The existing classifier, descriptor callback, native preparation caller and marker producer execute with synthetic request/state. Strict mode stops at 226F0 before persistent-storage implementation or even its return stub. A separately labeled conditional mode assumes subsystem/storage returns, reaches BFC1 with interrupt mask seven and observes eight self-branch iterations without watchdog servicing in that loop.

Exact application RAM FF8000..FFB7FF is hash-linked into a separate reset-model CPU. Reset injection and RAM retention remain explicit assumptions. For synthetic statuses 00/02/10/20, native reset entry preserves BFC1 and reaches B094 startup plus the synthetic Mode 34 reply. For 40/80/C0 it instead validates the saved OS and reaches the application boundary. Thus an external/power-up reset cannot be silently substituted for the candidate watchdog-reset transition.

The pinned boot store at 48E writes 84 to FFFFFA21. Under the conditional MC68336/376 SYPCR interpretation, this enables the software watchdog. The park instruction is a self branch, not RESET. Actual MCU, application-time watchdog state, timing, retained RAM and complete receive routing remain unqualified. See the [manufacturer register summary](https://www.nxp.com/docs/en/user-guide/MC68336376UMD.pdf), D.2.4 and D.2.12. Native execution here is emulator-only.

A deeper preparation case executes the real 226F0 caller using the historical bank bytes and the prepared application RAM. It reaches erase-wrapper entry 22B18 with target 6000. The wrapper is trapped before execution and the historical banks remain unchanged. This joins the request's preparation to a concrete persistent-storage boundary; it does not simulate successful erase/programming.

The failure continuation injects an erase-status error without changing bank contents, then executes the native copy wrapper until its copied RAM flash implementation would run. That implementation is intercepted before execution and given an explicit failure status. The wrapper sets marker 6124 and parks at 22DBC instead of reaching the accepted BFC1 park. The unchanged RAM can conditionally enter boot handling as 23CB after a separately injected status-20 reset. This demonstrates status/marker control flow only; failed-erase contents, physical reset and recovery remain unqualified.

[Preparation status paths](PREPARATION_STATUS_PATHS.md) now distinguish six success/error/readback cases and trace native wrapper returns. This strengthens the failure-control evidence without qualifying physical flash effects.

Remaining gate: persistent preparation side effects and actual reset/retention. The conditional RAM join does not remove those blockers or claim one uninterrupted physical session.

## 2. Read-only kernel

The existing compiled reader, native-copy handoff, RAM canaries, request/reply ownership and local software-quiesce tests remain active. Runtime/handoff tools now accept an explicitly supplied full flash fixture for offline validation; default synthetic-pattern regressions remain supported. The caller pins LOW/HIGH before using historical bytes.

[Full-flash rehearsal](FULL_FLASH_READER.md) now extends the compiled reader to all 1 MiB. Retained emulator contexts join reset vectors, native receiver/sender/copy and the compiled reader on the same CPU. Synthetic reset/IRQ/MMIO assumptions remain explicit.

Remaining gate: physical VPW/clock configuration, watchdog deadline, exclusive SRAM and interrupt ownership, and safe physical exit. No adapter upload/execution backend is enabled.

## 3. Collateral readback and preservation

The compiled reader reconstructed 41,000 bytes at 15FD8..1FFFF from the pinned historical LOW/HIGH fixture in 1,282 correlated requests. Marker 4AFC came from that fixture, not a replacement constant. Production C# host code consumed all replies and reproduced the bytes exactly. The assembled 8000..1FFFF snapshot matched historical LOW; writer assessment detected changed marker and collateral bytes. Readback, backup and recovery qualification flags stayed false.

The full-image campaign also distinguishes original historical fixtures from post-preparation atomic-model fixtures. Pre-entry persistent-bank data must not be inferred from a later image after normal entry has updated those banks.

Remaining gate: fresh independent readback of the actual controller. Historical success does not establish present contents, all flash-bank coverage or physical preservation.

The full sector baseline and SHA-256 now follow the offline rehearsal into stopped-snapshot assessment and explicit reconstruction. A matching saved snapshot does not resume the stopped attempt, and legacy collateral-only references never become a complete baseline.

## 4. Calibration-only programming rehearsal

The three retained EFILive calibration captures continue to match constructed requests, checksum retry handling, interruptions and saved-byte verification. The SPS full-programming corpus continues to match 181 generated transfers, 180 acknowledged blocks and its setup/cleanup lifecycle. These profiles remain distinct: a complete SPS calibration-only capture is still absent. Do not infer a safe calibration-only SPS sequence by skipping its OS transfers.

Remaining gate: exact selected live profile, fresh collateral baseline, physical erase/program/finalization and independent readback. No transport or automatic retry authority is granted by fixture success.

## 5. Programming and recovery qualification

Not performed. The owner reports a spare TCM has been ordered and is expected by the end of this week. It has not arrived or been identified/qualified. Interrupted erase/program testing and recovery require a separate qualification target and a demonstrated recovery procedure. A12 remains a conditional offline recovery hypothesis, not a qualified method. No destructive experiment is scheduled by this checklist.

[Spare bench qualification checklist](SPARE_TCM_BENCH_QUALIFICATION.md) defines intake, baseline-read, prototype-entry, programming and recovery gates.

## Reproduction and retained artifacts

- `test_application_reset_chain.py --low LOW --high HIGH` checks strict storage stop, conditional park, reset-cause routing, exact RAM provenance and offline gates.
- `emulate_application_reset_chain.py --low LOW --high HIGH --output NEW_JSON` saves the joined observations.
- `emulate_readonly_collateral.py --build-dir BUILD --low LOW --high HIGH --exercise-local-quiesce --output NEW_JSON` executes the historical collateral campaign.
- `dotnet run --project Tools/AL5/ReadOnlyCollateralCampaignTest.csproj -- REPORT LOW` checks all reconstructed historical bytes through production host and writer-assessment code.

Task-local reports are under `LocalOnly/al5_a12_recovery_20261102/`. Source/doc changes contain no proprietary raw firmware. The persistent-storage boundary is now connected to the application request. Remaining offline work is its complete success/failure ordering and how those outcomes constrain reset/entry; no reset assumption should conceal its effects.
