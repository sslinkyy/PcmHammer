# TCM Hammer AL5 write qualification

Updated 2026-11-02. This checklist distinguishes completed offline work from remaining physical qualification. Live upload, execution, erase/program operations and automatic retries remain disabled. Historical images, modeled outcomes and captured acknowledgements do not authorize writes.

## 1. Application to boot entry

Implemented `emulate_application_reset_chain.py` and its regression suite. The existing classifier, descriptor callback, native preparation caller and marker producer execute with synthetic request/state. Strict mode stops at 226F0 before persistent-storage implementation or even its return stub. A separately labeled conditional mode assumes subsystem/storage returns, reaches BFC1 with interrupt mask seven and observes eight self-branch iterations without watchdog servicing in that loop.

Exact application RAM FF8000..FFB7FF is hash-linked into a separate reset-model CPU. Reset injection and RAM retention remain explicit assumptions. For synthetic statuses 00/02/10/20, native reset entry preserves BFC1 and reaches B094 startup plus the synthetic Mode 34 reply. For 40/80/C0 it instead validates the saved OS and reaches the application boundary. Thus an external/power-up reset cannot be silently substituted for the candidate watchdog-reset transition.

The pinned boot store at 48E writes 84 to FFFFFA21. Under the conditional MC68336/376 SYPCR interpretation, this enables the software watchdog. The park instruction is a self branch, not RESET. Actual MCU, application-time watchdog state, timing, retained RAM and complete receive routing remain unqualified. See the [manufacturer register summary](https://www.nxp.com/docs/en/user-guide/MC68336376UMD.pdf), D.2.4 and D.2.12. Native execution here is emulator-only.

A deeper preparation case executes the real 226F0 caller using the historical bank bytes and the prepared application RAM. It reaches erase-wrapper entry 22B18 with target 6000. The wrapper is trapped before execution and the historical banks remain unchanged. This joins the request's preparation to a concrete persistent-storage boundary; it does not simulate successful erase/programming.

Remaining gate: persistent preparation side effects and actual reset/retention. The conditional RAM join does not remove those blockers or claim one uninterrupted physical session.

## 2. Read-only kernel

The existing compiled reader, native-copy handoff, RAM canaries, request/reply ownership and local software-quiesce tests remain active. Runtime/handoff tools now accept an explicitly supplied full flash fixture for offline validation; default synthetic-pattern regressions remain supported. The caller pins LOW/HIGH before using historical bytes.

Remaining gate: physical VPW/clock configuration, watchdog deadline, exclusive SRAM and interrupt ownership, and safe physical exit. No adapter upload/execution backend is enabled.

## 3. Collateral readback and preservation

The compiled reader reconstructed 41,000 bytes at 15FD8..1FFFF from the pinned historical LOW/HIGH fixture in 1,282 correlated requests. Marker 4AFC came from that fixture, not a replacement constant. Production C# host code consumed all replies and reproduced the bytes exactly. The assembled 8000..1FFFF snapshot matched historical LOW; writer assessment detected changed marker and collateral bytes. Readback, backup and recovery qualification flags stayed false.

Remaining gate: fresh independent readback of the actual controller. Historical success does not establish present contents, all flash-bank coverage or physical preservation.

## 4. Calibration-only programming rehearsal

The three retained EFILive calibration captures continue to match constructed requests, checksum retry handling, interruptions and saved-byte verification. The SPS full-programming corpus continues to match 181 generated transfers, 180 acknowledged blocks and its setup/cleanup lifecycle. These profiles remain distinct: a complete SPS calibration-only capture is still absent. Do not infer a safe calibration-only SPS sequence by skipping its OS transfers.

Remaining gate: exact selected live profile, fresh collateral baseline, physical erase/program/finalization and independent readback. No transport or automatic retry authority is granted by fixture success.

## 5. Programming and recovery qualification

Not performed. The owner currently has only the installed AL5 and no recoverable spare. Interrupted erase/program testing and recovery require a separate qualification target and a demonstrated recovery procedure. A12 remains a conditional offline recovery hypothesis, not a qualified method. No destructive experiment is scheduled by this checklist.

## Reproduction and retained artifacts

- `test_application_reset_chain.py --low LOW --high HIGH` checks strict storage stop, conditional park, reset-cause routing, exact RAM provenance and offline gates.
- `emulate_application_reset_chain.py --low LOW --high HIGH --output NEW_JSON` saves the joined observations.
- `emulate_readonly_collateral.py --build-dir BUILD --low LOW --high HIGH --exercise-local-quiesce --output NEW_JSON` executes the historical collateral campaign.
- `dotnet run --project Tools/AL5/ReadOnlyCollateralCampaignTest.csproj -- REPORT LOW` checks all reconstructed historical bytes through production host and writer-assessment code.

Task-local reports are under `LocalOnly/al5_a12_recovery_20261102/`. Source/doc changes contain no proprietary raw firmware. The persistent-storage boundary is now connected to the application request. Remaining offline work is its complete success/failure ordering and how those outcomes constrain reset/entry; no reset assumption should conceal its effects.
