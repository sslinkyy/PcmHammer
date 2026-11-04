# Spare AL5: first-write qualification run sheet

Prepared 2026-11-02. The objective is to qualify the calibration writer on the spare. Ordinary reads are prerequisites for the write, not a new general reader campaign. No live action is started by this document. The current build still blocks AL5 writing and prototype upload/execution.

## Before delivery: completed work stays completed

Use the frozen package recorded in the local bench readiness report. It contains the built Windows app, compiled offline candidate tool, source snapshot, programming requests, validation evidence and capture helper sources. Do not launch the application now: startup can initialize an adapter. Do not copy the write loader into a read-only utility slot.

On arrival, run this file-only check against the actual sealed directory:

```powershell
python Tools/AL5/freeze_bench_candidate.py verify --package FROZEN_PACKAGE_DIRECTORY --repo .
```

Expected: verified true, tests_rerun false, no source drift or modified package files. This does not run emulation or access hardware. If files changed, inspect the listed differences and run only the affected checks. Do not reflexively repeat full-image or entire historical test suites.

The package manifest is a local integrity inventory, not a signed authenticity guarantee. Keep its trusted copy with the retained qualification records.

## Session 1: identify and preserve the qualification target

Record the spare's service/hardware numbers and label/connector photos. Compare its identity to the saved AL5 profile. Matching the installed controller's service number 15768288 is useful evidence, but seller text alone is insufficient. A different OS/profile requires targeted compatibility review.

Use matching service information for the actual controller connector feeds. The current packet does not contain a verified AL5 bench pinout: do not reuse an E54 harness or assume previously suggested pin numbers. Wire only with power off, with fused feeds and the intended bench ground. Resolve this equipment/setup dependency before connecting the spare.

Use the GT as the single active PcmHammer interface at VPW 1x. AutoCal/SPS must not concurrently own the GT or run a diagnostic/programming operation. Record the current adapter firmware and USB identity. If USBPcap will record the GT, refresh its hub/device address after reconnect and confirm the recording is growing before communication.

Run the existing TCM Hammer identity command, then acquire the spare's calibration backup. Check the exact 57,304-byte length and native checksum and retain the raw log/capture. A second baseline read is needed if consistency has not been established for this target; old installed-TCM files are not the spare's original backup.

Record missing coverage explicitly. The current stock reader does not give a qualified complete original 1 MiB backup. In particular, programming-style entry can update persistent banks 0x4000..0x7FFF. A post-entry full image is not automatically an original pre-entry backup. This is a real write-preservation gate, not a request to re-run completed offline read emulations.

## Session 2: qualify the writer's entry and transport

Review only the hardware gaps: current security/profile, preparation side effects, reset/watchdog transition, loader RAM ownership, message framing and physical completion. Preserve capture from setup through cleanup. The candidate's dynamic-key action is unresolved authorization evidence; its one captured seed/key pair must not silently become generic support.

The current source has no enabled live writer executor. Connecting the spare does not bypass this. Use the implemented immutable dispatcher boundaries for staged qualification: before key submission (default), before programming entry, before loader upload, and before erase. The after-erase boundary is already destructive and belongs to a later qualified test. A live binding and its bounded operation list still require separate review/qualification before a first erase. A smallest bounded read can verify handoff; there is no reason to repeat long full-image offline campaigns on arrival.

Stop on an unexpected identity, reply, timeout, unstable supply or uncertain controller state. A missing acknowledgement does not authorize a duplicate erase/program command. Keep captures and the stopped candidate intact for targeted diagnosis.

## Session 3: unchanged-calibration programming

Require the chosen controller/profile and fresh security to be qualified, an adequate independently acquired preservation baseline, the reviewed live executor, and a demonstrated recovery route for the qualification module. A12 remains conditional and unqualified; do not assume it substitutes for recovery equipment.

Prepare the candidate from the spare's unchanged calibration, exact loader and complete reference using the offline tool. Review its hashes, two erase sectors, 192 data blocks, collateral restoration and separate finalization. Expected-image files are never used as proof of independent readback.

The [current multipart checkpoint](WRITE_PROGRESS_20261103.md) adds an explicit preflight gate: define the verification epoch around the finalizer's retained-marker/park tail and unqualified physical reset and ordinary startup journal updates. The current candidate correctly rejects unexplained bank differences even when programmed sectors match. Do not proceed by accepting a newly observed post-startup bank file as its own expected baseline, or by ignoring the entire bank region.

Once the required live gates are explicitly satisfied and programming is enabled in a reviewed build, capture the complete write. Independently read back and compare calibration, collateral, marker, persistent banks and other preserved regions. Record preparation-related differences explicitly. Confirm subsequent boot/identity separately from successful protocol acknowledgements.

## Recovery experiments are a separate session

First establish the recovery route without deliberately damaging the controller's only usable state. Vendor re-entry, boot-session recovery, external flash restoration and conditional A12 behavior are different paths. Record required software entitlement, equipment, original image coverage and actual results. Do not claim one is available just because the intact application currently communicates.

Only then design separately authorized interruptions at entry, erase, partial programming and finalization. The installed truck TCM is excluded. If a gate fails, preserve the evidence and investigate that specific failure; a failed hardware test does not invalidate unrelated completed offline checks.

## Latest original and finalization tools

The [external-original and timing continuation](EXTERNAL_ORIGINAL_AND_RESET_VERIFICATION.md) records the already demonstrated T48/Intel workflow and the new matching full-chip importer. Use the spare's actual identified chip and explicitly verified representation; do not assume the Intel conversion applies. `BeforeFinalization` is an additional terminal offline boundary after 192 data acknowledgements and before `36 FF`. It is already destructive in the model and proves no physical pause/readback service. The finalizer stores a retained RAM marker and parks; it does not establish an intervening host verification window or a reset deadline.
