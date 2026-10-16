# C# coordinator and original-instruction integration

The BCL-only C# harness can now run the production AL5 coordinator over a bounded
local stdio bridge. `test_native_coordinator_bridge.py` drives that coordinator
using the existing original-instruction boot/upload/loader emulator. This tests
host sequence and retry decisions against native instruction execution, rather
than supplying a generic success assertion for every stage.

The bridge is compiled only into `Tools/AL5/CalibrationInspectionTest.csproj`.
It links the production inspector, workflow, coordinator and reply validator,
without Vehicle, WriteManager, serial, adapter or driver code. It is not a live
transport implementation and has no network listener. No production write gate
or Mode `$23` reader was changed.

The native side follows C#'s pending phase, address and length. It executes the
original boot upload and loader entry, conditional erase, every dense calibration
and collateral block, and finalization. Original command/MMIO stores remain
suppressed; the existing host-owned conditional flash/FIFO models supply effects.
Native sender return, timeout/reentry, stack delta and actual modeled word coverage
feed `RecordLoaderModelResult`. Snapshot bytes feed C#'s saved verification or
stopped-operation reconciliation. Boot entry remains one explicit modeled
milestone; real startup/reset and interrupt delivery are not established.

The six cases in [the metadata report](NATIVE_COORDINATOR_BRIDGE_EMULATION.json)
passed on 2026-10-16:

- `complete_dense`: 389 coordinator observations, 98,302 bytes through the native
  block word loops plus the final marker word, then `SavedImageVerified`.
- `lost_ack`: the native sender times out after constructing `73`; C# stops on
  `ReplyLost`. The saved pending block matches, but the attempt stays stopped.
- `partial_block`: interruption after four native modeled word writes leaves
  four matching words and 124 words with clear-only differences in the pending
  256-byte block. C# retains `Interrupted` and cannot resume.
- `conflicting_word`: an explicitly chosen synthetic zero bit prevents a native
  requested `0x0001` word from matching. Native `F8` and a retained stack frame
  stop C#; reconciliation identifies the zero-to-one conflict at `0x9000`.
- `erase_failure`: synthetic persistent-toggle polling reaches native `85`,
  retaining pending frames. C# stops before block programming; saved bytes do
  not match the conditional erased range.
- `marker_failure`: the second dense full sequence reconstructs all block data,
  but a synthetic marker readback fault reaches native `F8`. Marker arithmetic
  alone looks clear-only; C# still forbids retry and session reuse.

Foreign attempt tokens, stale ordinals and outcomes after terminal states are
rejected without advancing the coordinator. The bridge also rejects bare
completion assertions for loader stages, malformed bodies and input digest
mismatches. A supplied UUID binds one attempt per owned process; it is not an
authentication credential or a physical controller identity.

Candidate, baseline and snapshot bytes pass over owned process pipes without
being logged or persisted by the bridge. Input reads use exact native sizes;
JSON lines and responses have explicit harness resource budgets and bounded
waiting. These are test-resource limits, not qualified vehicle timings. The
child is waited for and terminated if needed using its owned process handle.

Reproduce from the repository root with the existing optional dependencies:

```powershell
dotnet build Tools/AL5/CalibrationInspectionTest.csproj --no-restore
$env:PYTHONPATH='C:\REA\.cache\pccs-fil\python-deps'
python Tools/AL5/test_native_coordinator_bridge.py --low <pinned-128KiB-LOW-file> --loader LocalOnly/AL5/captured_write_loader.bin --bridge LocalOnly/AL5CalibrationInspectionTest/bin/CalibrationInspectionTest.dll --output <new-metadata-report.json>
```

The LOW input is pinned saved editor memory, not a current independent physical
backup. The captured loader remains a private local input; executable bytes are
not included in the report. Existing output files are refused before execution.
The report records the input, executed harness and source digests, Python/Unicorn
versions and each bridge process's .NET runtime. The C# harness build image is
not committed; a future build need not have the same binary digest.

The file-only write planner now references this report and its digest while
retaining empty send/erase/program lists and all physical readiness gates false.
Regression checks pin the report's current source dependencies. Six stdio/input
guard tests pass with the built bridge, alongside the existing 40 C# checks,
27 saved native-model observations and 32 Python planner/reconciliation tests.
The existing 210 null-vehicle WriteManager guard combinations remain rejected.

This is conditional software integration evidence. Synthetic flash, sector map,
readiness and fault values remain assumptions. The finalizer's checksum-pointer
table is also supplied by model setup. The compared snapshots come from
the same modeled flash backing, not an independent physical readback. No adapter,
controller, power interruption or physical recovery was exercised. Live writes,
automatic retries and `ready_to_flash` remain false.
