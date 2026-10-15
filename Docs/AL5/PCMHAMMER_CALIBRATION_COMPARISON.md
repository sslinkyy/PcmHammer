# PcmHammer AL5 calibration BIN comparison

The WinForms app now includes **Tools > AL5 Compare Calibration BINs (Offline)**.
It compares an original calibration file with an edited file without selecting
or initializing an adapter. This is the first shared C# file-inspection step
toward an AL5 writer; it does not enable programming.

## Using it

1. Select the original calibration BIN.
2. Select the edited calibration BIN.
3. Review the Results log for each file's SHA-256, reference anchors, stored
   and computed native checksum, BE16 sum, changed-byte count and address ranges.

Both files must be exact **57,304-byte raw calibration segments**, mapped to
`0x08000..0x15FD7`. Full flash/editor images and EFILive containers are rejected;
the tool does not silently extract a segment. File reads are bounded before
allocation, and neither input is modified. The log displays the first 20
contiguous changed ranges and the totals for all changes. The shared report
contains the complete range list, including checksum-field changes.

The supported reference layout is OS 15184109 / calibration 15183960. The
checks do not identify the connected controller or prove compatible edits.
Arbitrary edited bytes can be compared, but this does not change the existing
Python planner's stricter first-test target policy or authorize those edits.
A checksum match remains a file fact; programming and recovery are unproven.

## Shared implementation and verification

`Apps/PcmLibrary/AL5CalibrationInspection.cs` supplies pure `Inspect(byte[])`
and `Compare(byte[], byte[])` methods. Reports preserve malformed-length
errors and unavailable checksum/hash values; `DifferencesComputed=false`
distinguishes an unsupported comparison from unchanged valid-sized inputs.
Valid-sized inputs are copied
before inspection; returned reports contain immutable scalar facts and
read-only collections rather than mutable input buffers. Diff addresses are
absolute and inclusive at the end.

The C# implementation checks the existing three anchors and ports the offline
checksum formula: reflected CRC16 with polynomial `0xA001`, seed zero, over the
body before `0x15FD4`, followed by BE16 sum compensation. A zero BE16 sum alone
does not pass native checksum validation. Live identity, edit authorization,
live writes and readiness are all explicitly false on the reports.

The WinForms handler calls this helper directly. It does not call Vehicle,
FileValidator or WriteManager. Existing Mode `$23` reading and the AL5
WriteManager rejection remain unchanged. This command works without an adapter
and is disabled during an operation, consistent with other file commands.
The existing application was not launched for verification, avoiding its saved
adapter initialization; dialog interaction has not been tested at runtime.

Validation performed:

- Full WinForms/PcmLibrary Debug build passed using installed VS2022 MSBuild.
  Existing CS1998/CS8600 warnings remain outside the new code.
- The isolated BCL-only inspection harness passed **14 checks**: nine boundary,
  checksum, immutability and diff tests; pinned stock/PPEI files; and three
  reconstructions from saved native-export byte differences. Those three
  reconstructions are not new EFILive exports or controller tests.
- The current compiled library rejected all **105** write-type/forced-controller
  combinations with a null vehicle before any transport access.
- The existing **239-test** Python offline/native suite passed with no skips.

Basic isolated checks, with no corpus files or adapter required:

```powershell
dotnet run --project Tools/AL5/CalibrationInspectionTest.csproj
```

This basic command runs nine tests and explicitly reports the omitted native
corpus checks. Optional repeated arguments `--corpus PATH SHA256 FIELD` and
`--reconstructed-corpus PATH SHA256 FIELD` require caller-selected local files
and known expected values. The stock/PPEI fields are `4E35D040`/`DAE2BB2E`;
the three native-export reconstructions match `732DAAC8`, `EBA232B3` and
`7B29A38C`. The private manifest is under
`LocalOnly/AL5CalibrationInspectionTest/NativeExportDiffs/manifest.json`.
No calibration binaries are committed.

The inspection harness and existing gate harness now each own their NuGet and
compiler intermediates under separate ignored LocalOnly paths. This prevents
the net8 inspection restore from being consumed by the net48 gate project.

## Further PCCS tracing

The installed utility first records do not supply the missing VPW mapping:

- CALONLY/APPONLY's interpreter version 3 fails the opcode-1/action-1 version
  guard and reaches `0x75C5C0`. It does not enter the legacy CAN-ID combine
  branch at `0x75C588` on that record.
- POONLY's opcode-1/action-0 target `18` chooses an IESCAN-specific probe or
  configured CAN-ID fallback. On J1850 it updates fields `+0x74888/+0x7488C`
  with configured identifiers, whose image/constructor defaults are
  `0x7E2/0x7EA`. It does not change the logical selected-controller global
  to `0x18` or enable programming controls in the inspected opcode body.
- All three first records continue to step 2 through the local instruction
  result zero. That local result differs from the object's error status.
  The rest of the FIL flow remains unresolved. Interpreter entry also sets
  alternate-route/control flags, so the complete invocation is not state-pure.

These are original-byte observations from pinned Winrw32.exe SHA-256
`13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.
Nine source windows and three installed-file records are retained in private
`QuickWriteTrace/fil-fallback-source.json` with `FIL_FALLBACK_FINDINGS.md`.
No PCCS interpreter, driver, UI, adapter or controller executed.

The remaining writer work is controller-side VPW preparation/upload,
erase/program addressing and preservation, positive completion verification,
and recovery after interruption. Neither the new C# checks nor PCCS's inherited
write methods settle those requirements. The current branch remains
`live_write_enabled=false` and `ready_to_flash=false`.
