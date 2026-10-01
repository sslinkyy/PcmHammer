# AL5 continuation status

Continued from `d335b6efd5362bcb9c3f57e3f56647b16ba16df5` on
`imob/2.0-al5-readonly-probe`. The handoff was read completely before changes.
The existing direct reader, identity probe and their UI code were preserved.
All new reverse engineering and validation were offline.

## Verified progress

- Baseline and updated WinForms PcmHammer builds pass using installed Visual
  Studio MSBuild, .NET Framework 4.8, legacy packages.config restore and the
  existing SDK projects. No source/toolchain migration was required.
- Supplied TunerPro v0.3, D5100–D5115 mapping validation and the minimal v0.2
  first-test targets are committed unchanged. Local reference BINs are not.
- v0.3 audit reproduces the 102 PPEI changed bytes / 31 ranges and passes all
  130 resolved numeric XDF entries against the native export.
- v0.4 adds 38 TCC vectors / 646 cells with exact structural confidence.
  v0.5 adds 16 WOT upshift-speed vectors / 32 cells. All 184 resolved numeric
  v0.5 entries pass. Confidence is explicit; no new marker proof is claimed.
- Offline checksum generation reproduces stock `4E35D040` and PPEI `DAE2BB2E`.
  The CRC lookup table matches all 256 firmware entries. Additional edited
  native-segment validation and the second-word generator trace remain open.
- The file-only dry-run planner validates context, exact sizes, anchors, source
  hash, native checksum, diff ranges and the minimal target policy. It always
  blocks readiness and produces zero packets.
- PcmHammer's shared write entry point rejects a 57,304-byte AL5 segment before
  transport access, even with a forced PCM type. A C# null-vehicle test passes
  all 105 write-type/controller combinations. Ten Python offline safety and
  checksum tests pass.

The checksum-corrected existing minimal preview has field `439DCC98` and passes
the offline plan's file/policy checks. Its plan has seven diff ranges and zero
packets. That preview and the plan remain under ignored `LocalOnly/AL5`; neither
is flash-ready or committed. It is an OEM-stock-based development preview, not
a plan to program the currently installed PPEI calibration.

## Current boundaries and next work

The latest definition is `TunerPro/AL5_15184109_15183960_STRUCTURAL_TCC_WOT_v0_5.xdf`.
87 of 127 native IDs are represented, including partial/research entries.
`V0_5_AUDIT.json` lists the 40 absent IDs. D5010/D5015 Pattern G has two possible
record pairs and remains deferred. WOT downshift speed, WOT TCC, temperature,
remaining pressure/adaptive/enable and speedo mappings still need evidence.
The new XDF versions need a TunerPro GUI check; numerical audit is complete.

Read [CHECKSUM_RECOVERY.md](CHECKSUM_RECOVERY.md) and
[WRITE_PROTOCOL.md](WRITE_PROTOCOL.md) before extending writer work. Recover the
EFILive object/container state definitions and controller flash geometry offline.
Session/key, loader, erase, block programming, readback timing and recovery are
still unknown. No destructive packets have been invented or sent.

The only TCM remains protected: no live erase/program, experimental loader
upload or unknown destructive service. A normal UI write action cannot route a
raw AL5 segment into the existing PCM kernel writer. No AL5 live writer exists.

## Reproduce

From the repository root, use the scripts in `Tools/AL5`; each accepts explicit
local paths and has `--help`. Reference files remain outside Git:

```text
AL5_15184109_15183960_STOCK_REFERENCE_SEGMENT.bin
Direct Read PPEI AL5 Performance Tune.bin
AL5_15184109_15183960_tables_20260905_185942_001.json
AL5_RAW_00000_1FFFF_20260927_182847_001.bin
AL5_RAW_20000_FFFFF_20260927_184345_001.bin
local EFILive Config/AL5*.obj, *.bix, AL5.pmm
```

The baseline build used Visual Studio's `MSBuild.exe` on
`Apps/UI/WindowsForms/PcmHammer/PcmHammer.csproj`, with `/restore`,
`/p:RestorePackagesConfig=true`, `/p:SolutionDir=<absolute repo>/Apps/`,
`/p:Configuration=Debug`, and `/p:GenerateResourceUsePreserializedResources=true`.
Subsequent builds reused those restored packages. Existing CS1998 and CS8600
warnings remain. Run the tests:

```powershell
python -m unittest discover -s Tools/AL5 -p test_offline.py -v
& '<Visual Studio MSBuild.exe>' Tools/AL5/GateTest.csproj /v:minimal /nologo
& .\LocalOnly\AL5GateTest\AL5GateTest.exe
```

Build PcmHammer first so the gate harness uses the current Debug library. The
Python tools use the standard library; `scan_firmware.py` additionally needs
Capstone (the existing WSL environment was used). Neither test opens a vehicle.
