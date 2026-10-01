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
- v0.6 adds 26 vectors / 228 cells across eight WOT threshold, TCC duty and
  TCC on-ramp definitions. All 210 resolved numeric entries pass the audit.
- v0.7 adds 32 vectors / 64 cells: complete WOT TCC mode families and partial
  WOT downshift families. All 242 resolved numeric entries pass the audit.
- Offline checksum generation reproduces stock `4E35D040` and PPEI `DAE2BB2E`.
  The CRC lookup table matches all 256 firmware entries. Three independently
  EFILive-finalized edits now reproduce `732DAAC8`, `EBA232B3` and `7B29A38C`.
  The second-word generator trace and live acceptance remain unproven.
- The file-only dry-run planner validates context, exact sizes, anchors, source
  hash, native checksum, diff ranges and the minimal target policy. It always
  blocks readiness and produces zero packets.
- PcmHammer's shared write entry point rejects a 57,304-byte AL5 segment before
  transport access, even with a forced PCM type. A C# null-vehicle test passes
  all 105 write-type/controller combinations. Eighteen Python safety,
  checksum, record-family and flash-inventory tests pass.
- The extracted CRC routine passes twelve isolated M68020 emulator cases.
  The native boot BE16 sum routine passes nineteen isolated cases, including
  stock/PPEI and changed payloads. Its known boot/application callers do not
  establish a calibration compensation generator.
  The boot RAM-transfer handler passes thirteen offline boundary/fault cases.
  Its packet fields, RAM bounds and status codes are documented in
  `BOOT_RAM_TRANSFER.md`; this does not enable live uploading or programming.
- Twenty-five stateful boot-dispatch/transfer emulator cases now verify upload
  arming, input guards, negative-response echoes and retained RAM/arming state.
  The receive cleanup and hardware helpers remain modeled; application-to-boot
  entry remains unproven. See `BOOT_SESSION.md`. The planner links this evidence
  without enabling live session access or emitting packets.
- Twelve isolated application-handler/boot-route cases trace service 0x34
  through a RAM marker and selected boot initializer. The startup 0x74/0x44
  response leaves upload arming clear. Physical reset and full receive/security
  reachability remain unverified; see `APPLICATION_BOOT_ENTRY.md`.
- Twenty descriptor/security emulator cases now link the fixed-selector
  seed/key handler to the boot-request guard. The descriptor is a direct callback;
  0xA9D8C is a memory-clear helper. Lockout counter units and physical receive/reset
  remain unverified. See `APPLICATION_AUTHORIZATION.md`. No key sender was added.
- A resident boot erase/program primitive is statically traced, including its
  RAM copy, selector table and word-program loop. Neighbor-start inference flags
  41,000 bytes outside calibration that could require preservation. Actual
  geometry and the wire/session path remain unverified; see
  `RESIDENT_FLASH_PRIMITIVE.md`. Its inventory emits zero packets.
- The CAN-style resident caller passes sixteen isolated emulator cases with
  every flash call trapped before primitive execution. Arguments, status data,
  RAM mode, alignment/range checks and malformed-length behavior are recorded
  in `RESIDENT_COMMAND_DISPATCH.md`. This does not establish a live CAN writer.
- The main file-only plan includes hash-linked inferred collateral intervals
  and an explicit unverified preservation blocker. Executable erase scope
  remains null; readiness remains false and all packet lists remain empty.

The checksum-corrected existing minimal preview has field `439DCC98` and passes
the offline plan's file/policy checks. Its plan has seven diff ranges and zero
packets. That preview and the plan remain under ignored `LocalOnly/AL5`; neither
is flash-ready or committed. It is an OEM-stock-based development preview, not
a plan to program the currently installed PPEI calibration.

## Current boundaries and next work

**Current named XDF: v0.12**, `TunerPro/AL5_15184109_15183960_MARKER_EXTENDED_v0_12.xdf`.
The completed offline EFILive report resolves 83 marker cases and adds 41 items;
all 283 numeric native comparisons pass. The subsequent v7 report maps D5053
and D5054 byte enums and independently validates three native edited checksum
fields. The completed v8 pass identifies D5197 at 0x10A24 and the old PPEI
00-to-40 change as RPM Limit Req Disabled. All 127 native IDs are represented,
including research entries with explicit confidence. The completed v9 pass confirms
eight D5000/D5005 Pattern E-H vectors through 24 isolated markers. All 2517/2517
unique numeric stock cells now match the native export; 291 numeric entries pass.
This is full stock decoding coverage, not marker or runtime proof of every cell.
See [complete numeric coverage](TunerPro/NUMERIC_COVERAGE_v0_12.md).
H0105's completed high-word marker corroborates unsigned BE32 at 0x152E4 with
the native range and exact readback; v0.9.1 preserves every v0.9 encoding.
See [marker evidence and GUI checks](TunerPro/MARKER_VALIDATION_v0_9.md).
Four v0.9.1 scalar displays (H0105/H0136/H0103/H0137) are now screenshot-checked
on both the stock and PPEI BINs. D5073 Normal/1st Gear is also screenshot-checked
on stock: 17 rows, native labels 0..256, 99.998 displayed throughout, address
0x13B7A and 16-bit cells. Other table/axis checks remain open. The optional v0.8
raw supplement remains separate. Its two flag-dependent
families still have no native definition identity; keep their raw labels.

Read [CHECKSUM_RECOVERY.md](CHECKSUM_RECOVERY.md) and
[WRITE_PROTOCOL.md](WRITE_PROTOCOL.md) before extending writer work. Recover the
EFILive object/container state definitions and controller flash geometry offline.
Session/key, loader requirements, exact erase geometry, diagnostic programming
path, readback timing and recovery are still unproven. No destructive packets
have been invented or sent.

The only TCM remains protected: no live erase/program, experimental loader
upload or unknown destructive service. A normal UI write action cannot route a
raw AL5 segment into the existing PCM kernel writer. No AL5 live writer exists.

## Reproduce

The v7 enum/checksum, v8 final-enum and v9 remaining-column passes completed.
Reproduce v0.12 with `Tools/AL5/expand_remaining_columns.py` followed by
`audit_xdf.py`, supplying explicit local stock/export/PPEI paths. The redacted
v9 evidence, original-report hash, mapping manifest and audit are under
`Docs/AL5/TunerPro`. No additional numeric marker pass is required to close
stock decoding coverage. New-vector GUI checks remain pending. Ambiguous
pre-marker searches remain preserved in `REMAINING_COLUMN_CANDIDATES_v9.json`.

The v6 targeted mapper completed its 83-case EFILive pass; the v6.1 H0105
high-word pass also completed. Reproduce their validation with
`expand_marker_mappings.py` and `validate_high_word.py`, using explicit local
stock/native export paths and the redacted reports under `Docs/AL5/TunerPro`.
TunerPro GUI display checks are pending; no further H0105 marker is needed.

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
python -m unittest discover -s Tools/AL5 -p test_family_search.py -v
python -m unittest discover -s Tools/AL5 -p test_flash_inventory.py -v
& '<Visual Studio MSBuild.exe>' Tools/AL5/GateTest.csproj /v:minimal /nologo
& .\LocalOnly\AL5GateTest\AL5GateTest.exe
```

Build PcmHammer first so the gate harness uses the current Debug library. The
Python tools use the standard library; `scan_firmware.py` additionally needs
Capstone (the existing WSL environment was used). Neither test opens a vehicle.
