# PCCS LCT programming investigation

Status: offline host analysis only. AL5 live writing remains disabled. Internal
PCCS buffers below are not qualified CAN/VPW frames and are not added to the
PcmHammer writer or its dry-run packet plan.

## Inputs and provenance

Read/Write TCM `Winrw32.exe` 15.2.17.0, SHA-256
`13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.
An earlier installed build had a different digest; its offsets must not be reused.
The supplied tree contained 49 FIL files; neither `APPANDCAL_UTILITY.FIL` nor
`ERASE_APP_UTILITY.FIL` was present. Generic CALONLY is byte-identical to the
A54-named calibration utility, so generic names do not qualify LCT compatibility.

REA/Ghidra search Evidence:
`ev_f7e0e3282714b48069b32cb0ba0317152e82874d8c10f92193c1adb32006d5b0`.
Native identification function `0x5D8EC8` distinguishes LCT Gen3 application,
boot and boot-reprogrammer states. Retained Evidence:
`ev_32d1b9c641583f1491d35a2c640309a0c8ac49af9d73f8923fd09f94dd4affdf`.
Its high-pcode coverage is truncated and Delphi decompiler types are unreliable.

## Observed method anchors

The offline `inspect_pccs_methods.py` tool reads Delphi length-prefixed method
descriptor candidates and verifies that their address maps uniquely to executable
file bytes. It preserves source hash and descriptor/code offsets. It never
loads the executable or marks candidates as provider-verified functions.

- `EraseFlash`: `0x5B5410` and `0x5FF468`, distinct implementations.
- `WriteCalClick`: `0x7C8E70`.
- `WriteCalErasePO1Click`: `0x7EB844`.
- `RecoverandErasePO1Click`: `0x7EB9C8`.
- `UtilityFileViewer1Click`: `0x7EE120`.

Ghidra did not define containing functions at these method anchors. Explicitly
bounded, file-backed Capstone 5.0.6 windows were inspected instead; no Ghidra
database mutation or guessed function boundary was used. This is separate
static evidence, not a claim that REA recovered those functions.

## Erase helper: native emulation

The helper at `0x5B5410` was emulated with Unicorn 2.1.4 against the exact pinned
executable. A synthetic object, stack, exception-list storage and virtual
dispatch replace the host environment. Only helper instructions, a no-op string
cleanup and an in-memory dispatcher may execute. Unknown execution addresses
and exhausted fake responses stop the run. No Windows API or vehicle I/O runs.

Observed under the stated synthetic contexts:

- With the LCT flag set, block argument 3 builds internal buffer `12 03`.
- State 5 adds selector `B0`, `BF` or `AC` for selector values 0, 1 or other.
- Internal status 2 causes a single rebuild/retry as the simpler `12 03` form;
  for state 5 the first request has three bytes and the second has two.
- A second status 2 is retained; no unbounded retry occurs.
- State values 6 and 13 use timeout parameter 60000; the base case uses 30000.
  These are host parameters, not measured controller execution times.
- The modeled suppression flag prevents dispatch. In a freshly zeroed synthetic
  object the status remains zero even though no dispatch happened. Status zero
  alone therefore cannot establish that any operation was performed.
- A nonzero modeled response byte converts an initially zero status to 4.
- With the LCT flag clear, block arguments 1 and 4 select different request
  forms. Those branches must not be silently treated as LCT commands.

The meanings of status values 2/4, block geometry, authorization, transport
framing, and physical controller behavior remain unresolved. No buffer in this
document is approved for transmission.

## Recovery menu: bounded finding

The `RecoverandErasePO1Click` method at `0x7EB9C8` calls preparation at
`0x5D6C5C`, checks status through `0x5B0AF0`, then invokes `0x5B0C50` before
testing status and displaying completion/error UI. A bounded window at
`0x5B0C50` shows a timed exchange with hard-coded request fields and reply checks.
It has not been completely reconstructed or emulated. The action's name and
success text do not prove interrupted-flash recovery or application restoration.

## Installed documentation and comparison images

`Readwrite.hlp` describes a boot block protected from ordinary erase, separate
power-off/calibration blocks and native checksum-range readback. It says the
documented SPX J1850-VPW box excludes writes, while the described LCT programming
workflow uses CAN. This does not rule out another VPW programming path.

The LCT S2 images are calibration/application data, not FIL programming scripts:

- U2A maps `0x8000..0x15FD7` and `0x20000..0xC6073`.
- DF9 maps `0x8000..0x1903F` and `0x20000..0xD9DE3`.
- All 78,420 S2 record checksums pass without overlapping addresses.
- Neither supplies the low-address boot area or a full recovery backup.

## Reproduce offline

From `Tools/AL5`, pass the matching local executable explicitly:

```powershell
py -3.13 inspect_pccs_methods.py 'PATH\Winrw32.exe' --output 'PATH\methods.json'
py -3.13 -m unittest test_pccs_methods test_offline test_authorization
py -3.13 emulate_pccs_erase.py 'PATH\Winrw32.exe' --output 'PATH\erase-audit.json'
```

Only emulation needs the optional Unicorn 2.1.4 package on Python's module path.
No third-party binaries or calibration images are committed. The source-bound
emulation audit covers 14 synthetic cases; it does not qualify a live writer.

Next: resolve the virtual dispatcher and exact CAN framing; finish preparation
and recovery exchange semantics; trace block transfers and verification; then
compare controller-side behavior against the existing EFILive VPW evidence.
