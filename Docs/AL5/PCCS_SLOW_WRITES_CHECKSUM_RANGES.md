# PCCS slow-write ownership, calibration routing and checksum ranges

2026-10-15, offline continuation of `PCCS_QUICKWRITE_READBACK.md`.
Live writes remain disabled. No PCCS application entry point, COM, adapter or
controller executed. Synthetic native contexts establish host branching only.

## Calibration write call and precedence

The ordinary calibration block call at `0x7C625F..0x7C627D` pushes length
`0x100`, the selected index, zero, zero, then calls WriteData VMT +`0x10`.
Thus its low-byte caller flag is zero. The payload comes from the loaded
block array at `0x81F12C`; the address comes from the loop's local field.
This makes QuickWrite eligible at the later branch, subject to earlier routes
and the object-wide flag. It does not establish actual AL5 flag state.

WriteData first checks `Use CCP Messages` at `0x5B4894`. Subsequent alternate
routing at `0x5B4A42..0x5B4AD8` can also bypass the QuickWrite decision. Only
when those paths reach `0x5B4B87` does nonzero object +`0x68C60`, combined
with zero caller flag, call QuickWriteData VMT +`0x18`. Otherwise the ordinary
path constructs internal `22` requests. These internal identifiers are not
qualified VPW packets.

`emulate_pccs_native_write.py` now records twelve selection contexts in
`selection_cases`. A synthetic VMT +`0x18` callback records the native call's
address, payload, index and length without executing QuickWriteData. It verifies
CCP precedence and caller-flag fallback. The separate existing QuickWriteData
model covers that method's ordinary body with synthetic send callbacks.

Private source and model evidence in
`Tools/AL5/LocalOnly/PCCS_20261015/QuickWriteTrace/`:
`write-selection-callsite.json` and `native-write-selection.json`.
Both pin installed Winrw32.exe SHA-256
`13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.

## What changes the QuickWrite inhibit byte

Global `0x81D16C` is PCCS's **Slow Writes** byte, reached through the pointer
at `0x81ED28`. Its source value is 1. Configuration load
`0x7D4286..0x7D42CC` reads section `Communication`, key `Slow Writes`, with
default `YES`; after uppercasing and comparing to `YES`, `SETE` stores 1 for
equality and 0 otherwise. The save sequence `0x7D7628..0x7D7661` writes
`YES` for nonzero and `NO` for zero. The selected INI file and effective
runtime value remain unobserved.

The descriptor-named `FastWrites1Click` handler at `0x7E1A1C` toggles this
byte with XOR 1 through the same pointer. Its inverse drives UI object
+`0x420`; initialization uses the same inverse. The concrete widget class
is not proven. No application or UI was run, and no setting was changed.

Two additional stores force Slow Writes on at `0x7BABE1` and `0x7BB10B`.
The former follows the standard-LCT vector readback mismatch traced below. The latter is conditional on selected communication
text searches for `SOFT` and `VECT`. Neither establishes interrupted-flash
recovery. The bounded literal-pointer inventory finds eight references;
computed aliases and other runtime writers are not excluded.

This byte is separate from object +`0x68C60`. Identification can set, clear or
preserve that route flag. Changing Slow Writes does not itself clear a
previously enabled route flag in these traced snippets; immediate route
recalculation after the UI toggle is unproven. The actual AL5 identity bytes
at `0x3FE2`, selected index, version and prior object state still matter.

`emulate_pccs_slow_writes.py` runs ten bounded native store/toggle contexts,
with only the one-byte inhibit store writable. Configuration comparison
results are synthetic; parsing, complete handlers and UI calls are excluded.
Source windows, descriptor/string records and findings are private in
`slow-writes-ownership-source.json`, `SLOW_WRITES_OWNERSHIP_FINDINGS.md`
and `native-slow-writes-flag-final.json`.

## Standard-LCT vector readback and fallback

The gate at `0x7BA9D4..0x7BAA2D` selects family 1/version 0; a separate family
0/indexed +`0xB7` zero case can also reach it. It then requires the loaded file
length entry at block index `0x204` to be positive. The source label is
`Checking vectors`.

ReadData VMT +`0x2C` at `0x7BAAA2` requests **`0x20000..0x2040F` inclusive**
(`0x410` bytes) into `0x9DF398`, using the selected controller index. Only
zero read status reaches the comparison. Expected blocks `0x200..0x204`
come from `0x81F12C`; per-block lengths come from `0x81ED44`. The loop skips
absent blocks and byte positions beyond their declared lengths, so the read
span is not automatically a completely compared span. A mismatch logs
`Vector check failed: $` and forces Slow Writes at `0x7BABE1`.

This is a concrete standard-LCT readback/fallback path, scoped to loaded file
coverage. Follow-up failure exits and initialization retry decisions are traced
in `PCCS_VECTOR_FAILURE_RETRY.md`. Full caller reachability for a particular
AL5 operation, route requalification and physical transactions remain unproven.
The flag-store model executes only the final store, not the vector read or
comparison. Anchored raw instructions are preserved privately in
`slow-writes-vector-readback-source.json`. The other force-one path is not
promoted to recovery evidence.

## Variant-specific checksum storage readback

The two supplied S2 images independently support these four-byte intervals
(inclusive endpoints):

- **U2A:** `0x15FD4..0x15FD7`, containing CRC `1E0C` and compensation `A374`.
  Calibration body `0x8000..0x15FD3`; complete calibration ends `0x15FD7`.
- **DF9:** `0x1903C..0x1903F`, containing CRC `8DDC` and compensation `468F`.
  Calibration body `0x8000..0x1903B`; complete calibration ends `0x1903F`.

Both reproduce reflected CRC16 polynomial `0xA001`, seed 0, no final XOR,
with BE16 storage. Compensation is negative BE16 body sum minus CRC,
modulo 65536; each complete calibration's BE16 sum is zero. The locations
are artifact-specific: do not apply U2A's boundary to DF9 or assume either
matches the installed controller's OS.

Application source bytes reinforce the boundaries: U2A loads `0x8000` at
`0xA97F4`, `0x15FD4` at `0xA97FE`, then calls `0xA96E4` at `0xA9836`.
DF9 loads `0x8000` at `0xBF518`, `0x1903C` at `0xBF522`, then calls
`0xBF408` at `0xBF55A`. These are selected raw 68k instruction windows,
not provider-defined functions or observations of controller execution.

U2A source SHA-256:
`84e8ef5e8f38dbf2814011a40190e9d38ecd041560d888133cba35c98178065d`.
DF9 source SHA-256:
`6af8a1afd0cffabe2ba66979283b03de1eb030101d7be174289d0800d4d4b411`.
The offline auditor validates all S2 records, unique mapped addresses and
complete calibration coverage without filling holes. Private reports are
`u2a-checksum-range-audit.json`, `df9-checksum-range-audit.json` and
`variant-checksum-m68k-windows.json`.

These are supported **checksum-storage readback candidates** for the pinned
images. Exact equivalence to the help names `KwCOND_Cal_CRC` and
`KwCOND_Cal_Checksum_Location` remains unproven; the report leaves their
symbol bindings null. No matching symbol definitions were found in the
examined extracted pack/installed trees. Archive-member contents were not
exhaustively searched. Physical readback addressing is not validated.

Each four-byte interval fits the optional PCCS comparison's `0x1000` cap.
Checking it only establishes that the stored checksum bytes match the file;
it does not establish equality of the entire programmed body. Full independent
calibration comparison would need all bytes of the variant's complete range,
and application/preserved areas require separately proven coverage. Neither
four-byte readback nor send retries establish recovery after erase/interruption.

## Offline validation

**108 tests passed**, with the installed pinned PCCS and DOC DLL and both S2
images present; no tests skipped. This includes the ten inhibit contexts,
twelve new WriteData selection contexts, and both checksum-range audits.
Malformed S-records, overlaps, address overflow, holes, corruption, source-pin
changes, execution/write bounds and existing-output preservation are covered.
No reader or live-write gate changed.

From `Tools/AL5`, with the optional pinned Unicorn dependency and local inputs:

```powershell
python -m unittest test_pccs_slow_writes test_pccs_lct_checksum_ranges test_pccs_native_write -q
```

Set `AL5_PCCS_EXE` and `AL5_LCT_S2_DIR` to the existing source files' locations
for real-input cases; tests report explicit skips when those are unavailable.
The checksum auditor accepts `--variant u2a` or `--variant df9` and an exclusive
`--output` report path. It emits analysis only, never a flash image or packets.

## Provider scope

This continuation's new claims use pinned raw-source windows, S-record
parsing and bounded native instruction models. Supplemental REA xref requests
did not return usable reference evidence in this pass; no new provider-defined
functions or caller-completeness claims follow. The read-only session was closed
and saved privately as `pccs-slow-writes-checksum-20261015.snapshot.json`
(37 evidence records, five primitive bindings), retaining the earlier provider
results described in `PCCS_QUICKWRITE_READBACK.md`.
