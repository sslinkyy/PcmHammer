# PCCS QuickWriteData selection and optional readback

2026-10-15, offline. Identification can select QuickWriteData for standard
LCT under specific indexed-data, inhibit-flag and prior-state conditions.
PCCS also contains an optional command-line byte comparison labeled as a
checksum check. Neither establishes complete flash integrity or recovery.
Live AL5 writing remains disabled.

## Source and evidence

Installed Winrw32.exe SHA-256:
`13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.
Source-bound Capstone 5.0.6 windows, file offsets, bytes, digests and private
findings are retained in
`Tools/AL5/LocalOnly/PCCS_20261015/QuickWriteTrace/`:

- `QUICK_ROUTE_FINDINGS.md`, `quick-routing-source.json`.
- `native-quick-route-reviewed.json`: 76 native selection/getter contexts.
- `quick-write-and-send-source.json`, `native-quick-write-emulation.json`:
  source windows and eleven native QuickWriteData contexts.
- `CHECKSUM_READBACK_FINDINGS.md`, `checksum-readback-exact.json`,
  `checksum-token-helper-source.json`, `checksum-context.json`.

Raw source windows are not provider-recovered functions or complete
reachability proofs. Initial exploratory scans are superseded by the anchored
windows listed above. No application entry point, Windows API, COM, adapter
or controller executed. Native models use isolated Unicorn memory and declared
synthetic contexts; source identity and output preservation are guarded.

## Identification-to-QuickWriteData selection

Identification sets the indexed family field to 1. In its version-zero/two
read path, VMT +`0x2C` ReadData obtains three bytes at address `0x3FE2` into
indexed fields +`0x50..52`. Pure getter `0x5AE00C` returns these as a BE24
integer for family 1; for other families it uses first-byte low six bits.
The field's physical meaning and actual returned bytes remain unknown. It
must not be renamed a firmware-version threshold or capability bitmap by guess.

The bounded selection at `0x5DA7B1` changes object-wide +`0x68C60`:

- Versions 3 and 8..12 explicitly clear the flag.
- Index 3/version 0 enables it only when the getter is at least 16 and global
  `0x81D16C` is zero. Failed conditions preserve the previous flag.
- Other modeled indexed contexts can enable it when the global is zero and
  versions are neither 6 nor 13; failed conditions also preserve prior state.
- Version 5 has an earlier unconditional-enable path outside this slice.

Index 3 is a runtime array index, not the TController enum value 3. The route
flag is object-wide while the identification data are indexed, so an enable
condition failing does not necessarily imply a clear route flag.

Source `.data` initializes global `0x81D16C` to **1**, which blocks these
enabling branches. The configuration and UI owners are traced in
`PCCS_SLOW_WRITES_CHECKSUM_RANGES.md`; the effective value for the installed
AL5 remains unobserved. This source
initial value must not be presented as the current value in a connected session.

If earlier CCP/FIL routing has not exited WriteData, object +`0x68C60` nonzero
and the caller's low-byte flag zero select VMT +`0x18`, QuickWriteData, at
`0x5B4BA8`. Otherwise that branch falls through to ordinary `22` construction.
Actual AL5 identification bytes, effective globals and full caller state remain
unproven. `emulate_pccs_quick_route.py` executes the selection slice and actual
pure getter across 76 synthetic contexts; it does not run identification I/O.

## QuickWriteData is not readback verification

In the modeled ordinary non-batch path, `0x5B4F80` constructs internal `23`,
a BE24 address and at most four payload bytes. It advances address/payload
position after a zero send return. Prefix selection, driver send, memory copy,
waits and cleanup are synthetic replacements in the native model. The actual
send helper `0x5A9658` invokes object callback +8 and returns its result; this
does not establish the controller's acceptance of programmed bytes.

The retry comparisons recognize return words **11 and 137**, not 126:
the second comparison subtracts `0x7E` after subtracting `0x0B`. It permits
40 retries after the initial call, for 41 total attempts. Exhausted or other
nonzero send returns store the transport word and set host status `0C`.
Successful send returns do not clear a preexisting host error. No controller
acknowledgement-byte check or readback comparison appears in this selected
QuickWriteData loop. Send retry is not interrupted-flash recovery.

Object +`0x74878` selects a separate driver-batch path. That path remains
outside this model. The source buffers are not qualified AL5 CAN/VPW packets;
the existing VPW Mode `$23` reader does not establish their semantics.

## A real, optional command-line comparison

Delphi Timer1Timer (`0x7D95FC`) handles command-line W/WC paths, calls WriteCal
with argument 2, reconnects and checks status. An optional third argument with
literal `/C` prefix enables comma-separated address ranges with hyphenated
endpoints. Source anchors are `0x7D99C3..0x7D9E82`; exact delimiters and numeric
conversion helpers are preserved privately. This describes source syntax,
not a recommendation to execute a live PCCS command.

For each accepted positive range start, length is `end-start+1`, capped at
`0x1000`. The traced code does not subdivide an oversized range to verify its
remainder. Standard family 1 relocates starts below `0x8000` by `+0x10000`.
Malformed, reversed and out-of-image ranges are not established as safely
validated. The source parser must not be reused as a general safe range parser.

VMT +`0x2C` ReadData at `0x7D9BAE` reads into buffer `0x9DF398`. A nonzero read
status exits before comparison, through status `FE`. With zero status,
`0x7D9C27..96` compares returned bytes to the loaded calibration block array
whose pointer is held at `0x81F12C`. Block index/offset derive from the read
address relative to indexed +`0x74`, using 256-byte block boundaries.
The first mismatch exits through `F8`; matching bytes continue across blocks.

The ordinary ReadData branch constructs internal `20`, BE24 address and a
count of at most four, then copies response bytes starting at +`0x5267C`.
Alternate CCP/GMLAN routes also exist. These are host data-flow observations,
not validated physical transactions.

The help text corroborates optional W/WC checksum-address readback, naming
KwCOND_Cal_CRC and KwCOND_Cal_Checksum_Location for LCT. In the traced path,
this is a comparison of configured checksum-storage bytes against the loaded
calibration, not a fresh CRC calculation over all programmed flash. It does
not independently prove that all data covered by those stored values match.

Crucially, missing argument 3 or a non-`/C` prefix skips comparison but can
still reach the text **"Checksum matches Ok"**. That text alone does not prove
verification executed. The selected command-line path does not establish that
the GUI WriteCal workflow automatically performs the same comparison.

## Reproduce offline and remaining gates

From `Tools/AL5`, with optional Unicorn 2.1.4:

```powershell
$env:AL5_PCCS_EXE = 'PATH\Winrw32.exe'
python emulate_pccs_quick_route.py $env:AL5_PCCS_EXE --output 'PATH\new-route.json'
python emulate_pccs_quick_write.py $env:AL5_PCCS_EXE --output 'PATH\new-quick-write.json'
python -m unittest test_pccs_quick_route test_pccs_quick_write test_pccs_end_write test_pccs_prepare test_pccs_native_write test_pccs_file_chunks test_pccs_framing test_lct_typelib test_lct_event_setup test_lct_command_tables test_lct_session_callbacks test_allison_playback test_offline test_authorization test_pccs_methods -q
```

**97 tests passed**, including ten new test methods. The two new matrices
exercise 76 selection/getter and eleven QuickWriteData contexts. Real-input
tests skip explicitly if local input or emulator is absent. Source mismatches,
unexpected execution/writes, exhausted synthetic responses and existing report
paths are rejected. No working reader or live-write gate changed.

Selection conditions and optional configured-byte comparison are now traced.
Follow-up inhibit ownership, write-call selection and variant-specific checksum
ranges are documented in `PCCS_SLOW_WRITES_CHECKSUM_RANGES.md`. Still unresolved:
actual `0x3FE2` bytes and effective state for the AL5, driver-batch behavior and
physical transport, and complete independent programmed/preserved-byte verification.
Recovery after erase/interruption remains unproven; no flash readiness follows.

## Provider coverage

The private `pccs-quickwrite-readback-20261015.snapshot.json` retains 36 REA
Evidence records and five primitive bindings. Ghidra recovers the pure getter
and confirms its BE24/low-six-bit behavior:
`ev_f2710aa51fc7b79d75782fda516e149c888d200cf359f13e25ba91ca51dd236c`.
Its send-helper body is non-contiguous:
`ev_f364fbe795f4d354d16e0d5551979aec04369b51cc0079a91246e9b8ea581217`.
The readback-call address is not in a provider-defined function:
`ev_0aa018ba9482e2588eed1a30334802b8c240e5953842792d73927b31d5a78788`.
The QuickWriteData provider lookup did not return a usable result in this pass.
Its emulation and the command-line comparison findings therefore retain their
explicit raw-source scope; no provider function was created or expanded.
