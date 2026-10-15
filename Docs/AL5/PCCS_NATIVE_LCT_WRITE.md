# PCCS native WriteData and file-loop tracing

2026-10-15, offline only. A concrete native programming branch now connects
the calibration UI to the known erase helper and WriteData. This narrows the
AL5 investigation beyond the generic FIL path, but does not qualify a writer.
Controller/context binding, preparation, erase geometry, verification and
interrupted-flash recovery remain unresolved. Live writes stay disabled.

## Source and retained evidence

Installed Winrw32.exe SHA-256:
`13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.
Static Capstone 5.0.6 windows preserve source offsets, bytes and hashes.
Private evidence is in `Tools/AL5/LocalOnly/PCCS_20261015/FileTransferTrace/`:

- `LCT_SELECTION_FINDINGS.md`, `selection-metadata-source.json` and source windows.
- `writecal-nonzip-cfg.json`: partial recursive direct-branch graph, 2,556
  decoded instructions; indirect dispatches at `0x7C4EAD`, `0x7C592D` and
  `0x7C5B8A` remain unresolved. It follows no callees.
- `file-helper-static.json`: 825 instructions in a bounded raw source window.
- `native-file-chunk-slice.json`: eight synthetic file-loop cases.
- `native-write-data.json`: twelve synthetic WriteData cases.
- `pccs-native-write-trace-20261015.snapshot.json`: 27 REA Evidence records,
  four primitive bindings, including retained earlier analysis.

Raw windows and the partial graph are not full function/reachability proofs.
Ghidra observations are separate. No installed executable, COM object,
transport, adapter or controller ran. Native emulation uses private memory
and synthetic callbacks only.

## Controller selection and native caller

WriteCalClick compares the extension with `.ZIP` at `0x7C8F81`. Its ZIP
branch calls FIL entry `0x75B330`; the other path calls `0x7C44AC` at
`0x7C91F8`. That second handler also contains selective FIL branches, so it
must not be described as wholly native-only.

Source enum metadata records controller family LCT = 1, LCT_Boot_Reprogram = 2
and ISO15765 = 5. TLCTVersion records standard_lct = 0, power_pc_a = 3,
b_sample = 7 and power_pc_b = 8, among other values. The identification code
at `0x5DAB83` writes version zero and later logs LCT Gen3 application. These
are host enum/identification facts, not physical MCU identification.

At `0x7C4FF9`, one FIL condition requires family 1, version 7 and a separate
enabled flag. Family 5 also enters that branch. Standard_lct version zero
does not satisfy this particular version-7 condition; that does not exclude
all other FIL routes in the application.

The alternate native region calls VMT +`0x1C` at `0x7C60CE`, passing erase
argument 3 and the controller index. The source-bound TJ1939 VMT at
`0x5A405C` maps this to the existing erase helper `0x5B5410`.

The native transfer loop reads its initial address from the per-controller
field +`0x74`, then calls VMT +`0x10` at `0x7C627D`. Each call passes length
`0x100`, controller index, two zero flags, an indexed buffer from the array
whose pointer is held at `0x81F12C`, and the current address. Host status zero
advances that address by `0x100`. Errors, cancellation and entry-length checks
affect continuation. Source array construction, final partial-block treatment
and exact erase/preservation coverage are not established by this loop.

VMT +`0x10` resolves to `0x5B487C`, named **WriteData** by its Delphi method
descriptor at `0x5A6540`. This is a concrete native writer lead, rather than
an inference from a utility filename.

## Configuration ownership: CCP is not controller identity

Configuration reader `0x5E440C` reads **Use CCP Messages** under
**Communication**. Uppercased first character Y sets global `0x81D108` to 1;
N clears it. The source uses a null default and other characters leave prior
state unchanged. This pass does not establish the effective installed value.

Consequently WriteData's `02` / `03` branch is CCP-selected. It must not be
called the LCT branch merely because a synthetic object also has family 1.
The older erase emulator's `lct` input is a different field: the per-controller
family byte at +`index*0xA4+0x80`, not global `0x81D108`.

## Native WriteData behavior under synthetic contexts

`emulate_pccs_native_write.py` runs the source body
`0x5B487C..0x5B4D1B` and its real host-status getter. Only memory copy and the
VMT dispatcher are replaced. Source hashes, execution ranges, memory writes,
copy spans, callback parameters, instruction budget and RET-16 stack balance
are checked. The model bounds payloads to 1..256 synthetic bytes; this is not
a discovered controller limit.

- With CCP disabled and the alternate FIL/bulk-routing fields zero, WriteData
  builds internal `22`, a BE24 address and at most four data bytes. Successful
  acknowledgements advance both address and payload position.
- Ordinary response byte +`0x5267C` maps zero to continuation, 1 to host status
  4, 2 to 5, 4 to 6 and other nonzero values to `0D`. Nonzero host status also
  stops further chunks. No per-chunk retry appears in this selected path.
- With CCP enabled, the initial internal request is `02`, the object field
  +`0x74884`, two zero bytes and a BE32 address. Data requests use `03`, that
  field, chunk length and at most five data bytes. The initial address request
  must succeed before data transfer begins. Nonzero acknowledgement at
  +`0x52679` maps to host status 2 and stops continuation.
- In these contexts the dispatch timeout argument is 500. This is a host
  parameter, not a measured or qualified controller timing requirement.

The alternate routes through `0x5B3344`, FIL helper `0x5B10BC` and VMT +`0x18`
are disabled in this model by explicit synthetic state. Actual AL5 routing
requires proving those fields and the transport binding. The internal `22`
request has not been assigned standard service semantics by analogy or
approved for transmission.

Twelve audit cases cover the two paths, four-/five-byte boundaries, initial
host failures, CCP address/data acknowledgement failures and ordinary response
mapping. Additional checks cover exhausted synthetic responses and 256-byte
payloads. No real dispatcher, Windows API or controller response executes.

## Separate FIL file-transfer loop

The non-routine B0 helper `0x759368` uses stream objects rather than indexed
routine payloads. Some early missing-selection/null-stream branches set host
status zero without transfer. They are static observations outside the modeled
slice, and reinforce why status zero alone cannot prove programming success.

`emulate_pccs_file_chunks.py` executes only
`0x75951B..0x7597D1`, stopping at `0x759D33` **before cleanup**. Entry, UI
setup and the full helper do not run. Stream, status, transfer, cancellation,
progress and rounding callbacks are synthetic; the rounding replacement
consumes its x87 input to preserve the loop's stack behavior.

For the positive explicit-endpoint, offset-zero contexts:

- Interpreter 3 passes counter zero without download/exit bracketing.
- Interpreter 4 starts at counter 1, performs synthetic download and exit
  calls around successful transfers, and advances the counter.
- A ten-byte file with chunk size four produces lengths 4, 4, 2. With the
  modeled final flag enabled, only the short-final branch passes flag 1;
  an exact eight-byte boundary passes flag zero twice.
- Native address advancement uses the full configured chunk size, including
  after a short final transfer. Thus the ten-byte context's final local address
  advances by twelve. Fixed-address mode suppresses address advancement.
- The first failed transfer stops continuation and skips the modern exit
  helper. Synthetic cancellation stops data transfer but can occur after the
  download helper. No interrupted-flash recovery is established.

Nonzero stream offsets, alternate selector 3 and the no-explicit-endpoint paths
remain unmodeled. The +`closure-0x18` field is compared to stream position, so
it must not be generalized to a relative byte count without tracing its caller.

## Reproduce and remaining gates

From `Tools/AL5`, with optional Unicorn 2.1.4:

```powershell
$env:AL5_PCCS_EXE = 'PATH\Winrw32.exe'
python emulate_pccs_native_write.py $env:AL5_PCCS_EXE --output 'PATH\new-write-data.json'
python emulate_pccs_file_chunks.py $env:AL5_PCCS_EXE --output 'PATH\new-file-loop.json'
python -m unittest test_pccs_native_write test_pccs_file_chunks test_pccs_framing test_lct_typelib test_lct_event_setup test_lct_command_tables test_lct_session_callbacks test_allison_playback test_offline test_authorization test_pccs_methods -q
```

Current validation: **77 tests passed**, including ten new test methods and
20 native contexts across the two new audit matrices. Pinned real-input tests
skip explicitly if their input or optional emulator is absent. Existing report
paths and source mismatches are rejected. The working Mode `$23` reader and
live-write gates are unchanged.

Next: prove the standard-LCT object's preparation and routing fields; trace
the remaining native methods at VMT +`0x18`, +`0x20` and +`0x2C` for
verification/session behavior; establish final-block preservation and post-erase recovery. This is
offline host evidence, not authorization or readiness to program the truck.

REA Evidence anchors:

- WriteData dossier: `ev_200e0f2a6e55b5c3e3c051d4285c2f7f0e56a8cff78d9491ff57807d43c6fdd5`.
- Configuration dossier: `ev_9e65baf605c777f80c34a28e812a0f3db707bfc2d79ff0b193fdfca2165da48f`.
- Caller body resolution: `ev_28c341515f8b0925fa64cd35968fa7ee4914ab89c06b8e882d11c76bfdd6ef60`.

Ghidra's caller and WriteData bodies contain non-contiguous ranges; Delphi
stack, exception and string artifacts remain explicit limitations. Raw normal
return bounds used by the emulator are not mutations of provider definitions.
