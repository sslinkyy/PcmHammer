# PCCS FIL transfer path — offline, 2026-10-15

FIL opcode `B0` now has a source-bound bridge to PCCS's transfer helpers.
The examined routine helper has separate interpreter-3 and interpreter-4+
paths. Neither identifies a qualified AL5 utility or VPW programming sequence.
Live AL5 writes remain disabled.

Follow-up: [native LCT writer tracing](PCCS_NATIVE_LCT_WRITE.md) connects a
separate native caller to WriteData and the erase helper, identifies the
Use CCP Messages configuration flag, and models the file-loop slice.

## Exact source and evidence scope

Installed `Winrw32.exe` 15.2.17.0, SHA-256
`13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.
Older-build offsets are not interchangeable. Capstone 5.0.6 windows retain
raw source offsets, instruction bytes and window hashes. A bounded linear
decode is not a recovered complete function or proof of caller reachability.
Ghidra's separate function observations are identified below.

Private evidence is retained in
`Tools/AL5/LocalOnly/PCCS_20261015/TransferTrace/`:

- `fil-routine-transfer-static-windows.json`: 15 source-bound windows.
- `fil-routine-transfer-inputs.json`: selected FIL identities and B0 steps.
- `FIL_ROUTINE_TRANSFER_FINDINGS.md`: exact branch and instruction anchors.
- `framing-emulation-final.json`: eight isolated framing contexts.
- `pccs-transfer-trace-20261015.snapshot.json`: retained REA analysis.

No application entry point, Windows API, adapter, controller or vehicle network
was executed. Selected native instructions ran only in private Unicorn memory
with explicitly replaced callbacks, as described below.

## Parsing and utility interpreter ownership

The Delphi descriptor for LoadFromUtilityFile identifies `0x756654`; the
utility viewer calls it at `0x7EE25D`. It reads the big-endian interpreter field
at FIL header offset `0x0C`. Its explicit UI labels are **GMLAN** for value 3
and **ISO15765-3** for value 4. These are observed PCCS labels, not standards
compliance or controller compatibility claims.

The interpreter also reads these fields at `0x75BD25`. Header offset `0x0E`
gives the routine-table offset, `0x12` the default address and `0x16` the packet
size. The traced header parser clamps packet size to `0xFF0`. At `0x75BE91`
it reads sequential BE32 addresses and BE16 lengths, allocates payload memory,
and reads routine bytes at `0x75BF19`.

Routine ordinals begin at 1. Address, length and payload-pointer storage use
bases `0x9C1308`, `0x9C135A` and `0x9C1D98`, indexed by ordinal. Therefore the
first actual address entry is `0x9C130C`; scratch instruction bytes overlap
the nominal zero-index address location. Do not invent an ordinal-zero routine.

Opcode dispatch at `0x75C249` reaches the B0 handler at `0x75CEC3`. Indexed
branches load a routine address and ordinal, then call `0x759E04` at
`0x75CF81` / `0x75D060`. Other B0 branches use the header address or call the
separate file-transfer helper `0x759368`. B0 is not uniformly a routine load.

For the supplied generic CALONLY and APPONLY utilities, interpreter is 3.
Their B0 steps 4, 6 and 30 select routines 1, 2 and 3 respectively:
`0x400000` / 32 bytes, `0x7FA020` / 2,808 bytes and `0x7FAB18` / 120 bytes.
Step 8 selects the file-transfer path, not an indexed routine. The file-name
similarity between utility variants does not establish LCT/DF9 compatibility.

## Two transfer paths in the routine helper

Helper `0x759E04` uses the routine length/payload arrays, copies chunks into
`0x9D1DEC`, calls `0x5B10BC`, and advances the address/payload position after
host status zero. A separate argument value 3 selects `0x5B3BE0`.

- Interpreter 3 starts the counter at zero. The legacy `0x5B10BC` branch
  constructs `36`, a flag byte (`80` or `00`), and a BE32 target address.
  This helper does not bracket that branch with `34` and `37`.
- Interpreter 4+ starts the counter at 1, first calls `0x5B3A44` with address
  and length, uses counter-bearing `36` transfers and then calls `0x5B3B90`.
  The counter advances with successful chunks.

The newer request-download builder encodes `34 00 34`, a BE32 address and
BE24 length across internal segmented buffers, then waits for `74` through
`0x5ABD18`. The transfer helper waits for `76`. The final helper builds
`01 37` and waits for `77`. These internal buffers are not qualified wire
frames. In particular, do not assign this entire newer sequence to the
generic interpreter-3 utilities.

The transfer helper recognizes immediate `7F 36` negative responses. In the
traced branches `85` becomes host status 4, other immediate negative codes
become `0F`, and `78` avoids that immediate-failure branch. Full timeout,
pending-response and status meanings remain unresolved. This is host response
handling, not interrupted-flash recovery. The `37` here is separate from the
[DOC startup `37`](LCT_SESSION_TRACING.md).

## Separate dispatch and framing paths

The erase helper's indirect VMT slot resolves through the source-bound TJ1939
VMT at `0x5A405C`: its self pointer is at `0x5A4004`, class-name bytes at
`0x5A5AFA`, and slot zero points to dispatcher `0x5AEDC4`. The preceding
entry at `0x5A4058` is not slot zero. That dispatcher calls prefix builder
`0x5A8C58`, then payload-copy wrapper `0x5A924C` in its traced normal path.

The FIL helpers instead call `0x5A8D20` directly. That wrapper invokes the
callback at object +8 with five arguments. Callback identity/loading and the
complete transport implementation remain unresolved in this pass.

The FIL extended-prefix builder `0x5A8AD8` writes flag 1 and the big-endian
identifier derived from `18DA00F9 + (destination << 8)` in one explicit branch;
an alternate branch uses `0CDA...`. The standard-prefix helper `0x5A8BB8`
writes flag 0 and a BE16 identifier from object +`0x74888` in its ordinary
branch. These bodies do not use the erase dispatcher's `0x81D108` selection
check. Do not transfer that global's semantics between paths without a caller.

## Offline framing tool and validation

`emulate_pccs_framing.py` pins the executable hash and Unicorn 2.1.4. It executes
only declared prefix, byte-order, wrapper and status-helper ranges. Copies,
string cleanup and the final callback are replaced with synthetic operations.
Execution addresses, native writes, copy spans, callback arguments, instruction
budgets and stack returns are checked. Source spans and their hashes are saved.
Existing report paths and changed source hashes are rejected.

Eight contexts cover J1939-style target/source fields, identifier override
around `0x7FF` / `0x800`, the fixed startup source and separate FIL extended
and standard prefixes. FIL payload bytes are **prefilled synthetic caller
state**: opcode builders, the FIL interpreter and full dispatcher do not run.
The FIL extended case explicitly chooses global `0x81D144 = 1`; the alternate
text-comparison/0CDA branch remains unmodeled. Classical CAN payload length
1..8 is a harness scope, not a discovered AL5 transfer-block limit.

From `Tools/AL5`:

```powershell
$env:AL5_PCCS_EXE = 'PATH\Winrw32.exe'
python emulate_pccs_framing.py $env:AL5_PCCS_EXE --output 'PATH\new-framing.json'
python -m unittest test_pccs_framing test_lct_typelib test_lct_event_setup test_lct_command_tables test_lct_session_callbacks test_allison_playback test_offline test_authorization test_pccs_methods -q
```

Current validation: 67 tests passed, including five framing tests and eight
native framing contexts. Pinned-input tests skip explicitly when their local
source or optional emulator is absent. The working reader is unchanged.

## Remaining gates and provider observations

The next useful trace is B0's separate file-transfer helper `0x759368`, followed
by actual LCT utility selection and transport callback binding. Routine CPU
architecture, complete erase scope, preservation, final verification and
post-interruption recovery remain unproven. No live writer is enabled.

Ghidra defines `0x5B10BC` as a complete 5,330-byte body; dossier Evidence:
`ev_6a40795d35200aa10e9f69244a34831937f982c6ce722376804b7099d8ae9846`.
Its decompiler contains unreliable Delphi stack/parameter/string artifacts;
source-byte windows remain the basis of the detailed byte encodings above.
Prefix helper resolution Evidence:
`ev_9a371b71932fefee049ee90878fc671d5cfa6ee17c7e2fb2d1fcf4ebdff5b311`,
`ev_eae0c738a60e9b99610731b0b50c71753ba03c7d0ec084cdb71fece8053e1e71`,
`ev_ad98588b0635da7315083b7e0d4746187eb704be602d816a8303ae8667bea9e7`.
Ghidra's wrapper bodies are non-contiguous and omit epilogue helpers; the
emulator's declared raw bounds include the source-bound normal epilogues and
do not mutate or expand the provider's function definitions.
