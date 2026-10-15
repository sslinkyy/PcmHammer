# WriteCal switches and FIL selection effects

All three previously unresolved WriteCal switches are now reconstructed.
None of their new branches converts controller selection 3 to J1850 address
`0x18`. A separate callee does have a selection-changing path: the FIL
interpreter can assign an instruction byte to the shared selection global.
That branch is not a J1850 map lookup, and its use by an AL5 programming
workflow remains unproven.

This continues [the later-control and address-mapping investigation](PCCS_J1850_REENABLE_ADDRESS_MAPPING.md).
Source is the installed Winrw32.exe SHA-256
`13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.
Only static file parsing and bounded original-instruction emulation ran.
No PCCS process, driver, Windows UI callback, adapter or controller ran.

## The switches close local branch gaps

- `0x7C4EAD`: status is masked with `0x7F`, checked against `0x17`, then
  indexes 24 DWORD destinations at `0x7C4EB4`. Every case/default reports
  a failure, joins `0x7C4FEB`, calls cleanup/status helper `0x5D3310`, and
  exits to `0x7C6EDD`. Host messages include invalid address, programming
  mode failures and security denials. These labels are host text, not an
  independent decoding of wire response codes.
- `0x7C592D`: local byte `EBP-0x5B` indexes ten destinations at `0x7C5934`
  after an unsigned upper bound of 9. These format gear text: N, 1..6,
  R, P, L, or default ?. All join the "Not neutral and stopped" prompt.
  At the examined numeric gate of at least 20, UI result 3 sets failure
  status and exits; other results continue toward existing EnterWrite calls
  `0x7C5A98/0x7C5AAB`. The lower-gate branch exits after its prompt.
  This continuation is not a J1850-specific programming bypass or control
  re-enable. The UI result meanings are not inferred.
- `0x7C5B8A`: status masked with `0x7F` and bounded by `0x16` passes
  through a 23-byte remap at `0x7C5B91`, then seven DWORD destinations at
  `0x7C5BA8`. All cases/default report failure, join `0x7C5C5F`, call
  `0x5D3310`, and exit to `0x7C6EDD`.

The expanded direct-branch graph contains 2,659 instructions, including 103
newly covered instructions. It has no remaining unresolved jumps within its
explicit bounds. Calls are assumed to return and their effects are not
included in this graph. Thus resolving the switches does not establish
interprocedural state purity or complete programming reachability.

## A callee can change selection

WriteCal invokes FIL interpreter `0x75B330` at `0x7C50FD`, `0x7C521B`,
`0x7C5415` and `0x7C5796`. In its selection-changing branch:

1. `0x75C44A` requires local action byte `EBP-0x3C` equal to 1.
2. `0x75C454` requires interpreter word `0x9D2DEE` at least 4.
3. `0x75C462` requires local byte `EBP-0x3B` at least 1.
4. With the byte behind `0x81F250` zero, `0x75C480` stores local byte
   `EBP-0x3A` through selection alias `0x81EAF0` into `0x81D0F4`.
5. Whether that store occurs or the nonzero flag preserves selection,
   `0x75C492/0x75C4AA` mark the resulting indexed family/version fields
   as 1/7. The stride is `0xA4`, with offsets `+0x80/+0xB6`.

The native local producers load these fields from the 16-byte interpreter
record: byte 1 is the opcode, byte 2 supplies the requested selection,
byte 4 supplies the local version selector and byte 5 supplies action.
Opcode 1 dispatches to this area. This distinguishes a selection assignment
from a Controllers-to-J1850 configuration translation.

A structural inventory of the 49 installed PCCS FIL files found no record
matching opcode 1, action 1, local version selector at least 1 and header
interpreter at least 4 that requests selection `0x18`. This is a bounded
inventory, using the existing strict structural decoder and native field
producers; it does not execute interpreter control flow or prove that other
files cannot select that value. In particular, an opcode-1 record containing
target byte `18` in POONLY has action zero, so the target byte alone does
not establish execution of this setter.

Earlier direct `[ESI]` store searches need a narrower interpretation:
ESI is re-used as an object VMT at `0x7C4BE9` on an early retry path. It is
the confirmed selection pointer at the previously modeled write-call slice,
but it is not universally that pointer throughout WriteCal. Callee mutation
must be analyzed independently; an absence of direct caller stores is not
evidence that selection stays constant across interpretation.

The retained files do not yet establish an AL5-specific `0x18` selection,
its survival through later calls, a compatible TJ1850 write path, or recovery
after erase/interruption. Changing the logical selection also changes indexed
state; it is not a qualified repair for the fixed-target security mismatch.

Other traced calls retain important uncertainty:

- Identity refresh `0x7B4BEC` invokes virtual `+0x70` on the current object;
  its retry can close/reopen the connection and identify again. TJ1850 binds
  that slot to `0x726734`. Full transitive reset effects remain unaudited here.
- Reconnection wrapper `0x5D6C5C` reads the selected protocol/library and
  initializes the existing object through `0x5D37A0`; the inspected wrapper
  does not construct a different class. Loader/driver callback effects remain
  unknown. Close/unload helper `0x5D3310` clears connection/callback state;
  its actual callbacks were not run.
- ReadParameter virtual `+0x48` binds to TJ1850's fixed-target `0x18` reader.
  Inherited EnterWrite `+0x3C`, block fill `+0x1C`, nested utility preparation,
  file/container helpers and possible reentrant UI callbacks still require
  further transitive analysis. No examined wrapper establishes a J1850
  class/protocol replacement or programming bypass.

The examined caller subset does not contain an equivalent of the UI's
explicit J1850 exclusion. Its protocol reads at `0x7C467C/0x7C4FC2` format
error messages; the nearby library-name guard tests VIRTUAL, not J1850.
Consequently, the disabled controls must not be described as an enforced
prohibition inside WriteCal itself. A programmatic route into this function
would still need caller/state qualification and compatible controller-side
programming; neither has been demonstrated.

## New offline checks

`emulate_pccs_writecal_switches.py` parses the guarded tables and executes
the original selectors for all 256 byte inputs per switch: **768 cases**.
It stops before each destination, rejects every native memory write and
checks PC coverage, instruction budget and stack balance. Table data is
kept separate from instruction ranges.

`emulate_pccs_fil_selection.py` executes only `0x75C44A..0x75C4B2` or stops
at its earlier exits. **48 contexts** exercise action/version/subaction,
selection flag and requested selection 3/`0x18`. Original instructions can
change selection to `0x18` in a qualifying synthetic context; a nonzero flag
preserves selection while still updating its indexed family/version fields.
The report records exact native writes. This does not execute an actual FIL
or prove that an LCT utility reaches the branch. Following interpreter work,
possible later restoration and any transport remain excluded.

Both tools pin the original executable and retain source-range digests,
synthetic-context labels and explicit omitted-execution fields.
Validation: **239 tests passed with no skips**, including ten new test
methods and the existing pinned offline/native suite. Focused command from
`Tools/AL5`, with Unicorn 2.1.4 and `AL5_PCCS_EXE` configured:

```powershell
python -m unittest test_pccs_writecal_switches test_pccs_fil_selection -q
```

Private evidence in `Tools/AL5/LocalOnly/PCCS_20261015/QuickWriteTrace/`
includes `writecal-switches-source.json`, `writecal-switches-expanded-cfg.json`,
`writecal-switches-strings.json`, `WRITECAL_SWITCHES_FINDINGS.md`,
`writecal-callee-effects-source.json`, `WRITECAL_CALLEE_EFFECTS_FINDINGS.md`,
`writecal-callee-effects-fil-inventory-final.json`, `native-writecal-switches.json`
and `native-fil-selection.json`. Source parsing does not claim new provider
function completeness. Mode `$23` reading is unchanged; live writes remain
disabled, `ready_to_flash=false` and `would_send=[]`.
