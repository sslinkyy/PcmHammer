# PCCS J1850 later controls and controller addressing

The examined later communication, protocol and controller-selection handlers
preserve the J1850 programming restriction. No controller `3` to physical
address `0x18` conversion was found in the examined selection owners or
ordinary-write forwarding. These findings strengthen the
[initial compatibility findings](PCCS_J1850_PREPARATION_COMPATIBILITY.md);
they do not establish that every indirect path has been excluded.

All observations use the installed Winrw32.exe SHA-256
`13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.
Only original-file parsing and bounded native instruction emulation ran.
No PCCS process, driver, Windows UI setter, COM or hardware ran.

## Later enable sites keep their J1850 guards

Preserved Delphi method records identify the following handlers:

- `Communication1Click` at `0x7D7F28`: after accepted dialog result 1,
  the J1850 branch at `0x7D81AD..0x7D829B` creates TJ1850 and disables
  programming controls again. It jumps past the generic enable branch.
  The latter creates the base class and requires a separate numeric gate
  of at least 15. Its enable sites are not evidence of J1850 re-enablement.
- `CommProtocol1Click` at `0x7DC3A4`: after accepted dialog result 1,
  the J1850 branch at `0x7DC520..0x7DC5C0` disables programming buttons
  and skips the generic, numerically gated enable block.
- `ControllerRadioGroupClick` at `0x7E1DFC`: ordinary selected index 3
  reaches the protocol gate at `0x7E211E`. J1850 or XCP_ETHERNET jumps to
  `0x7E2202`, skipping programming-enable instructions `0x7E214C..0x7E21FF`.
  This gate skips enables; it does not itself clear stale control state.
  Earlier initialization and communication/protocol handlers provide the
  observed J1850 disables. Complete callback ordering remains unobserved.

The raw executable-section candidate inventory retained 96 instruction
candidates for four main-form field displacements, including overlapping
false candidates and unrelated classes. Examined main-form RecoverTCM
references supplied false to its setter; no direct true setter was found.
This is not an alias-complete inventory. Computed field access, shared
control aliases and unexamined callers remain unknown.

## Logical controller selection remains separate from the J1850 map

The producing owners still distinguish `[Controllers]` at object `+0x68C04`
from `[J1850]` at `+0x68C0C`. The selected global is `0x81D0F4`; image pointer
`0x81EAF0` aliases it. In addition to the previously traced common selector:

- `0x7ED807` writes selection through the alias after querying the Controllers
  map and parsing with default 3. It does not query the J1850 map.
- `0x75C480` supplies a FIL instruction byte under interpreter/action gates
  and marks family/version 1/7. It is not an established standard LCT J1850
  address conversion.
- `0x5B5F4F` temporarily sets selection from a caller argument of at most
  `0xFF`; `0x5B5FC3` restores the saved selection. That setter does not
  perform a configuration translation.
- The J1850 parameter/DPID loop at `0x7260CD..0x726146` parses an address
  with default `0x18` into its local byte. It does not write the selected
  global in those instructions.

The bounded audit examined 123 decoded absolute global-reference candidates
and 1001 raw alias representations. Local straight-line alias tracking found
33 candidate pointed writes, with no literal `0x18` store. Tracking stops at
calls/branches or 12 instructions and therefore does not prove whole-program
absence. All eight raw `+0x68C0C` representations were accounted for as map
lifecycle, metadata or local-loop accesses; generic/computed access remains
outside that claim. The retained 2556-instruction direct-branch WriteCal CFG
contains no store through its long-lived selection pointer, but three
unresolved indirect switches and unexamined callee effects remain limits.

Forcing logical selection to `0x18` is not a demonstrated repair: selection
also indexes controller state. TJ1850's fixed seed/key words `+0x29C/+0x29E`
match logical index 3 in the inherited indexed fields, as documented in
[security prerequisites](PCCS_J1850_IDENTITY_PREREQUISITES.md).

## New offline tools

`emulate_pccs_j1850_reenable_gate.py` runs the original interior controller
refresh gate for J1850, XCP_ETHERNET, CAN and IESCAN. Synthetic string equality
checks the original UTF-16 literal bindings. The model stops before all
control setters: J1850/XCP skip, while CAN/IESCAN reach the enable-block
boundary. It assumes earlier event state and does not establish actual UI
state or a complete session.

`emulate_pccs_j1850_write_target.py` runs independent WriteCal caller and
WriteData forwarding slices, followed by an explicit synthetic handoff to
the existing TJ1850 envelope model. Five selected values and three wait-field
states check that the caller preserves the dword and WriteData forwards its
low byte. Selection 3 produces host target `03`; selection `0x18` produces
`18`. The `0x103` case demonstrates byte truncation. These deliberately
synthetic inputs do not prove reachability or pre-slice mapping. The envelope
uses synthetic payload `10 10`, not a reconstructed WriteData request.
No virtual write or send callback executes, and the stages are not a
continuous writer.

Both tools pin the source executable, original instruction ranges and VMT or
literal bindings, bound PCs/writes/instruction counts and check stack state.
Reports preserve the omitted execution, synthetic context and hardware limits.

Validation: **229 tests passed, no skips**, including ten new tests and the
existing pinned offline/native suite. Focused command from `Tools/AL5`, with
Unicorn 2.1.4 and `AL5_PCCS_EXE` configured:

```powershell
python -m unittest test_pccs_j1850_reenable_gate test_pccs_j1850_write_target -q
```

Private evidence is retained under
`Tools/AL5/LocalOnly/PCCS_20261015/QuickWriteTrace/`:
`pccs-j1850-reenable-source.json`, `PCCS_J1850_REENABLE_FINDINGS.md`,
`address-mapping-decisive-source.json`,
`PCCS_J1850_ADDRESS_MAPPING_FINDINGS.md`, `pccs-j1850-write-target-source.json`,
`native-j1850-reenable-gate.json` and `native-j1850-write-target-audit.json`.
Candidate inventories and prior REA evidence remain private and unchanged.
No new provider function-completeness claim is made.

The checked handlers do not establish a supported PCCS J1850 AL5 writer.
Another application's VPW programming protocol remains a separate lead.
Programming and recovery after erase/interruption are unproven. Mode `$23`
reading is unchanged; live writes remain disabled, `ready_to_flash=false`
and `would_send=[]`.
