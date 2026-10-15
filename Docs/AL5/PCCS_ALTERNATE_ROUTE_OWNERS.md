# PCCS alternate-route byte ownership and QuickWrite reset bypass

2026-10-15, offline continuation of `PCCS_ROUTE_REQUALIFICATION.md`.
Object +`0x72D90` is mutable routing state: identification entry clears it,
and generic CAN/GMW probing, version-specific identification and alternate
workflows can set it later. Standard family 1/version 0 alone does not prove
it is zero. Nonzero at the EnterWrite post-status gate bypasses the QuickWrite
reset/identification loop. Live writes remain disabled.

## Entry clear and control ownership

Identification `0x5D8EC8` clears +`0x72D90` at `0x5D8F19`, before subsequent
protocol probes. It also clears +`0x72D91..93` and six global flags in the
bounded entry slice `0x5D8EFE..0x5D8F5B`. This entry clear does not itself
clear the separate QuickWrite byte +`0x68C60`, and it does not clear global
GMW control `0x81D104`. The outer reset method's earlier QuickWrite clear
remains a separate source operation.

Global `0x81D104` is reached through pointer `0x81F530`. Source `.data`
initializes it to zero. Configuration load `0x7D3CB5..0x7D3CFA` reads section
`Communication`, key `Use GMW3110 Messages`, with default string `YES`.
After uppercasing and comparing to `YES`, `SETE` at `0x7D3CF8` stores the
result through that pointer. Missing-key default therefore enables this
control when configuration loading occurs. Source image default, configuration
default and effective runtime state are distinct. The selected configuration
file and the current AL5 session value remain unknown. The installed PCCS
tree's examined INI/CFG files did not provide this key.

A Delphi metadata record at `0x5A4FD6` associates offset `0x72D90` with the
length-prefixed name `UseGMW3110Messages` at `0x5A4FDB`. The whole containing
metadata table is not independently parsed, so this name association is
qualified rather than treated as a complete recovered type definition.

## Setters and their scope

The exact-displacement inventory found 99 raw matches across file-backed
executable PE sections: 98 candidate instructions and one metadata match.
Candidate instructions include 35 zero stores, eight one stores and one DL
store. Embedded data and same offsets in other classes can produce candidates.
The inventory is not a complete writer proof: computed aliases, overlapping
wider writes, other displacements, external modules and runtime mutation are
not excluded. Anchored source supports the following setter classifications:

- `0x5D90BC`: generic CAN/GMW probe, gated by `0x81D104 != 0`, object
  +`0x74888 != -1`, and selected index neither 5 nor 6. It sets the byte
  before helper `0x5BB93C`. This is not inherently a version-7-only setter.
- `0x5DBD8E`: GMLAN retest after host status 2 and caller flag zero.
  Diagnostic text is `(wt3 boot GMLAN retest)`. Later handling can clear
  the byte at `0x5DBE6F`; status `17` calls helper `0x5D76F8`. Complete
  success-path controller binding remains unresolved.
- `0x5D7756`: helper `0x5D76F8`, whose subsequent identification fields
  describe family 1/version 7.
- `0x5DB545`: writes DL loaded from `0x81D104`, gated by indexed version 7
  and global `0x81D110 == 0`.
- `0x5DBFD6`: IESCAN/response-specific path with +`0x72D93` nonzero;
  subsequent classification assigns family 3 (PCM).
- `0x7B67BE`: early write-body override assigns family 1/version 7 and sets
  the byte when its caller flag is nonzero. It changes the classification
  away from standard version zero.
- `0x75B37C` and `0x75BFBA`: alternate shared-object workflows; the latter
  has an earlier indexed version-7 assignment. Their complete invocation
  and standard-LCT applicability are not established.
- `0x72930B`: another indexed-state reset/enable routine. Its runtime class
  and applicability to the native standard-LCT object remain unproven.

## Why standard-LCT classification does not guarantee zero

The default standard-LCT block `0x5DA68E..0x5DA6F1` assigns version zero at
`0x5DA69B` and family 1 at `0x5DA6EA`. It does not directly clear +`0x72D90`.
Six native contexts demonstrate preservation of synthetic prior values 0, 1
and 255 across indices 0 and 3. Identity-string assignment is synthetic and
logging is disabled; the model does not prove actual AL5 reachability.

Common generic-probe fallbacks clear the byte at `0x5D9B35`/`0x5D9B9B`.
A partial identification CFG nonetheless has a conditional path from the
probe setter through `0x5D91CA`, `0x5D9BA9` and standard classification
without a direct clear. The graph examines 2472 instructions and leaves an
indexed switch at `0x5DAB17` unresolved. Its 102-instruction path is a
candidate, not proof the branch conditions are jointly feasible. Calls are
opaque, notably helper `0x5D7A98`; their effects may change this conclusion.
It is therefore unsupported to declare that every standard-LCT identification
ends with zero, or that an actual AL5 reaches this candidate nonzero context.

## Reset bypass and ordering

After successful prior preparation, EnterWrite tests +`0x72D90` at
`0x5B8FFB`. Nonzero selects the alternate identity-assignment branch and
exits through `0x5B9154` without calling VMT +`0x70`. Zero enters the ordinary
poll loop and calls the reset-and-identify method, which clears QuickWrite
before identification. Any nonzero byte takes this branch; the offline poll
model now preserves byte values rather than restricting the field to 0/1.

The gate precedes the identification-entry clear. A clear inside a reset call
cannot repair a stale nonzero byte that already bypassed that call. Conversely,
if ordinary polling was entered, it overwrites GMW control `0x81D104` with
zero before identification; this disables the generic probe controlled by
that global during that invocation. Initial identification and later polling
can therefore have different control states. Other setters and intervening
calls still require their own qualifications.

This bypass establishes that this particular QuickWrite reset does not run.
It does not establish that QuickWrite is enabled or executed: the alternate
route can also affect other preparation/write decisions, and the QuickWrite
flag is independent. No automatic slow rewrite after vector failure follows.

## Offline tools, evidence and validation

`emulate_pccs_alternate_entry.py` runs six native entry contexts with exact
one-byte write guards. It confirms entry clears the four routing bytes and
six globals while preserving synthetic QuickWrite and GMW-control state.
Three independent compositions contrast entry clearing, standard classification
and the existing post-status polling model. They demonstrate ordering with
synthetic inputs, not continuous identification or caller reachability.

`emulate_pccs_standard_lct_identity.py` runs the standard classification block
with a guarded string-assignment callback. Source pins, strict instruction/
write bounds, budgets, stack balance and exclusive output paths apply.
`emulate_pccs_enter_write_poll_gate.py` now accepts the actual 0..255 alternate
byte domain; tests verify nonzero 2/255 bypass without losing the input value.

**137 tests passed**, with the pinned PCCS/DOC inputs and both S2 images present,
with no skips. Ten new test methods cover these two new models. From
`Tools/AL5`, with optional pinned Unicorn and `AL5_PCCS_EXE` pointing to the
existing executable:

```powershell
python -m unittest test_pccs_alternate_entry test_pccs_standard_lct_identity test_pccs_enter_write_poll_gate -q
```

Private artifacts under `Tools/AL5/LocalOnly/PCCS_20261015/QuickWriteTrace/`:
`alternate-entry-source.json`, `gmw-control-config-source.json`,
`route-field-writer-inventory.json`, `ROUTE_FIELD_WRITER_FINDINGS.md`,
`native-alternate-entry-final.json` and
`native-standard-lct-classification-final.json`.
All new source analysis pins Winrw32.exe SHA-256
`13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.
The inventory and path are raw-source observations, not provider-recovered
functions or an exhaustive interprocedural analysis.

Actual AL5 state, physical packet behavior, full programming verification and
recovery after erase/interruption remain unproven. No application entry point,
Windows API, UI, COM, adapter or controller ran. The working Mode `$23` reader
and all live-write gates remain unchanged.

## Provider coverage

REA/Ghidra resolves entry clear `0x5D8F19` inside identification `0x5D8EC8`,
with eight analyzed body ranges totaling 12807 bytes:
`ev_317917e2bfbb3766e013d84296aae52952ca08e0a44b78bcfff30e9ba95fc3c3`.
Pseudocode corroborates the entry clear and later setters/clears:
`ev_9e15a846cb342523f297970b42fc5f926e0e698508179cbc5479853851e60601`.
Its int-pointer expression `+0x1CB64` corresponds to byte offset `+0x72D90`;
text searching only the byte offset would miss those references. Decompiled
flag, stack and string artifacts do not establish exact branch feasibility.

Helper `0x5D7A98` is also provider-defined, `0x5D7A98..0x5D8AF0`:
`ev_8e79e473c4820080842287da535ae6ca9df81ae3f196a4283437cbcd366d7b1c`.
Its pseudocode shows conditional updates to global `0x81D118`, which affects
the caller's branch choices:
`ev_5e600f41aa2e873c830781148489099fc829286dc19f191e223f0d9acb2b61c9`.
This helper and its callees are not fully modeled; the partial raw CFG still
treats calls as opaque. No metadata or executable bytes were modified.

The read-only session was closed and saved privately as
`pccs-alternate-route-owners-20261015.snapshot.json` (45 evidence records,
six primitive bindings).
