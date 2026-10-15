# PCCS QuickWrite reset and requalification

2026-10-15, offline continuation of `PCCS_VECTOR_FAILURE_RETRY.md`.
The concrete QuickWrite clear/requalification connection is downstream in
EnterWrite preparation, after communication initialization. It is conditional
on reaching that preparation path; the vector mismatch still does not itself
retry writing. Live writes remain disabled. Follow-up ownership and bypass sequencing are
traced in `PCCS_ALTERNATE_ROUTE_OWNERS.md`.

## Communication initialization versus preparation

The wrapper calls `0x5D6C5C` before the nested write body. Its anchored ordinary
source `0x5D6C5C..0x5D6E3E` builds communication arguments and calls
`0x5D37A0` at `0x5D6CD7`. It then clears two 256-entry object arrays and
communication-related fields. No direct +`0x68C60` clear or VMT +`0x70` call
appears in this wrapper's ordinary instructions. This is a bounded source
observation, not proof about every transitive hardware/driver callback.

The `0x5D37A0..0x5D564F` raw source window contains indirect driver/resource
calls and requires separate transitive analysis for completeness. Merely
returning from communication initialization must not be called successful
QuickWrite qualification.

The write body's EnterWrite path supplies a stronger direct connection.
The standard family-1/version-0 branch can reach ordinary native preparation;
EnterWrite VMT +`0x3C` resolves to `0x5B87AC`. At `0x5B8FEE`, nonzero host
status bypasses the reset loop. With zero status, object +`0x72D90` nonzero
also takes an alternate branch. With zero status and zero +`0x72D90`, the
ordinary preparation reaches VMT +`0x70` at `0x5B90B2`, passing the same
object with EDX/ECX zero. The concrete TJ1939 VMT target is `0x5DCB40`.

The concrete object binding is also source-backed: startup passes the
TJ1939 VMT from `0x5A4004`/`0x5A405C` to constructor `0x5E440C` and stores the
result through `0x81F328` at `0x7D4E5A`. The constructor clears +`0x68C60`
at `0x5E4492`. Its class name does not establish the physical bus protocol.
The standard-LCT write-body branch at `0x7B6D61..0x7B6DB5` can reach the
native route at `0x7B7C3C`, then EnterWrite calls at `0x7B85F3`/`0x7B8611`.
These source bindings connect the preparation VMT call to the reset target;
full application execution is not emulated. The effective +`0x72D90` value
for the installed AL5 remains unknown; this chain is conditional.

A separate write-body preparation retry at `0x7B86B5`/`0x7B86D3` requires
status 3 and family 1/version 7, after a 2000-ms delay parameter. Those gates
do not describe the standard version-0 route and are not AL5 recovery proof.

This reset occurs before the subsequent erase loop in the traced write-body
route. It follows session/security/request steps, whose synthetic host status
and response checks do not establish real controller acceptance.

## Requalification polling and exits

After the zero-status/ordinary-route gate, EnterWrite waits using a delay
parameter of 2000 ms for standard version zero (some other versions use
3000 ms), then starts a counter at 1. Each iteration invokes VMT +`0x70`.
A nonzero returned status skips the boot predicate; zero status calls
`0x5ADC54` (the previously traced InBoot predicate). A true result ends the
loop. A false result delays with parameter 500 ms except on iteration 12,
which sets host status 8. Incrementing the counter to 13 exits the loop.
Twelve nonzero identification statuses instead leave the last status; they
do not force status 8 or call the boot predicate in the selected path.
These are source parameters, not measured elapsed delays.

Global `0x81D104` is saved inside each iteration and overwritten from the
alternate-route byte. The final store restores the last saved value, which
need not equal the initial one: two ordinary-route iterations starting from
1 produce native writes `[0, 0, 0]` and finish at 0. Do not describe this
loop as always preserving the original global configuration.

`emulate_pccs_enter_write_poll_gate.py` executes the actual post-status loop
`0x5B8FEE..0x5B9153` and pure status getter. Ten synthetic contexts exercise
entry errors, alternate-route bypass, version-dependent delay parameters,
one/two/twelve polls and identification errors. Delay, VMT identification,
boot predicate and alternate string assignment are synthetic callbacks;
the reset body and actual identification do not run in this model. Callback
arguments, stack balance, budgets and exhausted response sequences are checked.
This demonstrates the caller loop separately from the reset-prefix model.

## What the reset actually clears

`0x5DCB54` sets object +`0x68C60` to zero before further identification.
The following loop clears byte pairs +`0xB4/+0xB5` for 2048 indexed records
and 2048 bytes beginning at +`0x72564`. Their full semantic names remain
unassigned. These bounds are the actual native loop limits, not a claim that
an AL5 contains 2048 controllers.

The rest of the reset routine updates other state and calls identification
`0x5D8EC8` at `0x5DCC1D`. Afterwards the actual host-status getter drives the
selected record's +`0xB4` success marker. This establishes a source call into
identification; it does not execute or prove successful physical identification.

The existing selection slice at `0x5DA7B1` operates on the cleared route flag.
For standard family 1/version 0, Slow Writes (`0x81D16C`) equal to 1 prevents
its modeled enable branches. Previously, selection without a reset could
preserve a stale enabled flag. Resetting first removes that prior-state case
within these modeled branches. With Slow Writes zero, index 3 additionally
requires the BE24 identity getter to be at least 16; other modeled indices
have different conditions. Index is a runtime array index, not a controller
enum. Actual identification bytes and effective AL5 state remain unobserved.

The condition for an ordinary `22` WriteData branch therefore remains:
reach the reset/identification path, retain Slow Writes 1, complete the
standard identification route with the flag zero, and reach the ordinary
WriteData decision after earlier routes. This is a conditional source chain,
not a qualified physical slow-write retry.

## Offline reset model

`emulate_pccs_route_reset.py` executes the actual native reset prefix
`0x5DCB40..0x5DCB88`, stopping before string/state updates and identification.
Two prior-route contexts prove the selected native instructions clear the
route flag and all declared marker bytes: 6145 one-byte object writes.
The only permitted writes are those exact sparse fields and the private stack.

Eight independent compositions then pass the observed reset flag into the
existing native selection model, contrasting selection with and without a
reset for synthetic indices, identity values and Slow Writes states. The
models execute in separate emulators: this is not a continuous initialization
or identification replay, and it does not establish caller reachability.
Tests cover source pins, context validation, instruction/write bounds,
marker coverage, stale-state behavior and existing-output preservation.

Private evidence under
`Tools/AL5/LocalOnly/PCCS_20261015/QuickWriteTrace/` includes
`initialization-route-source.json`, `enter-write-requalification-source.json`,
`ENTER_WRITE_REQUALIFICATION_FINDINGS.md`, `native-enter-write-poll.json` and
`native-route-reset-selection.json`.
Source-bound windows record bytes, offsets, digests and decoded coverage;
they are not provider-defined functions or complete transitive call proofs.
All new source observations pin Winrw32.exe SHA-256
`13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.

## Validation

**127 tests passed**, with the pinned PCCS/DOC files and both S2 images present,
with no skips. Ten new test methods cover the reset prefix/compositions and
post-status polling model. From `Tools/AL5`, with the optional pinned Unicorn
dependency and `AL5_PCCS_EXE` pointing to the existing executable:

```powershell
python -m unittest test_pccs_route_reset test_pccs_enter_write_poll_gate -q
```

The tools write exclusive JSON report paths and never emit flash images or
packets. All reports retain `live_write_enabled=false`, `ready_to_flash=false`
and `would_send=[]`.

## Remaining qualification gaps

A vector failure closes host communication, forces Slow Writes and returns.
The caller's explicit retry still belongs to initialization status `0x0C` and
a dialog decision. Neither this retry nor the downstream reset establishes
recovery after erase/interruption. Actual AL5 family/version/identity, route
state, driver-batch behavior, physical transport, programming acceptance and
independent programmed/preserved-area verification remain unproven.
No PCCS application entry point, Windows API, UI, COM, adapter or controller
executed; the working Mode `$23` reader and live-write gates are unchanged.

## Provider coverage

REA/Ghidra resolves communication initialization `0x5D6C5C` to a defined,
non-contiguous function with ranges `0x5D6C5C..0x5D6CE5` and
`0x5D6CFA..0x5D6E30`:
`ev_fac12bf5eeb7f68cfd2076612941c5806176ca975106884a8131b384d83b9cc0`.
Its dossier corroborates the call to `0x5D37A0` and explicit object-field
clears: `ev_14747c9501d33d62647ec77d373387af67db0c197b3fe87a1f5bf81dc65fed73`.
Decompiler flag/stack reconstructions are not treated as exact source; the
anchored instructions remain the basis for the branch observations.

Reset target `0x5DCB40` remains `not_in_procedure`:
`ev_15579cc1ffc41095b8895dda559a3d2febad2ea03ff0fca29a3b278b17081abd`.
Its findings remain raw-source/native-slice evidence; no function was created
or expanded.

The read-only session was closed and saved privately as
`pccs-route-requalification-20261015.snapshot.json` (41 evidence records,
six primitive bindings).
