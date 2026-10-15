# PCCS CAN/GMW helper failure and standard-LCT fallback

2026-10-15, offline continuation of `PCCS_ALTERNATE_ROUTE_OWNERS.md`.
Follow-up: [E2 and ordinary acceptance](PCCS_E2_ORDINARY_ACCEPTANCE.md) models
positive host-parser acceptance of zero. The format transition and complete
AL5 exchange remain unproven; the assumptions below describe this earlier model.
A concrete failed-request path through helper `0x5D7A98` preserves the
nonzero alternate-route byte and can pass the caller's ordinary-fallback
gate. Later ordinary identification can replace the failed host status.
Standard-LCT classification and reset bypass remain conditional on that
subsequent response and intervening guards. Live writes remain disabled.

## From initial probe into the helper

The generic CAN/GMW probe requires global `0x81D104 != 0`, object
+`0x74888 != -1`, and selected index neither 5 nor 6. It sets +`0x72D90`
to 1 at `0x5D90BC` before calling `0x5BB93C`. Initial probe status zero
at `0x5D9123..0x5D912A` leads to helper `0x5D7A98`, called at `0x5D9187`.
This initial success is distinct from the helper's later request failure.

The initial probe `0x5BB93C` writes indexed word +`0x84` from an accepted
response byte on its E2 paths: source +`0x528B9` at `0x5BBA81`, or +`0x528BB`
at several other stores. It does not simply leave the preexisting word alone.
The examined body does not directly require that byte to be nonzero. The
zero-word witness therefore assumes an accepted upstream E2-path reply carrying
identifier byte zero. Whether a real AL5 supplies or accepts that response is
unproven; zero-initialized object memory alone is insufficient.

The helper first uses object VMT +`0x54` at `0x5D7B67`, selector low byte
`B4`, output buffer size 16 and stack arguments `-1, 1, 16`. These are host
call parameters; the method body and physical request are not executed by
the model. Actual status getter `0x5B0AF0` runs at `0x5D7B73`.

Nonzero status at `0x5D7B7A` jumps directly to terminal gate `0x5D89FE`,
bypassing successful-response parsing. That gate assigns family 1/version 7
only when global `0x81D118 == 0` and indexed word +`0x84` is nonzero. With
both zero, it makes no such assignment and reaches cleanup. The selected
path does not clear +`0x72D90`, alter the word, or set recognition flag
`0x81D118`. A synthetic failed status 9 can therefore remain 9 with flag 0,
word 0 and alternate byte 1 at this boundary.

The helper has other response/classification paths. For example, source
`0x5D7F03..0x5D7F30` can set `0x81D118` after a zero status and sentinel-byte
checks. Unknown/GMLAN and version-7 paths also exist. The new model excludes
those parsers; it does not establish a universal helper postcondition.

## Why the caller can fall back despite the error

After helper return, `0x5D91A1..0x5D91CA` tests only `0x81D118` and the
indexed word +`0x84`. Either nonzero selects exit `0x5DC085`. Both zero
select ordinary fallback `0x5D9BA9`, without checking host status or clearing
+`0x72D90`. This exact native gate accepts the failed-helper state above.
Conversely, a nonzero identifier word on the modeled failed-request path
causes the helper's terminal version-7 classification and makes this caller
gate exit. The upstream identifier byte is therefore a material constraint,
not an incidental synthetic value.

On a traced ordinary route, UI flag `*0x81EB44 == 0`, CCP control
`0x81D108 == 0`, caller stack flag zero and selected index 3 lead to internal
request `35` at `0x5D9F04`. VMT +0 dispatch occurs at `0x5D9F94` (EDX 1,
timeout parameter 200) or `0x5D9FB4` (EDX 5, timeout parameter 500), selected
by a local flag. These buffers/parameters are not qualified VPW/CAN packets.

The real VMT +0 target `0x5AEDC4` assigns host status 1 at `0x5AEE25` on a
fresh dispatch. The native entry model confirms prior statuses 0, 1, 9 and
255 become 1; it executes only the two instructions `0x5AEE22..0x5AEE2B`.
Thus an earlier helper failure is not a permanently latched error across
that dispatch. This does **not** prove the new dispatch succeeds. Later
response handling can set zero, for example the guarded store at `0x5B022C`;
its full acceptance contract and physical responses remain unproven.

After the new dispatch, `0x5DA13B..0x5DA14A` tests its status. A constrained
source witness with new status zero and response byte +`0x52679 == 0`
reaches the standard classification block `0x5DA68E`, which assigns family
1/version 0 without directly clearing +`0x72D90`. The 86-instruction witness
fixes conditional branches and assumes intervening calls permit continuation.
It is not an observed full invocation or proof of an actual AL5 reply.

## Consequence for QuickWrite reset

If that conditional continuation preserves alternate byte 1, EnterWrite's
post-status gate bypasses VMT +`0x70`, the reset-and-identify call. Standard
family 1/version 0 alone does not rule out this nonzero input to the gate.
The byte surviving this specific helper failure is now modeled rather than
left entirely opaque. The ordinary reply and intervening continuation are
still assumptions, so actual AL5 reachability has not been established.

This bypass does not by itself enable or execute QuickWrite. Other routing,
preparation, driver and object-state decisions remain separate. It also does
not provide retry, flash integrity or interrupted-flash recovery evidence.

## Offline tools and evidence

`emulate_pccs_gmw_helper_failure.py` executes the failed first-request slice,
the helper's terminal gate and actual pure status getter. Eight cases vary
failed status, recognition/word fields, alternate byte and selected index.
Only the virtual request is synthetic. Success response parsing, full helper
cleanup and hardware calls are excluded. A second bounded function executes
the dispatch status-reset instructions with one permitted object write.

Its conditional pipeline connects observed helper outputs to the new caller
gate, then explicitly assumes ordinary-response success before invoking the
existing standard-classification and EnterWrite-gate models. Each stage runs
independently. The report retains `continuous_execution=false`,
`actual_al5_reachability_proven=false` and four explicit assumptions.

`emulate_pccs_can_fallback_gate.py` runs twelve native caller-gate contexts,
varying recognition flag, identifier word and host status. All native writes
are forbidden in that gate. Its separate three-instruction producer slice
`0x5BBA73..0x5BBA88` copies a synthetic response byte into the indexed word;
values 0/1/255 become words 0/1/255. Only the destination word is writable.
This models the upstream producer without proving acceptance of the reply. Both tools guard source hashes, instruction and
write boundaries, budgets, context types, stack balance and exclusive output.

**147 tests passed**, with the installed pinned PCCS/DOC files and both S2
images present, with no skips. Ten new test methods cover the two models,
including eight helper contexts, twelve caller contexts, three identifier
producer values and dispatcher-entry status replacement. From `Tools/AL5`,
with optional pinned Unicorn and `AL5_PCCS_EXE` pointing to the existing file:

```powershell
python -m unittest test_pccs_gmw_helper_failure test_pccs_can_fallback_gate -q
```

Private artifacts in `Tools/AL5/LocalOnly/PCCS_20261015/QuickWriteTrace/`:
`gmw-helper-failure-source.json`, `probe-helper-retained-pseudocode.txt`,
`can-probe-caller-fallback-source-final.json`,
`CAN_PROBE_CALLER_FALLBACK_FINDINGS.md`, `can-initial-probe-word84-source.json`,
`INITIAL_PROBE_WORD84_REFINEMENT.md`, `native-can-fallback-gate-final.json` and
`native-gmw-helper-failure-refined.json`. The final caller source supersedes an
exploratory empty-witness report. All new source observations pin Winrw32.exe
SHA-256 `13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.

No PCCS application entry point, Windows API, UI, COM, adapter or controller
executed. The Mode `$23` reader and live-write gates remain unchanged.
Full response acceptance, actual AL5 state, physical routing, complete flash
verification and recovery remain unproven.

## Provider scope

The helper's retained REA observations are reused rather than regenerated:
`ev_8e79e473c4820080842287da535ae6ca9df81ae3f196a4283437cbcd366d7b1c`
resolves its defined body, and
`ev_5e600f41aa2e873c830781148489099fc829286dc19f191e223f0d9acb2b61c9`
retains the provider pseudocode. The original source-bound snapshot remains
unchanged; the extracted private text is a view, not executable source.

A supplementary dispatcher-address lookup did not return usable structured
evidence in this pass. No new provider function or completeness claim follows
from it. The new branch and copy observations rely on anchored source windows
and the declared native slices; no function was created or expanded.

The read-only session was closed and saved privately as
`pccs-can-helper-fallback-20261015.snapshot.json` (45 retained evidence records,
six primitive bindings). No new dispatcher observation was added.
