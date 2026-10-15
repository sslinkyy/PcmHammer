# PCCS fallback and receive-format transition

2026-10-15, continuation of `PCCS_E2_ORDINARY_ACCEPTANCE.md`.
The host explicitly selects different message envelopes for the initial E2
probe and ordinary identification. The difference between the prior parser
models is therefore supported by host formatting code. Actual driver filters,
AL5 support for both exchanges and complete invocation success remain unproven.
Live writes remain disabled.

## Caller reaches the ordinary request

New native model `emulate_pccs_fallback_request.py` follows caller instructions
from `0x5D91A1` through the ordinary indirect-dispatch boundary at `0x5D9F94`
or `0x5D9FB4`, without an independent phase handoff. One identity-string
assignment is replaced; UI/logging is off and controller index is fixed at 3.
The supplied post-helper fields remain synthetic.

Recognition flag and identifier word both zero take fallback `0x5D9BA9`.
With CCP off and caller flag zero, the actual caller prepares command 35,
request length 1, prefix length 1 and maximum response length 2. It retains
alternate byte +`0x72D90` and the earlier host error up to dispatch. The short
wait flag selects EDX 1/timeout parameter 200; otherwise EDX 5/parameter 500.
The stack arguments at the pending dispatch are target 3 and zero.

The model also observes the actual exclusions: nonzero recognition or word
exits; CCP on with +`0x74890 != -1` selects helper `0x5D7458`; caller flag one
sets status 2 and skips this ordinary request. CCP on with handle -1 reaches
ordinary dispatch in this bounded caller path, but that does not qualify the
resulting transport configuration. No dispatcher or driver call executes.

## Header rebuilding explains the format difference

The initial probe calls formatter `0x5A8BB8` with DL=0 at `0x5BBA2B`.
It writes format 0 at +`0x528B0` and a two-byte BE identifier from +`0x74888`
at +`0x528B1`. The probe then builds its initial request and invokes
`0x5A8D20`. That helper pads/builds the buffer and uses callback object +8
with connection word +`0x2C` at `0x5A8DC3`. These are host buffer formats,
not a standalone physical packet specification.

The ordinary dispatcher `0x5AEDC4` calls formatter `0x5A8C58` at `0x5AEE43`.
With CCP global `0x81D108` zero, native instructions `0x5A8CDD..0x5A8D0F`
build ID `0x18EF0000 + (target << 8) + source_81D0FC`, store four BE bytes,
and write format 1. These header-selection instructions do not consult the
retained +`0x72D90..0x72D93` flags. For synthetic target 3/source F9, the
header is `01 18 EF 03 F9`. The previously modeled ordinary reply comparison
expects the corresponding low 24 bits `EF F9 03`.

The ordinary dispatcher invokes `0x5A924C` at `0x5AEEB7`. The new
`emulate_pccs_transport_envelope.py` runs the actual header formatter, then an
explicit independent packet-assembly phase. It constructs the host buffer
`01 18 EF 03 F9 35` and stops **before** callback +8 at `0x5A92B1`, with the
same connection-word field as the initial helper. The native byte-order helper
runs; buffer-copy helpers are guarded replacements. Initial E2 padding and
sending are not emulated by this tool.

For CCP on, the formatter instead uses +`0x74890`; its comparison with 0x7FF
is signed. Tests include ordinary 16/32-bit header examples and a raw
`0xFFFFFFFF` edge case, without treating those checks as physical CAN-ID
validation. Turning alternate byte off does not change the CCP-off header.

Source tracing also connects the ordinary sender's zero driver result to the
normal receive callback at `0x5AF3F0`, using object +`0x0C`, connection word
+`0x2C` and capacity `0x21A`. This is a conditional static edge. The model does
not execute that sender result, the receive callback, timeout logic or complete
dispatcher entry.

## What remains unresolved

Host-side formatting now explains why the initial and ordinary parser slices
use different formats. It does not show the driver's selected bus, active
filters or handling of mixed identifiers. No continuous initial E2 response,
failed helper, ordinary driver exchange and standard-LCT classification has
been replayed. The early probe has additional device/string gates; modeled
post-driver fields do not establish a real AL5 reply.

The source-bound TJ1939 VMT +`0x54` resolves to `0x5BE860`. Its selector path
at `0x5BE915..0x5BE933` can join the format-0 request branch when +`0x72D92`
is set by initial E2 acceptance. This is supporting static evidence only;
the prior failed-helper callback remains synthetic. Driver configuration and
the concrete helper response/failure path are the next useful tracing targets.
QuickWrite execution, flash integrity and interrupted-flash recovery remain
unqualified.

## Evidence and validation

Both new tools pin Winrw32.exe SHA-256
`13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.
They guard execution/write boundaries, instruction budgets, context types,
stack accounting and exclusive report creation. The caller model has ten
contexts; the formatter audit has six, plus a signed-field edge test.

Private source windows and native reports are retained under
`Tools/AL5/LocalOnly/PCCS_20261015/QuickWriteTrace/`, including
`fallback-request-transition-source.json`, `native-fallback-request.json`,
`transport-envelope-selection-source.json`,
`TRANSPORT_ENVELOPE_SELECTION_FINDINGS.md` and `native-transport-envelope.json`.
New observations are anchored static bytes and bounded Unicorn 2.1.4
emulation; earlier REA evidence is reused. No new provider completeness claim
or analysis-database mutation follows.

Validation: **167 tests passed, no skips**, including ten new test methods,
with pinned PCCS/DOC inputs and both S2 images present. Focused command from
`Tools/AL5`, with optional dependencies and `AL5_PCCS_EXE` configured:

```powershell
python -m unittest test_pccs_fallback_request test_pccs_transport_envelope -q
```

No PCCS application entry point, Windows API, COM, adapter or controller runs.
The working Mode `$23` reader remains unchanged. All reports retain
`live_write_enabled=false`, `ready_to_flash=false` and `would_send=[]`.
