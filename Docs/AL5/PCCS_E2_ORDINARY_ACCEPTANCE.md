# PCCS initial E2 and ordinary response acceptance

2026-10-15, offline continuation of `PCCS_CAN_HELPER_FALLBACK.md`.
The examined host parsers permit identifier zero. A synthetic accepted ordinary
`35 00` response reaches family 1/version 0, retaining alternate-route byte 1.
This strengthens the conditional standard-LCT/reset-bypass witness; it does not
establish a complete AL5 exchange or enable live writes.

## Initial E2 receive gate

The initial probe calls `0x5AC9B0` with expected service E2 and selector CL=0.
The modeled lower receive branch at `0x5AB6B9..0x5AB791` requires the signed
reported length to be greater than 8 and less than 128, format byte
object +`0x528B4` zero, and a matching identifier. The received BE16 identifier
is stored at +`0x5288C`; comparison uses `(received_id | 0x200)` against
+`0x7488C`. These are post-driver fields, not a validated wire-packet schema.

The upper branch at `0x5ACC3E..0x5ACCB9` requires the high nibble of
+`0x528B7` to be zero and compares +`0x528B8` with E2. On this positive path it
sets +`0x72D92` and calls the actual status setter `0x5B0AF8` with zero.
It does not reject a zero identifier at +`0x528B9`. The actual producer slice
`0x5BBA73..0x5BBA88` then zero-extends that byte into indexed word +`0x84`.
Synthetic identifiers 0, 1 and 255 are accepted and copied, preserving
alternate byte +`0x72D90`=1.

The new tool models three bounded native stages in shared private memory with
explicit register handoffs. It does not run complete nested calls, receive
drivers, timeout/retry paths, negative-response parsing or extended E2 paths.
Low PCI nibble values 0 and 15 also pass this particular gate; that observation
does not make either synthetic buffer a physically valid response.

## Ordinary response and classification

The dispatcher slice `0x5AFBC7..0x5B0232` derives payload length from the
reported length, subtracting 9 for format 1 and 7 otherwise. It requires positive
length and excludes `0x91`. With CCP control zero, the modeled branch rejects
format 0; format 1 compares the normalized low 24 received-ID bits with
`0xEF0000 + (global_81D0FC << 8) + target_byte`.

For synthetic source F9 and target 3, identifier `0x18EFF903` and payload
`35 00` pass. Native prefix handling compares one byte against request 35 and
allows at most two payload bytes, as configured by this caller. A guarded copy
replacement populates response +`0x52678`; the native acceptance store sets
host status zero. The second byte freshly supplies identifier zero at
+`0x52679`. Values 1 and 255 also pass acceptance.

An optional explicit phase handoff runs the actual caller branch
`0x5DA13B..0x5DA6F1` with that same accepted status and response buffer.
It reaches family 1/version 0 and preserves +`0x72D90`=1. Logging is disabled;
one string-assignment helper is replaced. This is neither complete dispatcher
execution nor complete identification execution.

A one-byte payload `35` also passes the modeled prefix gate, but does not
refresh +`0x52679`. Tests retain both zero and nonzero stale sentinels to make
this distinction visible. A previously zero byte is not evidence of a fresh
zero identifier. Wrong prefixes/IDs, oversized payloads, empty payloads and
excluded receive formats do not reach the acceptance boundary in the tested
contexts.

## Remaining reachability gap

The positive initial E2 model uses format 0 and a 16-bit received-ID field.
The ordinary positive model uses format 1 and a 32-bit received-ID field.
There is no continuous invocation proving that the initial E2 route, failed
helper, ordinary request and these accepted ordinary fields occur together for
standard LCT/AL5. Transport selection and that format transition remain the
next tracing targets. The earlier helper-failure and EnterWrite models remain
independent stages. No new QuickWrite execution, erase safety, successful flash
or interrupted-flash recovery has been established.

## Offline tools and evidence

New tools: `Tools/AL5/emulate_pccs_e2_acceptance.py` (14 receive contexts) and
`Tools/AL5/emulate_pccs_ordinary_response.py` (12 receive contexts, including
one explicit classification handoff). Both pin the installed Winrw32.exe to
SHA-256 `13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.
They enforce instruction/write boundaries, instruction budgets, stack balance,
input validation and exclusive report creation. Reports retain source-window
digests and explicit synthetic/partial-execution limitations.

These new branch observations use anchored source bytes and bounded Unicorn
2.1.4 emulation. Existing REA helper/identification evidence is retained from
the previous investigation; no new provider completeness claim follows.
Private evidence is under `Tools/AL5/LocalOnly/PCCS_20261015/QuickWriteTrace/`:
`e2-acceptance-source.json`, `native-e2-acceptance.json`, and the ordinary-response
source, findings and native report files. Source bytes remain private.

From `Tools/AL5`, with the optional pinned dependencies and `AL5_PCCS_EXE` set:

```powershell
python -m unittest test_pccs_e2_acceptance test_pccs_ordinary_response -q
```

Validation: **157 tests passed, no skips**, including ten new test methods,
the existing PCCS route/write/checksum models, DOC parsing and offline gates,
with the pinned local PCCS/DOC inputs and both S2 images present.

The tools execute no PCCS application entry point, Windows API, COM, adapter
or controller. The existing Mode `$23` reader is unchanged. All reports keep
`live_write_enabled=false`, `ready_to_flash=false` and `would_send=[]`.
