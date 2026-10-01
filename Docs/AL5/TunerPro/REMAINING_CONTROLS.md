# Remaining control candidates — no new XDF assignments

Historical candidate ledger below. The subsequent 83-case EFILive marker pass
resolves the named scalar/throttle identities in v0.9; see
[marker validation](MARKER_VALIDATION_v0_9.md). Three text enums remain absent,
and the subsequent v0.9.1 high-word pass resolves H0105's width question. Earlier candidate
confidence statements below describe the evidence before that pass.

`search_remaining_controls.py` narrows 14 of the 22 still-absent native IDs.
It uses the existing native export and anchored stock segment, records scaling
and packing hypotheses explicitly, and adds even-aligned address-literal hits
from the saved high firmware dump. `REMAINING_CONTROL_CANDIDATES.json` records
all matches and source hashes. Literal hits are not exhaustive decoded xrefs;
indirect address references may exist. The active XDF remains v0.7.

The original critical-controls/packing mapper outputs were inspected first.
They cover previously represented TAP/TAV/shift-time/torque controls and do not
resolve these remaining identities; this work extends their structural approach.

## Narrowed scalar families

The four Bidi-disable values D5042–D5045 have one consecutive BE16 match at
`0x9CFC`, using /4 RPM. The first three candidate addresses have repeated direct
firmware references, including word loads at `0x4239E`, `0x423A6` and `0x423AE`.
No absolute-long literal reference to the proposed fourth address `0x9D02`
was found. That is not proof of non-use, but it prevents treating the fourth
consecutive equal word as confirmed sixth-gear identity. The family remains
deferred pending control-flow or differential evidence.

D5055/D5056's /128 temperature words (29/31) have one consecutive match at
`0x1378C/0x1378E`. Their only found absolute references select the two words
based on bit three of a state byte, then compare each with the same runtime
word at A5+`0x1F04`. This is a hysteresis-shaped use, consistent with thresholds.
It does not establish that runtime word's temperature source or the precise
enable/disable semantics. The pair remains a candidate.

D5057/D5058's /8 RPM values (900/1050) have three paired matches at `0x9CF8`,
`0x1375C` and `0x145E0`. The /8 hypothesis follows the native unsigned maximum
8191.875; borrowing /4 from the signed Bidi RPM controls would be unjustified.
Their pair alone cannot establish TCC enable identity.

The combined D5061/H0103/H0137 ratio values have one consecutive match at
`0x14B14/0x14B16/0x14B18`. D5061 and final-drive H0103 use the candidate scale
1/8192; H0137's candidate raw unit is inferred from its native maximum divided
by 65535. The firmware loads the latter two words and multiplies them near
`0x2F416`. This provides structural corroboration for interacting ratios, but
the scaling and field identities still need independent confirmation. A
standalone D5061 raw word also occurs at `0x15644`; it must not be assigned from
the value alone.

`REMAINING_CONTROL_REFERENCE_WINDOWS.json` retains bounded disassembly for
the Bidi loads, temperature comparison and ratio multiplication. No code was
executed to derive these scalar references.

## Throttle-release packing

D5073/D5074 are identical 17x5 tables of 99.99847412437049%; D5075 is all zero.
The tested BE16 row/column dimension wrapper has no match. Five separate
`0x0011`-header column vectors do match: the all-65535 family has four starts
(`0x13950`, `0x13A08`, `0x13B78`, `0x13C30`), and the zero family has many.

A joint signature of those three native families in export mode order, with
`4E714E71` separators, uniquely matches `0x13950`. It is a useful reference
target, not independent proof of the normal/tow/4WD or gear ordering. In
particular, identical normal/tow values cannot distinguish their identities.
These three definitions remain absent from the XDF.

## Remaining evidence needed

Trace the selected scalar references to their runtime inputs and state bits;
check the existing differential artifacts for named field markers. For the
throttle families, trace table pointers/axis selection or obtain an existing
marker differential. Enum/locked-counter controls, repeated disabled RPM
sentinels and the remaining speedo fields require separate encoding or identity
evidence. No native ID assignments, raw BIN edits or vehicle operations were made.

## Subsequent firmware-selection validation

The code at `0x3A83C–0x3A935` now has 45 isolated selection cases. Its mode
getter reads A5+`0x1C7B`, via wrappers `0x29A60` and `0x8BA60`. The observed
selection is:

- Mode one chooses `0x13950`, or `0x13A08` when both A5+`0x1226` and the
  calibration byte at `0x11ACC` are nonzero.
- Mode two chooses `0x13AC0`.
- Other modes choose `0x13B78`, or `0x13C30` when both A5+`0x1226` and the
  calibration byte at `0x11ACD` are nonzero.

Every path adds 36 times the signed byte at A5+`0x2286` to the family header.
Indices zero through four select five distinct `0x0011`-header vectors per
family. The emulator injects that index and operating mode, stubs the getter
and interpolation helper, captures its arguments, and checks its result is
stored at A5+`0x23C4`. It verifies primary enable gating as well. It does not
execute interpolation or establish the producer's actual gear/mode names.

This resolves raw table selection while leaving D5073–D5075 identities open.
The v0.8 research supplement exposes all 25 raw vectors with selector-index
and raw-row labels, raw integer scaling, and no assigned native IDs or physical
mode names. It preserves the v0.7 named tables. Coverage remains 105/127 IDs.
See `THROTTLE_SELECTION_EMULATION.json` and
`THROTTLE_SELECTION_STATIC_EVIDENCE.json`. The active named definition remains
v0.7; v0.8 is an optional inspection supplement awaiting GUI validation.

## Runtime-input tracing

The routine at `0xA3898` updates A5+`0x1F04`: in its normal branch it copies
A5+`0x1F0A`; in another branch it uses the computed A5+`0x1F06` or a fallback
word at `0x14BA8`, depending on a calibration bit. This narrows the source of
the temperature-candidate comparison, but the sensor conversion and fault-code
meaning have not been established. Do not assign physical units from the
runtime register address alone.

The routine at `0xA3E3A` compares the runtime word A5+`0x1214` with threshold
pairs `0x1375C/0x1375E` or `0x145E0/0x145E2`. The byte at A5+`0x2D1D` selects
the latter pair when it equals one; otherwise the former is used. A5+`0x1F14`
selects the low/high threshold within either pair. Thus two of the three raw
900/1050 candidate pairs have a shared hysteresis consumer. Their precise
parameter/mode identity remains unresolved. The third pair near the Bidi
controls was not selected by this consumer. See
`TEMPERATURE_RPM_REFERENCE_WINDOWS.json` for exact bounded disassembly.
