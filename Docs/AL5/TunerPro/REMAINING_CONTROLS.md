# Remaining control candidates — no new XDF assignments

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
evidence. No speculative entries, raw BIN edits or vehicle operations were made.
