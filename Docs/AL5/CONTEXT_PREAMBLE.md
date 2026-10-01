# Context preamble and bounded alternate invocation

The context initialization preamble itself reaches persistent writes. All results
below use saved firmware and synthetic RAM/storage. Real flash primitives are
replaced by atomic host models; no hardware, transport or programming packet is
used. The direct reader and C# write gate are unchanged.

## Small records

Static reader `0x228D8` selects a main record and addresses four 12-byte slots
immediately after its 2546-byte context. For a main record at bank offset `0x28`,
the slots begin at offsets `0xA1C`, `0xA28`, `0xA34` and `0xA40`. Each has a
two-byte marker followed by ten payload bytes. These are address observations,
not calibration parameter identities or verified physical storage geometry.

The reader accepts a selected pending or committed parent record. Twelve
isolated cases use a pending parent and each of four slot indices:

- Slot marker `0xFFAA`: return zero and copy ten bytes.
- Slot marker `0xFFFF`: return one and leave the destination untouched.
- Slot marker `0x0000`: return two and leave the destination untouched.

Helpers `0x5B5E4`, `0x5B6E4` and `0x5B7EC` read slots 0, 1 and 3 into
`A5+0x1418`, `A5+0x1422` and `A5+0x142C`. The caller then reads slot 2 into
`A5+0x1436`. Real bit-vector helpers initialize or combine two 40-bit vectors
and clear a selected bit. The tested erased-slot sequence writes slots 0, 1 and
3 through their wrappers: marker `0xFFFE`, ten payload bytes, then marker
`0xFFAA`. This produces nine atomic program operations and no modeled erase.
Only those slot spans change; bank 2 remains unchanged.

Two cold cases, starting with different RAM fills and running the previously
traced startup clear, produce matching contexts with no preamble helper bypasses.
The older startup report remains a historical bounded result; this report
extends it with the preamble effects.

## Main update and alternate invocation

The main-context update's tail copy starts at bank offset `0xA4C`, after all four
small records. A separate modeled main update therefore leaves the destination
bank's four slots erased. Preservation cannot be inferred from copying the main
context and its tail alone.

The bounded alternate path starts at `0x79112`: it calls preparation `0x5BAB8`,
cache clearing/selection `0x22B0C`, then the context initializer `0x5B8EC`.
Preparation retains the existing ten explicit subsystem bypasses. The real
update caller performs seven modeled main-context operations, moving the
committed record from bank `0x4000` to `0x6000`. The real preamble then rewrites
slots 0, 1 and 3 in the new bank with nine further modeled program operations.
The context restores, passes its CRC and matches the thirteen-byte calibration
comparison at `0xC5D50`, reaching `0x5BAA6` without repeating default helpers.
Its context hash equals the separately prepared context hash.

This establishes sixteen atomic operations in that bounded synthetic path, not
a complete warm startup or recovery guarantee. Execution stops before the
initializer's status restoration and epilogue. Calls preceding `0x79112`,
intervening startup, other slot contents, partial programming, physical error
behavior and controller geometry remain unverified.

## Evidence and reproduction

[Static observations](CONTEXT_PREAMBLE_STATIC.json) omit raw firmware bytes.
[Emulation report](CONTEXT_PREAMBLE_EMULATION.json) records source/code hashes,
two pipeline cases and twelve reader cases; all fourteen pass. Reproduce with
`Tools/AL5/emulate_context_preamble.py --low <saved-low-dump> --high
<saved-high-dump> --output <report>` in the existing Unicorn M68020 environment.
The standard-library regression suite now contains 71 passing tests.

The file-only planner hash-links this report and explicitly marks initialization
as having persistent writes. Complete startup, physical recovery and write
readiness remain false; erase scope remains null and all packet lists empty.
Next examine the earlier alternate-path calls and small-record failure ordering
before claiming preservation. No live erase/program testing is authorized.
