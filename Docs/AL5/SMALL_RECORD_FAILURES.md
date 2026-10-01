# Small-record interruptions and modeled status failures

Twenty-eight saved-firmware cases exercise the real writer `0x2296C` and reader
`0x228D8` for four initially erased slots under a pending parent. All actual
flash implementation entries remain trapped. Successful host writes are atomic
and enforce one-to-zero transitions; injected failures perform no write and
store synthetic status `0x0020`. This does not establish physical status behavior.

For each slot, stopping after zero, one, two or three atomic operations gives:

- Zero: erased marker `0xFFFF`; reader returns one, destination untouched.
- One: marker `0xFFFE`; reader returns two, destination untouched.
- Two: payload written but marker `0xFFFE`; reader still returns two.
- Three: marker `0xFFAA`; reader returns zero and copies the requested payload.

The same caller also runs with one no-write failure at each operation. It returns
after all three attempts and does not branch on the injected status between
them. Failure of the first marker operation still allows payload and final
marker writes. Failure of the payload operation still allows the final marker:
the resulting `0xFFAA` slot is accepted by the reader, which copies ten erased
bytes rather than the requested payload. Failure of the final marker leaves
`0xFFFE`, rejected by the reader. Only the selected slot changes in these cases.

These observations establish caller ordering under the declared model, not
hardware failure semantics or the full initializer's subsequent response. The
reader reselects the saved parent after each interruption; this is not execution
of a reset. Partial words, non-erased payloads, committed parents, full caller
reaction and physical programming/recovery remain open.

[The report](SMALL_RECORD_FAILURE_EMULATION.json) includes source/code hashes,
all 28 cases and explicit false readiness/recovery flags. Its code windows are
documented in [the preamble static observations](CONTEXT_PREAMBLE_STATIC.json).
Reproduce with `Tools/AL5/emulate_small_record_failures.py --low <saved-low-dump>
--high <saved-high-dump> --output <report>` in the existing Unicorn environment.
The planner hash-links this evidence but still emits no packets or erase scope.
