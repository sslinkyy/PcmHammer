# Receive dequeue and response scheduling

Offline native evidence from the same hash-pinned HIGH firmware used in
`MODE23_COVERAGE_20261030.md`. No adapter, vehicle, flash or peripheral access
occurred. The new native harness and report are `emulate_mode23_boundary.py`
and `MODE23_BOUNDARY_20261030.json`. Capstone supplied the local disassembly;
Unicorn executed only allowlisted functions with synthetic queue/RAM state.

## Receive queue observations

`0x23694..0x23778` uses the ring at `0xFF8EB6`, consumer offset A5+`0xEFF`,
producer offset A5+`0xEFE`, and first-record state A5+`0xF00`. Zero at the
current record returns zero. In first-record state, equal producer/consumer
offsets also return zero; otherwise the current offset is returned, the raw
length/flag byte is saved at A5+`0x13A7`, and its high bit is removed.

Subsequent calls calculate the next record offset from the current length.
The native bound check wraps to offset 1 when current offset + length + 13
is at least 53. If the next record is present, the previous record is cleared
and the consumer advances. If no next record exists, zero is returned and the
current record remains in RAM. Tests execute initial, advance, no-next, equal
offset and wrap cases. This is not a model of the ISR producer or atomicity.

Crucially, a zero dequeue result leaves Mode 23 pending state and response
data unchanged. Receive emptiness therefore cannot be used as transmit drain.

## Shared response staging and native formatter

Mode 23 stages one six-byte body at `0xFFA269` and sets bit `0x10` at
`0xFF8F3F`. This is pending index 75 in the MSB-first bitmap at A5+`0xF36`.
The response table entry at `0x6DDBA` is service `0x63` and descriptor
`0x6DF50`, which points to that body and specifies six bytes.

Two native handlers executed before formatting replace the single body; the
second body is what gets formatted. No per-request response FIFO was found in
this path. This test deliberately feeds two requests; it does not claim the
normal serialized reader actually loses responses this way.

The scheduler slice at `0x23ABC` selects index metadata then calls `0xC17E4`
to clear the pending bit before invoking formatter `0x23C9C`. Executed physical
formatter `0x23E88` builds priority/destination/source/service from shared
dispatcher metadata; `0x23EE4` appends the six-byte body. Helper `0x70E34`
stages bytes into RAM at A5+`0x16DE` with count at A5+`0x16E9`; it does not
write the peripheral. With synthetic priority group 3 and destination F0,
the real instructions produce `6C F0 18 63 FF FC BF D0 E1 F2` for the synthetic
tail data. Both empty RX and cleared pending coexist with those staged TX
bytes. Neither state proves transmission completion or host receipt.

## Reply ordering prevents a generic query fence

Executed selector `0x23BD4` calls bitmap scan `0xA9BF0` and checks eligibility
bitmap A5+`0xF48`. For the tested range 1 through 84 it selects the lowest
eligible pending index. Tests stage Mode 23 index 75 first, then synthesize
pending index 65 (service `0x62`, Mode 22 reply). With both eligible it selects
65 first, then 75 after clearing 65. Removing eligibility for 75 produces no
selection while its pending bit stays set.

Thus response selection is not a general arrival-order FIFO. A later Mode 22
query response cannot be assumed to fence an earlier Mode 23 response. This
experiment executes the native selector with synthetic flags, not the Mode 22
handler or complete outer scheduler. Eligibility initialization, timer gates,
interrupts, hardware transmit completion, adapter queues and host USB ordering
are still outside the experiment. No maximum stale-response latency is known.

## Result and next boundary

Eight native cases and four saved-evidence/identity tests pass; existing C#
offline correlation tests also pass, including all 10,250 supplemental dwords.
The native fixtures explicitly retain `session_boundary_proven=false`.

Keep one request pending, do not automatically retry after timeout, and do not
reuse an address echo within an offline correlation instance. Starting another
instance, clearing host queues, waiting an arbitrary delay, or receiving an
unrelated diagnostic response does not qualify a physical session boundary.
The existing live reader and its range remain unchanged; live writes remain
disabled. The remaining 41,000 bytes have not been acquired.

The next unresolved path is transmit submission/completion after formatting
(`0x70A44` and its callers), together with the ISR producer and eligibility
initialization. A usable boundary needs evidence that earlier Mode 23 work is
completed or invalidated across controller and adapter queues, not merely
absent from one local queue. These tests narrow that requirement rather than
assert a reliable boundary that has not been demonstrated.
