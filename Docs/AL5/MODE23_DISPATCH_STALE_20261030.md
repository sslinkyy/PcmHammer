# Mode 23 dispatch and stale responses

## Evidence and native scope

This continues `MODE23_COVERAGE_20261030.md` using the same hash-pinned HIGH
firmware. No vehicle, adapter, unlock, or flash operation ran. Capstone supplied
the local static disassembly; Unicorn executed the isolated native descriptor
processor and Mode 23 handler/helpers. This is not a full firmware simulation.

Static dispatcher `0xA4A38..0xA4C9E` obtains queued work via `0x23694`.
After queue acceptance it uses request offset A5+`0xEFF`. The observed path
checks internal length 3 through 11, priority bit 4 clear and bit 3 set. Mask
`0x04` at `0xA9DD2` selects the physical service-table branch; that branch also
requires priority bit 1 clear. Both `0x6C` and `0x6D` pass these priority checks.
Lookup uses service byte offset 4 and table `0x99A70`. At `0xA4C20..0xA4C26`
it passes argument 1 and the selected descriptor to `0xB1970`.

There is an earlier alternative route when saved selector `0x10954` equals 1
and A5+`0x13A7` has its high bit set. Queue acceptance, address filtering before
this point, this alternate route, and queue-state transitions remain unexecuted.
These conditions must not be reduced to an unconditional dispatch claim.

The real Mode 23 descriptor is `9000000BFDA0` at `0x99A12`. Twenty native
experiments use states 0, 1, 2, 3 and 255 at A5+`0xF2A`, lock flags 0 or `0x20`
at A5+`0x1DBE`, and callback arguments 0 or 1. Argument 1 reaches the real
handler in all tested states, even with the lock flag set. Argument 0 only
reaches it in state 0. In each reached case the request for `0x1FFFC` stages
the expected four synthetic data bytes, low-16 echo and pending flag `0x10`.

Unlike the Mode 34 boot handler, this Mode 23 handler does not inspect the
lock flag. This establishes no additional unlock requirement in the executed
descriptor/handler path; it does not prove all upstream session restrictions
absent. `MODE23_DISPATCH_20261030.json` records hashes, cases and limits.

## Host correlation findings

The existing live reader clears buffers before each send and permits three
send attempts. `Vehicle.ClearDeviceMessageQueue` delegates to
`Device.ClearMessageQueue`, which clears the host queue and device buffer.
For OBDX, `ClearMessageBuffer` calls `Port.DiscardBuffers`. None of these source
operations establishes that the controller has no pending response or that a
future arriving reply belongs to the new attempt.

Positive Mode 23 responses have no transaction number and echo only low 16
address bits. A delayed same-address retry reply, or a prior-bank reply whose
address differs by `0x10000`, can satisfy the parser. Negative replies identify
the service but carry no requested address. These are potential ambiguities;
we have not observed corruption in the saved successful reads.

`AL5SavedReadSession` is an offline correlation rehearsal with exactly one
pending request. It ignores unrelated echoes, rejects orphan responses and
concurrent requests, and stops on malformed/negative replies, timeout or
cancellation. It never automatically retries. Reusing any low-16 echo within
an instance stops the session, including same-address repeats and bank aliases.
The 41,000-byte supplemental range has 10,250 distinct echoes and passes this
model. A combined 98,304-byte snapshot would reuse echoes and is deliberately
not accepted as one such session.

A new instance does not establish a clean physical session. An old response
from outside its history can still match. Tests demonstrate that limitation;
`FreshnessProven` and `LiveReadEnabled` remain false. No arbitrary delay or
buffer flush is promoted to a freshness guarantee. No changes were made to
the existing live reader or its range.

## Validation and continuation

The 20 native callback cases, 10,250-dword offline correlation sequence,
duplicate/stale/timeout/negative tests, existing Mode 23 report tests and library
build pass. The library retains its three existing CS1998 warnings. All 210
null-vehicle write-gate checks pass.

Next trace the native receive dequeue at `0x23694`, queue invalidation and
response scheduling to establish whether a bounded drain or a distinct
read-only exchange can provide a useful session boundary. No such boundary is
qualified yet. Broader live reads and all AL5 live writes remain disabled.
