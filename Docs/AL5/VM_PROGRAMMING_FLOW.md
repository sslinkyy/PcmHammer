# AL5 VM programming and recovery control flow

File-only static analysis, 2026-10-11. Live writes remain disabled. The exact
trace/object/dll hashes, reconstruction stages and per-instruction digests are
in [VM_PROGRAMMING_FLOW.json](VM_PROGRAMMING_FLOW.json) and
[EFILIVE_VM_DISPATCH.json](EFILIVE_VM_DISPATCH.json).

The reconstructed DATA section is the instruction stream; CODE is the value
pool. Native vmStep fetches little-endian 16-bit opcodes. The installed object
header selects initial entry `0x2AD8` and host-error entry `0x2A76`.
The listing groups 1,117 candidate instructions across 11,394 bytes; 14 trailing
bytes remain uninterpreted. Every direct branch/call target lands on a structural
instruction boundary. All five saved W reconstructions have the same DATA hash.
Descriptor grouping is derived from this stream; full opcode arities and helper
side effects are not established. B0 payloads are skipped by their signed length,
not searched for opcodes. Unsupported/truncated representations fail closed.

The main path calls initialization `0x0000`, loader preparation `0x17E4`,
recovery information `0x2036`, and precondition checking `0x2904`. It then calls
erase setup `0x1A6A` at `0x2BF0`. Flag `0x80` routes errors to `0x2A00`.
Assignments at `0x2C22`, `0x2C2C`, and `0x2C38` select block size 512 and
bounds `0x8000..0x1FFFD`. Calls at `0x2C4E` and `0x2C5A` enter programming
`0x1B6E` and finalization `0x1DEC`, each followed by an error branch.
The final jump at `0x2C66` reaches cleanup `0x29F0`.

Those inclusive bounds cover 98,302 bytes, exceeding the 57,304-byte calibration
segment by 40,998 bytes. They are observed object values, not executable erase
scope or proof of physical preservation. The final two marker bytes are excluded
from these bounds. Conditional sector erase geometry still has separate limits.

Erase setup inserts literal `0x36EE`, calls common exchange `0x0188`, and compares
a response field against `0xEE`. A separate simulation branch labels simulated
erasing and assigns `0x36DB`; the other branch assigns `0x3600` for later use.
These literals do not establish serialized wire packets.

Programming labels its phase and initializes an attempt counter at pool `0x217A`
to three (`0x1BBC`). Field-copy operations construct a buffer using the selected
command, length and address. Native opcode 24 copies first operand to second
using third operand as offset; B0 views reverse byte stepping, so this must not be
flattened to forward memcpy. The exchange call is at `0x1CE8`. Response comparisons
select distinct `0x73` and `0x77` branches. A failure branch calls helper `0x028E`;
the backoff path delays, subtracts one from the attempt counter (`0x1DD4`) and
tests flag `0x20` before returning to `0x1CCA`. The subsequent [retry/flag audit](VM_RETRY_FAILURE.md) resolves this immediate
condition as stored-result nonzero. Executable retry authorization and physical
acknowledgment success remain unproven.
Exhaustion sets flag `0x80`. Progress also loops to `0x1BBC`.

Finalization selects `0x36FE` or `0x36FF` according to system reference `0xFF28`,
calls `0x0188`, and checks different response values (`0xFE` or `0x86`). Failure
sets flag `0x80`. The earlier loader evidence remains necessary to interpret the
marker operation; this VM listing alone does not resolve either variant fully.

Cleanup `0x29F0` clears system status `0xFF07` and jumps to host-error entry
`0x2A76`. Common error entry `0x2A00` protects against repeated handling through
pool `0x214A`, constructs status, and reaches the same cleanup. Host-error entry
saves status, invokes unresolved host operations 99/93/64, calls `0x2C6C`, then
opcode 81 at `0x2AD2` sets the native stop flag and returns the saved status.
Callback failures can redirect PC to this entry outside ordinary VM edges.
The inspector omits fallthrough from stop, unconditional jump and return.
Call continuations and reachability are context-insensitive candidates; dynamic
returns and callback effects remain unresolved.

The recovery message in `0x2036` is conditional status reporting. Error cleanup
and stop paths do not prove recovery after interrupted erase/programming. Session
entry, physical acknowledgment/readback, storage preservation, interrupted power
recovery, and safe erase geometry remain unverified.

`Tools/AL5/inspect_vm_flow.py` requires an explicit saved trace and installed object
with their expected SHA256 values. It reuses strict captured-reply reconstruction,
checks the validator CRC, and writes an exclusive JSON output. It never executes
VM instructions or contacts host IPC, an adapter, or a controller. The offline
planner hash-links both evidence reports and keeps erase scope unset and every
packet list empty.
