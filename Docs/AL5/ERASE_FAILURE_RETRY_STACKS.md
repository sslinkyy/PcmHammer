# AL5 erase/program failures and retained retry stack frames

`emulate_loader_erase_failures.py` extends the loader-entry model with original
ID checking, two-sector erase call chains, toggle polling and nonlocal error
routing. It executes nine explicit offline sequences in Unicorn 2.1.4. Flash
ID words and poll samples are synthetic. Every ID/erase/reset command store
is suppressed before execution; erased bytes and physical flash mode are not
modeled. No adapter, driver or vehicle is opened.

The source is the existing captured loader, SHA-256
`b545d9b2d078662466ab32d9cdeb5b3c38c840135e8aeca09f33760ec66780fa`.
Source-range and implementation/dependency hashes are recorded in
`LOADER_ERASE_FAILURE_EMULATION.json`. The report contains synthetic test
state and logical status bodies, not original loader bytes or wire captures.

## ID and sector cleanup

With synthetic manufacturer `0x0001`, device `0x2258` and stable toggle samples,
original code calls sector helper `0xFF937A` for `0x8000` and then `0x10000`.
The successful sequence constructs body `76 00 EE` and returns to receive with
the entry stack restored. Each stable sector path reaches two reset stores;
these stores are counted and skipped, not executed.

A manufacturer mismatch branches around the ID reset store, while a device
mismatch reaches it before rejection. Both produce `76 00 89`, reach no sector
helper, and leave one pending return word: `0xFF9256` (-4 bytes).

Persistent toggling after the bit-5 recheck sets D7 bit 2, constructs
`76 00 85`, and jumps nonlocally to receive. The failing sector skips its
normal reset stores. A first-sector failure never invokes the second sector.
The actual pending return words, from current SP upward, are:

- First sector: `FF9370`, `FF9358`, `FF9256` (-12 bytes).
- Second sector: `FF9378`, `FF9358`, `FF9256` (-12 bytes).

A synthetic toggle that becomes stable on the bit-5 recheck instead follows
the normal reset/return path. These samples test native branch semantics;
they do not establish how an installed flash chip behaves.

## Mixed retries do not unwind older errors

One same-session sequence performs an erase-poll failure, a word-program
failure, a successful erase path and a successful word-program path. Stack
deltas are `-12`, `-16`, `-16`, `-16`. The four retained words remain exactly
`FF91BE`, `FF9370`, `FF9358`, `FF9256` throughout the later successful calls.
A successful response therefore does not demonstrate that prior error frames
were cleared. This includes actual receive/parser/caller execution, not a
fresh stack or manually reconstructed receive buffer between attempts.

Another sequence combines first- and second-sector failures with a later ID
failure: deltas become `-12`, `-24`, `-28`. A successful program afterward
retains -28. Selecting original software entry resets A7 and the receive
budget; it does not roll back the modeled program state or clear the receive
buffer. The sender timeout that can branch to entry is still not executed
here. Software entry is not an established recovery command.

The existing loader-entry emulator now exposes instruction ownership and
observation creation at the owning class boundary. The erase extension reuses
its native runner, callback caller validation, receive/parser model, read-only
loader page, fail-closed lifecycle and 256-byte stack guard. Default loader
entry experiments still stop before erase. No opcode patches are introduced.

## Resource guards and physical limits

The prolonged-toggle case stops after a selected small number of poll
iterations with `synthetic_poll_budget`, without inventing a native error
response. This is a terminal test-resource stop. The source loop still has no
identified software deadline when toggling continues and bit 5 remains clear.

A repeated-error test deliberately reaches the emulator's stack-ownership
guard. It fails closed before proceeding outside the permitted stack region;
further frames and software reentry are rejected. The 256-byte region is an
experiment boundary, not measured physical stack capacity or a safe retry
count. No physical collision, flash mode or preservation conclusion follows.

Thirteen tests cover the two sector call sites, ID cleanup differences,
recheck and prolonged-toggle branches, exact retained return words, mixed
success/failure, stack-guard termination and invalid contexts. A planner test
pins the evidence and leaves physical erase mode, erase deadline, recovery,
automatic retry, live writing and flash readiness unqualified. The previous
loader-entry report is regenerated after its behavior-preserving extension
points were added. The Mode `$23` reader and C# write rejection are unchanged.

With the existing Unicorn path and `AL5_CAPTURED_LOADER` set, run from
`Tools/AL5`:

```powershell
python -m unittest test_loader_erase_failures test_loader_entry test_offline -q
```

Physical erase extent and collateral preservation, independent programmed-image
readback, and interrupted-flash recovery remain unproven. The user has no
recoverable spare AL5 available; the installed truck TCM remains outside
experimental qualification. Live writes stay disabled.

Validation: **322 offline tests passed with no skips**, including the existing
parser/program/receive regressions. The new CLI reproduced the nine-case report
byte-for-byte. Staged changes passed `git diff --cached --check`. No adapter,
controller or vehicle access occurred.

[Error sender and native software reentry](ERROR_SENDER_REENTRY.md) follows actual sender timeouts through their JMP into loader entry. Intended status bytes do not qualify physical delivery or retry safety; live writes remain disabled.
