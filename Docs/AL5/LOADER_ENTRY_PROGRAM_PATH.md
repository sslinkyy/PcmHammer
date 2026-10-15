# Captured AL5 loader entry and programming continuity

`emulate_loader_entry.py` joins original loader entry, receive polling, header
validation, block parsing, checksum verification and the word-program/error
path in one offline Unicorn 2.1.4 session. This extends the earlier isolated
parser and word-loop models. It does not join resident boot execution to the
loader; the previous boot model still traps before uploaded code executes.

The source is the captured 1,590-byte loader mapped at `0xFF9000`, SHA-256
`b545d9b2d078662466ab32d9cdeb5b3c38c840135e8aeca09f33760ec66780fa`.
`LOADER_ENTRY_EMULATION.json` records source-range, generator and dependency
hashes, eight sequences and their observations. No original loader bytes are
included in the report. All frame and word data in it are synthetic.

## Entry and dispatch

Actual entry instructions mask interrupts, set A7 to `0xFFA7FE`, initialize
A0 to `0xFFFF9AA0`, set the frame budget at `0xFFFF9A72` to `0xFF`, and branch
to receive `0xFF903A`. The setup store of `0x7060` to absolute-short address
`0xFA4E` (effective `0xFFFFFA4E`) is suppressed before execution. Delay,
watchdog, sender and broadcast-cleanup helpers are guarded synthetic returns;
helper return addresses must match their original BSR call sites. Loader
instruction bytes remain unchanged and its code page is read-only.

The retention probe initializes D7 and sixteen receive bytes to `0xA5`, with
a different incoming stack and frame budget. Actual entry resets the stack
and budget but retains D7 and receive bytes. These probe values are explicit
synthetic inputs, not observations of hardware startup.

Synthetic register events then pass through the actual receive loop and
parser. A valid two-word block reaches `0xFF940E`, where the default model
stops before the first flash command. An optional synthetic readback model
skips all four command stores per word and supplies matching or mismatching
readback at only `0x8000` and `0x8002`. Original word polling, error mapping,
status construction and branches back to receive execute afterward. Native
flash writes remain forbidden by memory protections and write ownership.

The success case constructs logical body `76 00 73`, calls the synthetic
broadcast-cleanup helper and returns to receive with a balanced stack. A bad
block checksum constructs `76 00 77` before word programming. Subtype `0xDB`
constructs `76 00 73` without any modeled word write. This reinforces that a
positive status alone is insufficient programming verification. Subtypes
`0xEE` and `0xFF` stop before erase and finalization entry, respectively.

## Error frames and software reentry

A modeled second-word mismatch follows the real polling/error route and
constructs `76 00 F8`. It leaves synthetic words `12 34 56 79`, with error bit
6 set in D7 and a pending 4-byte program return frame. It bypasses the normal
broadcast-cleanup helper. A later explicit successful block replaces the
synthetic words and clears D7 but leaves that older pending frame on the
stack: delta remains -4 bytes.

Two modeled first-word failures in the same session accumulate stack deltas
-4 and -8. Selecting the original loader entry again restores the stack
pointer and frame budget, while retaining D7, the receive bytes and the
modeled partial write. The original entry does not provide rollback. This
reentry is selected at a receive boundary; the model does not run the sender
timeout which can branch there on hardware. It is not a retry command or a
qualified flash-recovery procedure.

## Bounds and qualification

The experiment uses a fixed sixteen-byte frame and two synthetic words.
These are model boundaries, not physical FIFO capacity or protocol limits.
All physical register reads are intercepted; setup, flash command/reset
stores, actual sender, reset, erase and finalization are trapped or skipped
before execution. Unexpected execution, writes, helper callers and execution
budget exhaustion fail. A trapped command/erase/finalize route is terminal.
No hardware, driver or adapter is opened.

Eleven tests cover native entry, program continuity, checksum and delay
branches, pending error frames, software reentry, source/context ownership,
terminal stops and report preservation. A planner test checks report hashes
and confirms that this evidence cannot enable physical programming or retry.
The file-only planner links the report while physical loader execution,
physical recovery, automatic retry, live writes and readiness remain false.
The Mode `$23` reader and C# AL5 write gates are unchanged.

With the optional Unicorn dependency path and `AL5_CAPTURED_LOADER` pointing
to the existing private loader, run from `Tools/AL5`:

```powershell
python -m unittest test_loader_entry test_offline -q
```

A complete physical upload/program exchange, erase scope and preservation,
independent programmed-image readback and interrupted-flash recovery remain
unqualified. The user has no recoverable spare AL5 available. The installed
truck TCM remains outside experimental qualification; live writes stay disabled.

Validation: the broader AL5 offline suite passed **299 tests with no skips**.
The new CLI reproduced the saved eight-case report byte-for-byte. No adapter,
controller or vehicle access occurred.

[Erase failure and retry stack evidence](ERASE_FAILURE_RETRY_STACKS.md) traces native ID/sector failures and mixed program retries with synthetic flash samples. Successful later calls retain older error frames; physical recovery and live writes remain disabled.
