# AL5 boot receive, dispatch and RAM transfer in one offline session

`emulate_boot_receive_session.py` extends the previous isolated ISR and boot
service models with original saved code running in one Unicorn 2.1.4 session.
Synthetic FIFO events drive the real receive ISR into resident dispatch or RAM
transfer. Native handler returns, receive-buffer cleanup, register restore and
stack restore run through the instruction before RTE. Synthetic RAM persists
between explicit interrupt entries; no transfer routine resets the processing
flag or rebuilds a staged buffer behind the caller's back.

This closes a software continuity gap, not the physical recovery gate. Actual
interrupt entry, exception frames and RTE are omitted. Sender/FIFO/flush helpers
return through guarded synthetic callbacks; original call sites are checked.
Watchdog stores are suppressed before execution. Flash code, hardware startup,
transport and uploaded code never execute. The only upload experiment accepts
four synthetic bytes at `0xFF9000`; it does not accept a real controller image
or captured programming loader.

## Observations from eight modeled sequences

- A completed service `0x34` frame enters dispatcher `0x341C`, constructs
  logical response `6D F0 18 74 44`, and leaves upload arming set after native
  ISR cleanup. The same session then receives service `0x36`, enters `0x3074`,
  copies four synthetic bytes, constructs `6C F0 18 76 00 73`, and returns with
  a balanced stack, empty staged buffer and cleared processing flag.
- Without arming, the transfer still copies bytes into synthetic RAM before
  the later authorization rejection `6C F0 18 7F 36 00 00 04 FF 90 22`.
  Arming is therefore not a guard against all RAM writes on this boot path.
  This is distinct from the application's separately traced lock-bit guard.
- A checksum-failed transfer leaves the supplied `bad!` bytes in synthetic
  RAM, constructs status `0x77`, and retains arming. A later explicit transfer
  replaces those bytes with `12 34 56 78` and constructs status `0x73`.
  This is RAM-transfer retry evidence, not rollback or flash recovery.
- A duplicate valid transfer succeeds again in the modeled context. A later
  wrong-length arm request produces a negative reply without clearing the
  prior arming flag. A wrong destination produces no reply and does not arm.
- A partial service `0x34` frame survives one native ISR epilogue in synthetic
  RAM; a second explicit interrupt entry finishes and dispatches it. This
  does not establish real FIFO interrupt thresholds or physical frame timing.
- With subtype `0x80`, original code reaches a call to uploaded RAM. The model
  traps before `0xFF9000` executes and makes the session terminal. Its pending
  stack delta is -72 bytes; this boundary cannot be resumed as a completed ISR.

All ordinary handler-return scenarios use no synthetic cleanup between
steps. Every ordinary ISR return restores the original stack; the
partial-frame case deliberately retains the staged bytes until completion.
Source is the pinned saved LOW editor image, SHA-256
`cf5dd139e52ba5925fc95f166627a9a7abcac1374ded8cb738df8297b961a3f6`.
It is not a current physical controller backup. Source ranges and generator/
dependency hashes are recorded in `BOOT_RECEIVE_SESSION_EMULATION.json`.
The report contains observations and synthetic test bytes, not original
firmware or a replayable physical programming capture.

The file-only write planner links the report and implementation hashes under
`calibration_recovery_assessment`. It explicitly leaves physical interrupt
delivery, continuous reset-to-upload execution, physical recovery, automatic
retry, live writes and flash readiness false. No C# write gate or Mode `$23`
reader changes are included.

## Verification and remaining work

Eleven focused tests check native same-session behavior, failure/retry memory
state, partial-frame persistence, terminal upload trapping, source/context
bounds, callback callers, write ownership and output preservation. A planner
test checks evidence hashes and verifies that physical qualification remains
blocked. Focused tests, with the existing optional Unicorn path and pinned
`AL5_LOW_DUMP` set:

```powershell
python -m unittest test_boot_receive_session test_offline -q
```

Physical VPW startup, FIFO/IRQ behavior, loader execution, erase preservation,
programmed-image readback and interrupted-flash recovery remain unqualified.
The user currently has no recoverable spare AL5; the installed truck TCM is
not authorized for experimental qualification. Live writes remain disabled.

Validation: the combined offline suite passed **287 tests with no skips**
using pinned native inputs and Unicorn 2.1.4. Staged changes passed
`git diff --cached --check`. No adapter or vehicle was accessed.

[Loader entry and programming continuity](LOADER_ENTRY_PROGRAM_PATH.md) joins actual loader entry, receive/parser and bounded synthetic word programming. Nonlocal errors retain pending call frames; software reentry resets the stack without rollback. Live writes and recovery qualification remain disabled.
