# Captured word loop and response bodies: synthetic flash model

[Eight bounded cases](LOADER_PROGRAM_EMULATION.json) extend the parser work into
the captured word loop, polling, error mapping and response-body construction.
Source and generator hashes accompany the report. This is file-only M68020
emulation; no adapter or controller is used.

## Model boundary

At `0xFF940E`, the host model skips all four command/data stores and sets synthetic
readback to match the source word or differ permanently. Actual instructions
then execute the readback comparisons, polling counter, byte-count decrement
and destination advance. At `0xFF9452` both reset stores are skipped. Watchdog,
delay, cleanup and the hardware sender use return stubs. A store allowlist
rejects any other instruction store outside the stack and known RAM bytes.
The synthetic flash state is not a NOR command/state/timing model.

The real status builder writes service `0x76`, zero and a status into RAM.
The sender stub records these fields and verifies length three. They are
constructed response bodies, not wire acknowledgments or proven physical
transport behavior. Source reads beyond the supplied frame stop execution;
word and instruction budgets bound all runs.

## Results and implications

- Two synthetic successful words produce status `0x73` after counts four and two.
- A permanent mismatch on word one produces `0xF8` after 12,290 readback checks.
  Failure on word two produces `0xF8` after 12,291 total checks, including the
  first word's success. Both failure paths exit to the receive boundary without
  adding `0x73`. Poll counts do not establish physical elapsed time.
- Start `0xFFFFE` produces `0x74` without a modeled write. Start `0xFFFFC` with
  four bytes models one successful word, then produces `0x74`. Thus this bound
  check can report an error after a partial update; there is no demonstrated
  rollback or complete-range preflight in this routine.
- Odd count one models a word containing the payload byte and high checksum
  byte, wraps the count to 65,535 and attempts another source word beyond the
  frame. No success response occurs before the read trap.
- A separate direct-entry case bypasses the parser with count zero. It models
  two supplied words with counts zero then 65,534, reaches count 65,532 and
  stops at the source-read trap. It is not evidence that the parser accepts
  an empty block; the preceding parser report already traps that case.
- Two words at `0x4000` produce `0x73` under synthetic matching readback. The
  routine's lack of a calibration lower bound remains a host-validation concern.

The partial-update cases require exact-range preflight and independent readback
in a future implementation. A failure acknowledgment cannot establish that no
data changed. Do not retry blindly or treat the synthetic state as a backup.

## Reproduction and remaining work

Run `Tools/AL5/emulate_loader_program.py --loader <private-captured-loader>
--output <report>` in the existing WSL Unicorn environment. Output contains
metadata only. The planner hash-links it while keeping physical programming and
wire verification false, readiness false, erase scope null and packet lists empty.

`LOADER_SENDER_EMULATION.md` now bounds sender/header construction and selected
exit paths with MMIO intercepted; physical framing/checksum remain unverified.
Next bound the complete receive/session loop. Add delayed readback and interrupted-word cases
when a defensible flash model is available. Physical chip mapping, collateral
preservation and demonstrated recovery remain unresolved. The existing C#
direct reader and unconditional AL5 write rejection are unchanged.
