# Captured loader parser: bounded fault observations

[Fourteen emulator cases](LOADER_PARSER_EMULATION.json) execute the saved loader
from `0xFF90BE` using synthetic receive-buffer contents. The private loader must
match the previously captured SHA256. The report also hashes the generator.
No live adapter, packet replay or loader upload is involved.

Watchdog, status builder and delay/receive cleanup calls use isolated RTS stubs.
Execution stops before the first flash command at `0xFF940E`, reset writes at
`0xFF9452`, and erase/finalize/other-service branches. Only stack stores and three
identified RAM state bytes are allowed; other stores raise an error. Reads past
the supplied frame stop execution. The full physical receive loop, timeouts,
flash polling and later word iterations are not modeled. Stops record attempted
operations, not physical outcomes.

## Observations

- A valid two-byte payload passes the sum check and reaches the flash-command
  trap. This establishes parser flow, not successful programming.
- Zero count enters the sum loop and attempts a read beyond the supplied frame.
  Declared count four with two payload bytes also reaches the frame-read trap.
- Count one passes the sum guard and reaches word programming. Its source word
  spans the payload byte and high checksum byte.
- Odd destination `0x8001`, below-calibration `0x4000`, and zero destination
  reach the flash-command trap. `0xFFFFD` also reaches it; `0xFFFFE` sets error
  bit 7 and reaches the reset trap. M68020 emulation does not establish the
  physical CPU's misalignment behavior.
- Bad sum supplies status argument `0x77`. Subtype `0xDB` supplies `0x73` without
  entering word programming. The status builder is stubbed; these are arguments,
  not captured wire acknowledgments.
- Wrong destination returns to the receive boundary. Erase and finalize subtypes
  stop before their routines execute.

## Reproduction and next work

Run `Tools/AL5/emulate_loader_parser.py --loader <private-captured-loader>
--output <report>` in the existing WSL Python environment with Unicorn M68020.
It exports metadata and observations, not the private loader or packets.

The planner hash-links the report but retains false readiness and physical
programming verification, null erase scope and empty packet lists. Future host
validation must reject zero/odd lengths, unaligned or out-of-scope addresses,
and frame/count mismatches before constructing a transaction. Do not rely on
this loader to impose those limits.

Next bound later word-loop count/address behavior with a flash model and examine
failure propagation and response construction. Physical identity, collateral
preservation, complete session evidence and demonstrated recovery remain
separate blockers. The working Mode 0x23 reader is unchanged.
