# Boot session and loader arming — offline firmware sequences

The extracted boot dispatcher at 0x341C–0x39A9 now runs in an isolated M68020
emulator together with the previously reconstructed RAM-transfer handler.
The flag at 0xFF8185 is set by actual dispatcher instructions, then retained
for subsequent transfer calls; it is not injected as an armed test fixture.
Twenty-five cases pass in `BOOT_SESSION_EMULATION.json`.

## Established within the extracted boot path

- A four-byte staged service 0x34 request, addressed to 0x18 or 0xFE with the
  tested header/status flags, sets upload arming and produces a five-byte
  logical response ending in 0x74 0x44. No preceding seed/key operation is
  needed within this isolated dispatcher. This does not prove that the live
  application can enter boot without security.
- Wrong length produces a negative response; wrong destination, incompatible
  priority/status flags and response-service input are ignored in the tested
  cases. A failed arming request does not clear an already set arming flag.
- Boot service 0x27/subfunction one returns seed zero. Subfunction two with the
  tested seven-byte input produces a rejection. This boot behavior differs
  from the observed application seed 0x9CE5 and must not replace its security
  model.
- Arming followed by RAM transfer copies the payload and returns success.
  Repeated identical transfers and a checksum-failure/valid-retry sequence
  behave as recorded when the receive caller's cleanup is modeled.
- Bad checksum and unarmed transfers still copy the payload before rejection.
  Arming remains set after a bad checksum. These results cannot justify flash
  retries: only the RAM transfer path was exercised.
- The real negative-response helper at 0x2FE0 echoes up to six request bytes
  starting at the service before appending a reason byte. An unarmed transfer
  therefore yields a longer response than a fixed service/reason pair. Response
  parsers must not assume that the reason is at a fixed offset for every input.
- Global 0xA0 sets a separate flag at 0xFF8183 and responds. The tested global
  0xA1 requires that flag, sets 0xFF8184, and calls the external helper at
  0x2E30 with bytes 10 03. The helper is stubbed, so its effect is unknown.
  Neither operation establishes a reset/recovery procedure or upload arming.

All request and response bytes in the committed report are synthetic emulator
inputs and captured send-helper buffers. They exclude physical VPW CRC and
actual transmission behavior. They are not a production command builder.

## Isolation and modeling limits

`emulate_boot_session.py` requires the known low-dump size and SHA256. It loads
only the dispatcher, RAM handler and negative-response helper as executable
firmware. ROM pages are read-only. Flash primitive code is absent. Execution
outside these ranges and four explicit stubs fails; uploaded-code execution is
trapped before its first instruction. An exhausted FIFO, instruction/time limit
without return, or unexpected response length fails the run.

Send, FIFO, flush and the 0x2E30 helper are abstractions. After a transfer, the
receive ISR clears 0xFF8182 at 0x3ACA; the harness models that caller cleanup
before the next transfer. Without it a repeated direct handler invocation would
return after its first FIFO event. The full ISR, hardware status/CRC, watchdog
timing, peripheral configuration and event interleaving are not emulated.
Synthetic RAM persists between steps, but no wall-clock session expiry,
power-cycle recovery, packet loss or real receive timing is established.

## Reproduce and remaining work

Run `Tools/AL5/emulate_boot_session.py --low <existing low editor dump> --output
<report.json>` with the existing Python/Unicorn M68020 runtime in WSL. The
bounded supporting disassembly is in `BOOT_SESSION_STATIC_EVIDENCE.json`.
The dry-run planner includes a hash-linked assessment of this report while
keeping application-entry verification and live-session authorization false.
Readiness is false, erase/program scope remains unresolved, and all packet
lists remain empty.

Next trace entry from the current application into this boot path, the external
0x2E30 helper and flag initialization/lifetime. Exact flash geometry, loader ABI,
programming wire path, preservation and recovery remain open. No live session,
upload, erase or program operation was performed.
