# AL5 startup RAM provenance and context invocation — offline

Two cases in `STARTUP_CONTEXT_EMULATION.json` pass. They execute the real
startup RAM copy/clear loops with different initial RAM fills, then the context
caller with four preamble helpers bypassed. Both produce identical pending
contexts. Separate CRC preparation and atomic modeled commits also converge.
Physical startup, intervening helper effects and recovery remain unverified.

## Startup copy and clear

The static application entry at `0xC5B7A` establishes A5 as `0xFF8000`, performs
hardware setup, and calls `0xBE4F4` via A0 at `0xC5D36`. The hardware setup is
disassembled only; it is not executed in this harness.

At `0xBE4F4`, helper `0xBE478` copies 312 bytes from ROM
`0xC5E4A–0xC5F81` into RAM `0xFF8008–0xFF813F`. Helper `0xBE4B4` then clears
RAM `0xFF8140–0xFFB7AF`: 13,936 bytes (`0x3670`). The clear uses longword count
`(0x37F0 - 0x140 - 0x40) / 4`. Its `MOVEQ #0xC0` is signed **-64**, not +192.
The observed write coverage matches that exact interval, all bytes become zero,
and the byte immediately after it is unchanged in both cases.

The copied global prefix matches the saved ROM data. Watchdog writes in these
loops hit synthetic memory only; observed values are `0x55`/`0xAA`. The harness
stops when the startup copy/clear routine calls `0x994D0`, before its unrelated
initializers and hardware effects execute.

This clear covers the full 2546-byte stored context at `0xFF8140–0xFF8B31`,
including the previously untouched bytes and the bits retained by later
read-modify-write operations. It also covers external RAM fields read by the
context initializers, including `A5+0x2DA7`.

## Invocation links and omitted effects

Static code at `0x994D0` calls a series of initializers and then directly calls
context routine `0x5B8EC` at `0x99572`. A second call at `0x7911E` follows
preparation `0x5BAB8` in another application path. The meaning and complete
reachability of that second path remain unverified; do not assume every context
invocation is preceded by the cold-start clear.

After executing the clear, the harness explicitly starts at the real caller
`0x5B8EC`. It bypasses the three preamble helpers `0x5B5E4`, `0x5B6E4`, `0x5B7EC`
and the metadata helper at `0x228D8`. Their effects are omitted. The real status
helper and restore/selector execute; the synthetic pending record makes restore
return nonzero, and the caller reaches the previously traced pending defaults.
All twelve remaining helpers execute. The harness stops at `0x5BAA6`, before
status restoration and the caller epilogue.

Intervening startup initializers are not simulated, so this is a linked,
bounded control-flow experiment rather than a complete startup transcript.

## Result and limitations

Both initial RAM fills (`0xA5` and `0x5A`) produce the same context hash after
the real zeroing and modeled caller sequence. This explains the prior 500-byte
sentinel dependency for the tested cold path: untouched bytes and retained bits
now have zero provenance instead of arbitrary sentinel provenance. The earlier
sentinel experiments remain valid demonstrations of what the default helpers
alone do not initialize.

The stored CRC remains zero through the pending defaults. As a separate step,
the existing preparation path computes a matching CRC with ten subsystem calls
bypassed; its real storage entry is trapped. The prepared context is then
committed only in the atomic host storage model. Both prepared hashes match and
the selector reselects their modeled committed contexts. This does not establish
automatic startup persistence or physical recovery.

`STARTUP_CONTEXT_STATIC_EVIDENCE.json` preserves bounded startup/clear/caller
disassembly with exact source hashes. No raw ROM table, calibration or context
payload is exported. Reproduce with `Tools/AL5/emulate_startup_context.py --low
... --high ... --output ...` using the existing WSL Unicorn environment.

The file-only report hash-links this evidence while keeping complete startup,
physical persistence and recovery false. It emits zero packets and the working
Mode 0x23 reader is unchanged.

Next trace the omitted context preamble and metadata effects, and distinguish
cold invocation from the other caller path. Intervening startup initializers,
physical flash geometry and programming transport remain unresolved. No live
destructive command, experimental service or loader operation is enabled.
