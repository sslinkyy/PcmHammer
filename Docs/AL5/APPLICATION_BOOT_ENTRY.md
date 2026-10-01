# Application boot-request route — offline evidence

The saved application service table links service 0x34 to the handler at
0xBE6D0. Twelve isolated firmware experiments now exercise its guards, the
reset-marker branch and boot initializer. This is a traced candidate transition,
not a verified physical application-to-boot session. No vehicle commands were
sent and no application/boot code was run on hardware.

## Service attribution and handler behavior

At 0x99A70, 22 six-byte entries pair a service byte with a descriptor pointer.
The 0x34 entry at 0x99AB8 points to 0x99A30, whose bytes are
`90 00 00 0B E6 D0`: flags 0x9000 and handler pointer 0xBE6D0.
The table lookup at 0xA4BDA uses 0xBA824; subsequent code forwards the
descriptor to 0xB1970. Descriptor flags, scheduling and authorization in that
downstream path remain incompletely decoded. Application startup at 0xC5B7A
sets A5 to 0xFF8000, supporting the RAM-base interpretation used here.

With a synthetic internal request buffer and injected state, the extracted
handler establishes these exact guards and effects:

- The buffer's first byte must be four; otherwise it calls the negative helper
  with argument 0x12. This is an internal-buffer length, not independently
  verified complete wire framing.
- Bit five at A5+0x1DBE must be clear; otherwise the negative argument is 0x33.
  Its full security-state meaning and the route that sets/clears it are open.
- The low word returned by helper 0xBD89C must be at most 0x0190, and the word
  at A5+0x1E6C must be at most 0x0640. Above-threshold values reject with 0x22;
  boundary values pass. Units and upstream physical conditions are unassigned.
- The accepted path copies buffer byte five to A5+0x223C, prepares state around
  A5+0xF36/0xF56, calls 0xA9D8C with argument 0x55, then calls 0x5BAB8.
  Those two helpers are stubbed in the experiment; no application wire response
  or cleanup effect is claimed from their names or arguments.
- The real helper at 0x21D08 sets the interrupt mask to seven. The handler then
  writes 0xBFC1 to A5+0 and spins at 0xBE78C. The spin is trapped. Interrupt
  masking alone is not a reset command; physical watchdog/reset behavior has
  not been emulated or verified.

## Marker route and response ambiguity

The reset code saves the RAM marker before RAM tests and restores it afterward
(0x4E6 and 0x7C2). After boot integrity/reset-status gates, the branch at 0x8B2
maps 0xBFC1 to 0xB094 and enters the boot continuation at 0x97C. The emulator
starts at this selected branch and traps the continuation, then explicitly
invokes the boot initializer at 0x3B7C with retained synthetic RAM. Hardware
reset, integrity checks, reset-status gates and the intervening boot startup
are not executed in this linked experiment. Boot startup at 0xAB4 also has a
flag-dependent call to the initializer; that flag's initialization is open.

The initializer clears the upload-arming byte at 0xFF8185 and neighboring state,
executes the 0x2E30 helper with synthetic register writes 0x18/0x02 at
0xFFE800/0xFFE801, and, for marker 0xB094, produces logical response
`6C F0 18 74 44` through a stubbed send helper. Hardware meaning and timing of
those register writes remain unassigned. A previously set arming flag is also
cleared. This response therefore cannot, by itself, prove upload arming.

The separately verified boot dispatcher can also respond with service
0x74/0x44 while setting upload arming. See `BOOT_SESSION.md`. These paths have
different state effects; a future session implementation needs state and
provenance checks rather than treating that response suffix as a universal
permission to upload.

The reset marker 0xD0C2 follows a different static route through application
integrity checks and an application entry pointer at 0x20408. It must not be
interchanged with 0xBFC1 as a generic boot-entry operation. Other marker routes
remain documented as firmware branches, not a recovery procedure.

## Validation and remaining work

`Tools/AL5/emulate_application_boot.py` requires both known firmware hashes,
loads only selected executable ranges, protects ROM against writes and fails
on execution outside permitted ranges/stubs. Reset loops, boot continuation and
application resumption are trapped. Synthetic MMIO writes are recorded; no
hardware is connected. Instruction/time-limit exhaustion without an expected
return or trap fails the run. The flash primitive is absent.

`APPLICATION_BOOT_EMULATION.json` includes code hashes, service bindings,
per-case inputs/assertions and observations. `APPLICATION_BOOT_STATIC_EVIDENCE.json`
contains the bounded supporting disassembly. Run the harness with the existing
WSL Python/Unicorn runtime and explicit `--low`, `--high`, `--output` paths.
The planner links the report by hash while retaining false live authorization
and application-entry verification; all packet lists remain empty.

Next resolve 0xB1970 scheduling/descriptor flags, the guard-bit lifecycle and
application response helper, then boot initialization gates and reset behavior.
Loader ABI, exact erase geometry, collateral preservation, flash wire protocol,
verification and recovery remain unresolved. The direct reader and live-write
block are unchanged.
