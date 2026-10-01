# AL5 offline programming state machine

This is an evidence-based reconstruction scaffold. Unknown packet formats are
deliberately absent. No live erase, program, key, or loader upload was performed.
The existing PCM writer cannot be assumed to apply to VPW module `0x18`.

## States and transitions

1. **Identify → Context checked. Confirmed read-only requests; raw semantics
   partly established.** Mode `0x3C` identity queries at VPW 1X work. OS block
   `0x0A` starts with `00 E7 B0 ED`, with trailing data; block `0x08` contains
   hardware 15183963, not necessarily the PCM calibration meaning. Do not use
   the probe's generic trailing-UInt32 helpers as AL5 context proof.
2. **Context checked → Current backup read. Confirmed.** Mode `0x23` request
   `6D 18 F0 23 <address24 BE> 01`; response
   `6C F0 18 63 <address-low16 BE> <four bytes>`. Preserve the working high-address
   preflight and anchor/BE16 checks. Capture exactly 57,304 bytes; require the
   caller's expected backup SHA256 in the offline plan.
3. **Backup read → Candidate checked. Confirmed offline for the current
   family.** Length, cal ID, gear signature, D5196 header, native CRC16 and sum
   compensation, source hash, and explicit edit allowlist are checked. The plan's
   OS/controller values are caller-supplied context, not live identity proof.
4. **Candidate checked → Programming session/security. Unknown requirement.**
   Seed read `6C 18 F0 27 01` is confirmed. The pair `9CE5 → BC08` matches
   an algorithm-50 hypothesis, but the saved selector-zero application uses
   fixed seed/key words. Twenty offline descriptor/security cases now exercise
   selected guard clearing and failure-counter transitions; the separate dynamic
   transform differs for that seed. See `APPLICATION_AUTHORIZATION.md`. Live
   key transmission, session entry, expiry, lockout duration and programming
   authorization remain unverified. They remain unknown live transitions.
5. **Session → Loader ready. Partially reconstructed offline.** Application
   preparation reaches a persistent flash-storage update caller referencing
   0x4000/0x6000; boot entry is not established to be free of storage side effects.
   Thirteen isolated receive/preparation cases intercept that caller before
   execution; see `RECEIVE_PREPARATION.md`. The boot
   firmware RAM-transfer handler and its bounds/checksum/status/execute behavior
   have been exercised in an isolated emulator; see `BOOT_RAM_TRANSFER.md`.
   The boot dispatcher now sets upload arming in 25 stateful emulator cases,
   including arming followed by transfer; see `BOOT_SESSION.md`. The real
   negative-response helper is exercised, but transmit/FIFO/configuration
   helpers and receive cleanup remain modeled.
   A service-table link and extracted application handler now trace a candidate
   boot-request marker route; twelve emulator cases exercise guards and selected
   marker/initializer steps. See `APPLICATION_BOOT_ENTRY.md`. The startup
   0x74/0x44 response leaves upload arming clear, unlike the boot dispatcher
   response. Physical reset, scheduling/security and full application entry,
   whether flashing requires this loader path, the kernel ABI and safe recovery
   remain unproven. No live upload
   is enabled.
6. **Loader ready → Erased. Partially traced offline; destructive.** A resident
   boot routine has an internal erase selector table and word-program loop;
   see `RESIDENT_FLASH_PRIMITIVE.md`. The CAN-style internal caller is exercised
   with all flash calls trapped; see `RESIDENT_COMMAND_DISPATCH.md`. Its physical
   wire/session path and relationship to VPW programming are still unknown.
   Adjacent selector starts suggest an erase span extending beyond calibration,
   which requires a separate preservation policy. Exact flash geometry, erase scope,
   service/subfunction bytes, timing, status and interrupted-erase recovery are
   unproven. The calibration payload bounds are not erase-sector bounds.
7. **Erased → Programmed. Internal primitive traced; wire path unknown/destructive.**
   The internal byte count and word stride are not a transport block-size proof.
   Block size, framing, address
   width, sequence counters, packet checksums, acknowledgments, retry idempotency
   and transfer exit are unproven. No generic GM/PCM packet has been substituted.
8. **Programmed → Verified. Strongly inferred requirement; programming-session
   readback behavior unknown.** Exact readback/hash comparison is required.
   Application-mode direct reads work, but when they become available after
   programming is unknown.
9. **Verified → Reset/recovery. Unknown.** Reset command, safe ordering, boot
   behavior and recovery from loss of power/connection have not been established.

## Existing artifacts inspected

The local EFILive installation provides AL5_R/F/L/W `.obj` and `.bix` files and
`AL5.pmm`. `OFFLINE_EVIDENCE.json` records each size, SHA256, prefix and short
printable strings. Objects report version `08.05.89` / date `20260726`. Their
opaque container payloads have not been decoded into packet/state definitions.
Names alone do not prove their role or packet formats. No proprietary object or
firmware BIN is committed or executed.

PCM Hammer's existing `WriteManager` validates a PCM image, establishes hardware
support/security, and delegates to `CKernelWriter`. The AL5 segment has a
separate unconditional rejection before vehicle queries, including forced PCM
types. The file-only Python planner has no transport dependency or execute flag.

## Dry-run contract

`Tools/AL5/write_plan.py` accepts current/candidate files plus explicit current
SHA256, controller and OS context. It reports native checksum validity, input
errors, absolute diff ranges and readiness blockers. The initial policy permits
only the supplied minimal OEM-stock 1→2 target words and a valid checksum field.
It does not permit arbitrary values at those addresses, D5197 changes at
`0x10A24` (now marker-identified), changes to other controls, or an implicit
PPEI-to-stock rebase. Identifying the enum does not expand the write allowlist.

`ready_to_flash` and `live_write_enabled` are always false. `would_send`,
`erase_packets`, and `program_packets` are always empty. Erase scope and program
block size are null. Exit code 2 means readiness blocked, even if all file checks
pass. Printing fabricated destructive packets would misrepresent the evidence.

The report also links the boot-session emulator evidence by SHA256. Passing
offline boot cases does not authorize a live session or verify application
entry; both remain explicitly false. No executable packet plan is generated.

A separate hash-linked preparation assessment records the intercepted storage
call and candidate bank starts. Current storage backup and geometry remain
unverified; a distinct blocker prevents treating calibration-only preservation
as sufficient. No preparation storage implementation was executed.

The report includes a hash-linked preservation assessment from the static
resident inventory. The inferred 41,000 extra bytes and candidate intervals
remain explicitly unverified; no current collateral backup is supplied or
validated by this calibration-only tool. Saved editor dumps cannot substitute
for a current physical preservation backup. The assessment never populates
`erase_scope` or enables any packet generation.

## Next offline work

Recover the local EFILive container format and state definitions, or obtain an
existing AL5 programming capture from a separate documented source. Trace the
firmware programming handlers and native flash geometry offline. Establish exact
packet bytes and acknowledgments before adding a simulated transport. Add fault
injection for timeouts, duplicate blocks and interrupted programming. Keep live
execution disabled until checksum corpus, session, erase, programming, readback
and recovery evidence are all independently adequate.
