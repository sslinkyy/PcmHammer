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

The preparation assessment now also hash-links the 15-case storage selector and
restore emulator and the metadata-only saved-bank inventory. Invalid headers
can enter repair before a cached/committed record is returned; restore itself
does not check context CRC. See `STORAGE_SELECTION.md`. All flash calls remain
trapped, interrupted-update recovery remains false, and the saved editor image
does not establish current physical preservation.

Three downstream CRC-validation and eighteen atomic update/interruption cases
now pass (`STORAGE_RECOVERY.md`). The application caller rejects bad restored
CRC with marker `0x8C9B`; early update interruptions reach repair despite an old
committed record. Host-modeled successful operations do not validate physical
recovery, error statuses or partial writes. The planner links this evidence by
hash while keeping all destructive scope/packets disabled.

Nineteen repair/error cases subsequently exercise rebuilding both banks as
pending/inactive records and bounded program/copy failure marker `0x6124`.
The model does not preserve either context through repair, including after
early update interruptions. See `STORAGE_REPAIR.md`. Hash-linked repair evidence
keeps physical recovery and surviving-commit safety false; it does not establish
a programming transport or authorize any live operation.

Six bounded pending-initialization cases execute real default helpers without
storage writes. They rebuild 2020 context bytes before the next initializer,
leaving 526 bytes, including the CRC word, untouched in the sentinel model. See
`PENDING_INITIALIZATION.md`. The planner links this partial evidence while
keeping complete context initialization and physical recovery unverified.

Four subsequent cases execute all twelve remaining pending helpers and link
separate boot-preparation CRC generation to atomic modeled persistence.
Correct CRCs and modeled commits coexist with 500 sentinel-dependent context
bytes, so they cannot waive initialization or preservation requirements. See
`PENDING_HELPERS.md`. Startup RAM provenance and physical persistence remain
unverified; the file-only plan continues to emit zero packets.

Two subsequent startup-clear cases reproduce the signed `MOVEQ` clear bounds
and identical cold pending contexts from different RAM fills. Static startup
code directly calls the context routine after intervening initializers. See
`STARTUP_CONTEXT.md`. Those initializers and four context preamble helpers are
omitted, so full startup, physical persistence and recovery remain false.

The report includes a hash-linked preservation assessment from the static
resident inventory. The inferred 41,000 extra bytes and candidate intervals
remain explicitly unverified; no current collateral backup is supplied or
validated by this calibration-only tool. Saved editor dumps cannot substitute
for a current physical preservation backup. The assessment never populates
`erase_scope` or enables any packet generation.

## Next offline work

The context preamble now executes with atomic host models, including nine
small-record writes and a bounded alternate invocation. See `CONTEXT_PREAMBLE.md`.
Twenty-eight subsequent small-record interruption/failure cases expose a caller
that continues to a commit marker after a synthetic no-write payload failure;
the reader accepts the erased payload. See `SMALL_RECORD_FAILURES.md`. Physical
failure semantics and full initializer reaction remain unverified. These reports
are hash-linked by the planner and do not weaken any write gate.

Recover the local EFILive container format and state definitions, or obtain an
existing AL5 programming capture from a separate documented source. Trace the
firmware programming handlers and native flash geometry offline. Establish exact
packet bytes and acknowledgments before adding a simulated transport. Add fault
injection for timeouts, duplicate blocks and interrupted programming. Keep live
execution disabled until checksum corpus, session, erase, programming, readback
and recovery evidence are all independently adequate.

Five existing AL5 write trace containers and one read comparison have now been
inventoried offline. Common bounded zlib/byte-transform probes did not decode
them; that historical result is preserved in `EFILIVE_TRACES.md`. Subsequent
static stream analysis recovers an additive/rotate/XOR transform and decodes all
17 saved AL5 containers with complete record framing. Four write traces contain
Mode 0x34/0x36 candidates, but erase/program semantics and completion remain
unknown. See `TRACE_DECODE.md`. The planner hash-links this progress without
generating packets. Prioritize captured payload/response comparison with the
offline loader before creating any new programming capture.
The captured comparison now matches all 16 Mode 0x36 candidates to the saved
boot handler's RAM-transfer contract. Four write traces contain the same 1590-byte
execute-request loader at 0xFF9000; only its bounded entry has been statically
inspected. See `CAPTURED_RAM_TRANSFER.md`. Calibration programming semantics,
physical execution and recovery are still unverified, and no live builder exists.
The captured loader's static dispatcher now maps subtype 0xEE to erase calls at
0x8000/0x10000, subtype 0x00 to word programming, and subtype 0xFF to a sum check
and marker write. No corresponding destructive requests are observed in the
supported host wrappers of the saved write traces. See `CAPTURED_LOADER_DISPATCH.md`.
The ID comparison does not verify physical geometry, and capture completeness,
flash completion and recovery remain unproven.

## Staged route to live testing

`OFFLINE_PRESERVATION_MANIFEST.md` now pins baseline/candidate hashes and reports
missing conditional collateral and persistent-bank files. Complete file coverage
does not verify current backups or preservation. The finalization marker lies
inside collateral and has unresolved permitted-change handling; executable erase
scope and packet lists remain empty.

`TRACE_WRAPPER_AUDIT.md` now accounts for all 709 binary records in the five
saved W containers, including broader module/global/tester address variants.
No unsupported binary wrapper or framed destructive request/Mode `76` response
is observed. Complete physical exchange and flash outcome remain unverified;
the existing files do not close the acknowledgment replay's evidence gap.

`OFFLINE_ACKNOWLEDGMENT_REPLAY.md` now checks supplied block-event ordering,
headers/statuses, exact block readbacks and a complete final snapshot. A success
status cannot advance the model without readback. Identical statuses carry no
verified block sequence identity; stale-response correlation remains unresolved.
Session entry, erase, exit and physical transport are not implemented by this model.

`OFFLINE_HOST_VALIDATION.md` now supplies complete-frame, even-length, alignment
and calibration-range checks, plus whole-batch preflight and conservative fault
outcomes on logical RAM. Malformed later blocks prevent all edits; duplicate or
overlapping blocks cannot trigger automatic retry. Physical block size, transport,
flash behavior and acknowledgments remain unverified, with no executable packets.

Eight stale-buffer cases now show synthetic short frames reusing old service or
subtype bytes to reach erase, finalize, block-parser and exit routes. A frame
rejected by completion flags can leave bytes for a later short frame. See
`LOADER_STALE_BUFFER_EMULATION.md`. The physical FIFO's short-frame acceptance,
RAM aliasing and receive capacity remain unverified. Host length validation is
required; these routes do not authorize a live transaction.

Eleven receive-loop cases establish seeded timeout branches, flag-mask rejection,
absence of an observed pre-dispatch length guard, and priority-dependent budget
refresh. See `LOADER_RECEIVE_EMULATION.md`. The explicit write trap is a model
limit, not a physical RAM boundary. FIFO semantics and elapsed time remain
unverified; all destructive paths and MMIO are trapped.

Ten sender/exit cases now bound software header/status construction and synthetic
FIFO busy timeout. Both tested finalize tails reach the reset trap after status
transmission; these tails bypass verification/programming. See
`LOADER_SENDER_EMULATION.md`. Physical framing, CRC/checksum, reset and recovery
remain unverified; this progress does not open a live-write gate.

Eight word-loop emulator cases now establish bounded counter wrap, partial-update
error paths and response-body construction under synthetic readback. See
`LOADER_PROGRAM_EMULATION.md`. These do not verify flash semantics, elapsed time
or wire acknowledgments; command/reset stores are skipped and the sender stubbed.

Fourteen bounded captured-parser emulator cases expose zero-count overreads,
odd source words spanning checksum bytes, and acceptance of unaligned or
below-calibration destinations before the first flash-command trap. See
`LOADER_PARSER_EMULATION.md`. Flash/MMIO calls remain trapped. These findings
establish host-validation requirements, not physical programming or wire responses.

The saved finalize pointers resolve to the exact 57,304-byte calibration range.
The loader checks its BE16 sum but does not recompute the native CRC. Published
AMD ID/sector tables corroborate a conditional 98,304-byte erase span with
41,000 bytes outside calibration. See `LOADER_GEOMETRY_FINALIZATION.md` for the
source, address coordinates and limits. Physical chip identity and current
collateral backup remain unverified; this evidence does not open any write gate.

There is a development path to writing, but no executable AL5 live writer yet.
`FIFO_CANDIDATE_COMPARISON.md` records an unresolved receive-completion ordering
comparison with a manufacturer candidate. Passing synthetic receive cases do
not establish that candidate's physical FIFO contract or identify the fitted chip.
Checksum recovery and stock decoding are sufficient to validate a candidate
offline; they do not supply a programming protocol or safe erase scope.

1. **Read-only live baseline.** Repeat the already proven identity and calibration
   read using the existing direct reader. Save the exact current BIN and hash;
   compare repeated reads. A stock CTZ-derived reference remains useful for
   candidate construction, but it does not replace the current physical backup.
   Do not expand address probing or send session/key/reset commands merely to
   obtain more evidence. Reading alone is the presently established live stage.
2. **Offline protocol closure.** Recover exact session, loader, erase/program,
   acknowledgment, transfer exit and readback behavior from existing local
   artifacts or an already recorded, documented AL5 programming capture. Trace
   physical geometry and every collateral region, including persistent records.
   Do not create a new destructive capture using the only TCM for research.
3. **Transport simulation.** Implement replay against evidence-derived packets,
   with no vehicle adapter attached. Check address bounds, duplicate blocks,
   retries, timeouts and interruptions. The existing file plan stays blocked
   until independently supported protocol and preservation gates are satisfied.
4. **Recoverable bench stage.** Use a compatible spare TCM with a documented
   bench setup and demonstrated recovery, or first independently establish
   recovery for the current unit. Obtain current backups for all affected regions
   using a verified method. A calibration-only backup is insufficient when erase
   geometry reaches outside calibration. The first destructive trial should
   restore the unchanged baseline and verify exact affected-region readback;
   calibration changes come after that succeeds.
5. **Vehicle calibration stage.** After bench writing and recovery are established,
   bind the approved candidate to the current backup, validate its checksum and
   allowlist, program through the verified path and check exact readback before
   normal vehicle use. Evaluate the minimal calibration only after write integrity
   and preserved collateral have been verified.

These are development gates, not authorization for live destructive operations.
No packets, new transport services or hardware actions are enabled by this document.
The user currently has one installed TCM; work can continue offline without it.

## Offline EFILive session and VM object analysis - 2026-10-11

The saved write-session chronology now retains exact record identity and all
preceding Mode 34 / 74 44 candidates. Four of five saved W traces show two
requests/responses before one subtype-80 upload; these bytes do not prove
upload arming. See [session chronology](SESSION_CHRONOLOGY.md).

Static Ghidra analysis of the installed EFILive_VM.dll recovered the object
section load boundary and its unresolved host callbacks. The new file-only
inspector validates all four installed AL5 object layouts without decoding or
executing their contents. See [VM object loading](EFILIVE_VM_OBJECT_LOADING.md).
The planner hash-links both reports; live writing, physical transport,
preservation and recovery remain unverified, and packet lists remain empty.

Host callbacks: [static callback tracing and supplied-buffer CRC inspection](EFILIVE_HOST_CALLBACKS.md). The transform reaches Windows IPC; its recipient is statically linked, and captured-reply reconstruction is available. Device-independent transformation remains unresolved. Live writes remain disabled.

[Captured object transform replay](EFILIVE_HOST_IPC.md): all five saved W traces match the installed object input and validator CRC. Device-independent transformation and programming/recovery remain unverified; live writes remain disabled.

[Reconstructed VM programming and recovery flow](VM_PROGRAMMING_FLOW.md): static instruction listing, broader programming bounds, attempt-counter branches, and separate error/stop paths. Full VM semantics and physical recovery remain unverified; the planner keeps live writes disabled.
