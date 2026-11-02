# Offline VPW runtime, entry, watchdog and RAM checks

## Implemented source and evidence boundary

entry.S masks interrupts with SR 0x2700, sets SP to 0xFFA7FE, calls initialization, then polls al5_ro_step. runtime.c owns explicit scratch RAM, receives bounded frames, validates the experimental envelope, invokes read_core.c, and emits bounded replies. No firmware erase/program/reset/security routine is linked and no adapter/upload route references this build. Live upload, execution and writes remain disabled.

The captured SPS loader is evidence for the candidate 24-bit command/status register 0xFFE800, data register 0xFFE801, watchdog word register 0xFFFA26 and stack top 0xFFA7FE. The prototype uses the loader-style FIFO classes; it does not substitute the resident OS's different status/data offsets. Register behavior, inherited peripheral setup, clock/speed selection and physical framing/CRC remain unqualified.

## Experimental transport

A request has the four-byte header 6D 18 F0 B1 followed by the exact 22-byte AR payload described in README.md (26 bytes total). Replies use 6D F0 18 F1 followed by the bounded ar payload (27-58 bytes total). These are prototype service values, not a standard or physically qualified AL5 protocol. Complete token/sequence/address fields and payload CRC are mandatory; the existing application reader is not redirected to them.

Each bounded polling step services the watchdog and consumes at most one scripted FIFO event or submits one TX byte. Numeric FIFO classes 1-4 collect data; a class-7 end with clear 0xC0 error bits can finish a request. Other end classes/flags, wrong headers, missing bytes, receive overflow and invalid core payloads do not read flash or generate replies. Overflow discards through the end event. The test interpretation of these FIFO classes is not a peripheral specification.

The candidate transmitter writes command 0x14 for the first byte, 0x04 for middle bytes and 0x0C for the last, as observed in the SPS sender. Busy status defers submission while watchdog servicing continues. Software completion does not establish physical transmission or adapter receipt. A second incoming request while TX is pending is discarded, consistent with the single-pending host contract. Corrupted internal bounds latch a fault rather than transmitting from outside the declared buffers.

The C# saved-VPW methods match these envelopes and use the core validator's nonce, sequence, full 24-bit address, count and CRC checks. The compiled runtime and C# validator exchange exact matching vectors in the offline harness, including persistent sessions crossing address banks and rejection of delayed previous replies.

## Candidate RAM layout and ownership limits

The linker bounds text below 0xFFA000 and rejects implicit writable .data/.bss. With the recorded toolchain the combined runtime is 1,166 bytes at 0xFF9006-0xFF9493, SHA256 505025dd1b1de06d1ba03e6be351f39c0e935a22a1ca02a6ab9bda30e5e66d79.

Declared candidates are:

- State: 0xFFA300-0xFFA30F (16 bytes).
- RX frame: 0xFFA380-0xFFA399 (26 bytes).
- TX frame: 0xFFA400-0xFFA439 (58 bytes).
- Core request: 0xFFA500-0xFFA515 (22 bytes).
- Core reply: 0xFFA600-0xFFA635 (54 bytes).
- Stack guard window: 0xFFA700-0xFFA7FF (256 bytes), initial SP 0xFFA7FE.

readonly_ram_layout.py verifies containment in the candidate 0xFF8000-0xFFB7FF interval and pairwise nonoverlap. This interval derives from saved firmware permissions, not proof of physical SRAM ownership. These addresses are resident RAM and cannot be assumed free while firmware/interrupts/DMA run. The code range overlaps the historical SPS loader intentionally; concurrent coexistence is unsupported. An exclusive and safe handoff remains a required, unproven condition.

The emulator rejects every guest write except declared RAM, byte writes to the VPW command/data registers and watchdog word writes of 0x0055/0x00AA. It rejects reads outside declared RAM/code/flash and the exact scripted status/data registers. Flash is mapped read-only. The deepest measured stack write in direct-step cases is 0xFFA7BC; the full-entry request case reaches 0xFFA7BE. These are measured case bounds, not a proof against every future path or asynchronous event.

## Executed validation

Fifteen grouped compiled-runtime cases cover flash endpoints, both address banks, the stock-service-excluded bytes in synthetic memory, malformed headers/length/overflow/CRC, error end events, busy TX, corrupt-state fault latching, persistent-state operation, overflow recovery and actual assembly entry. A malformed request following a successful reply does not retransmit the retained reply buffer. The full-entry case runs initialization and 100 loop steps through a complete scripted request and 58-byte software reply, with interrupt mask 7 and 101 watchdog pairs. The watchdog's write order and progress are checked; its physical deadline and other watchdog requirements remain unknown.

The host harness validates six actual compiled-runtime reply vectors, matching experimental VPW request/reply envelopes, and a two-frame persistent cross-bank transcript. Three RAM-layout/identity tests check bounds, overlap assumptions and rejection before emulator allocation. Existing AL5 write-gate and correlation regressions remain separate checks. No hardware was accessed by these tests.

## Reproduction

Requires the caller's existing WSL M68K compiler; no tools are installed by the builder:

```powershell
python Tools/AL5/build_readonly_kernel.py --output-dir LocalOnly/al5_runtime_new_build
```

With Unicorn available to the chosen Python environment, run emulate_readonly_runtime.py with --build-dir and a new --output receipt. Pass that receipt to `dotnet run --project Tools/AL5/ReadOnlyCoreSessionTest.csproj -- <receipt>` to check production C# interoperability. The builder records source hashes, compiler/flags, ELF text, symbols and emitted-code identity. It never places output in deployed Kernels/build and enables no device operations.

Before hardware execution, remaining gates include physical FIFO semantics/maximum frame length, initialization and speed, safe boot entry, CPU instruction compatibility, watchdog timing, exceptions/NMI/DMA, exclusive RAM ownership, safe exit/restore behavior and bench qualification on a recoverable controller. An emulator read of the six excluded addresses is not proof they can be physically read.

## Native boot handoff and peripheral fault follow-up

`Tools/AL5/emulate_readonly_handoff.py` now joins the pinned historical boot ISR,
dispatcher and RAM-transfer instructions to this independently built runtime in
one CPU/RAM session. LOW identity is
`cf5dd139e52ba5925fc95f166627a9a7abcac1374ded8cb738df8297b961a3f6`.
The executable bytes are removed before transfer; native byte stores must copy
all 1,166 bytes at 0xFF9006 and their final contents must match the build.
Five cases check armed entry, unarmed rejection, checksum rejection, copy without
execution, and checksum rejection followed by a valid transfer in the same session.

On accepted execution the native JSR arrives with a 72-byte pending boot stack
and return PC 0x33B8. The prototype then replaces SP with 0xFFA7FE, masks
interrupts and runs initialization plus two polling steps. All 72 abandoned
frame bytes remain unchanged in the synthetic external boot stack. This proves
neither a return path nor a safe physical stack arrangement: the test supplies
the boot stack at 0x208000, ISR-enabled context, FIFO/send/flush callbacks and
interrupt entry. Boot watchdog instructions are skipped, RTE is trapped, and
no physical upload or exception delivery occurs. The incoming stack location is
a test input, not an observed controller address.

The native transfer copies bytes before rejecting an unarmed or checksum-invalid
request. Rejection prevents entry in these cases but does not roll RAM back.
The reports distinguish those copied bytes from actual runtime entry; they do
not authorize experimenting with the installed controller.

Six additional compiled-runtime groups bring the runtime report to 21 groups.
They examine all 32 idle-class status bit combinations, repeated data overflow
and end-event recovery, partial frames across idle gaps, RX errors during TX,
software completion before physical completion, and every unowned RAM canary
after full assembly entry. The important open behaviors are explicit:

- An idle gap retains a partial frame; elapsed polling alone is no session boundary.
- A receive-error event during a pending reply is consumed without aborting TX.
  Whether that event represents a hardware TX fault is unknown.
- Last-byte submission clears software pending state without a physical-completion
  acknowledgement. The harness cannot establish wire delivery.
- Untouched RAM canaries and guarded CPU accesses establish containment for the
  exercised paths, not freedom from an asynchronous interrupt/DMA writer.

The runtime machine code and its SHA256 above are unchanged. This extension adds
offline evidence and exposes missing hardware contracts; it does not add a live
backend, peripheral initialization, watchdog timing proof or safe exit procedure.
The handoff report records generator/dependency hashes and both binary identities.
To reproduce with existing Unicorn dependencies, run the handoff tool with
`--low <pinned LOW dump> --build-dir <runtime build> --output <new report>`.

## Full collateral and completion-marker campaign

`emulate_readonly_collateral.py` now runs the compiled runtime through the entire
0x15FD8-0x1FFFF supplement in one persistent CPU/RAM session. It issues 1,282
requests: 1,281 at 32 bytes and a final eight-byte request at 0x1FFF8. All
41,000 flash bytes are read exactly once, with no calibration/OS overread.
This includes the 40,998 collateral bytes and the separately observed two-byte
completion marker. Assembly entry/initialization runs once; the emulator resumes
the original polling loop's saved PC and stack between requests.

The production `AL5ReadOnlyCollateralCampaign` uses the existing full-address,
nonce, sequence, count and CRC validator. All compiled request/reply envelopes
are checked through this host campaign. Old replies do not advance coverage.
No supplement, collateral-only reference or assembled saved snapshot can be
exported until every byte has a matching reply. Timeout/cancellation and a bad
CRC close the attempt, including a corrupt last reply after 40,992 accepted
bytes. No missing marker is invented. Marker values 4AFC and 1234 are preserved
in synthetic host tests; the compiled runtime's synthetic flash yields DFF0,
which is preserved exactly as well.

The complete direct-entry run records 128,201 ordered watchdog pairs, deepest
stack write 0xFFA7BE and 14,786 unchanged unowned-RAM canary bytes. These are
exercised software bounds, not physical watchdog timing or SRAM ownership.
The kernel machine code is unchanged: its source hashes still match the saved
1,166-byte build and SHA256 documented above.

An optional `--low <pinned LOW dump>` extends the same campaign through native
boot RAM-copy and handoff before reader initialization. It requires exact copied
runtime identity, observes pending boot frames, and checks that all 72 abandoned
frame bytes remain unchanged through the complete read. Reader-era canaries are
compared to RAM at the explicit handoff boundary, since bootstrap writes have a
different owner. This still uses a synthetic external boot stack, enabled-ISR
context, FIFO/send/flush callbacks and scripted runtime registers; boot watchdog
stores and RTE are not executed. It does not establish physical entry or shared
peripheral-state continuity.

Reproduce the campaign with `--build-dir <build> --output <new JSON>`, optionally
adding `--low`. Pass its report to `Tools/AL5/ReadOnlyCollateralCampaignTest.csproj`
to validate the production host against every compiled reply. Flash contents
remain synthetic; the output is not an independent controller backup. Live
upload, execution and writes remain disabled. Physical FIFO/clock/speed setup,
TX completion, CPU compatibility, exclusive RAM ownership, exceptions/watchdog,
safe exit and recoverable-bench qualification remain open.
