# Resident startup, interrupt unmasking and scheduling

This extends the [entry-to-communication audit](RESIDENT_MAIN_STARTUP_AUDIT.md) in the same native CPU/RAM instance. The pinned historical image executes in Unicorn; startup flash programs remain trapped by default. Optional bank continuation uses the existing bounded atomic model. There is no device connection, live reader backend, kernel upload, live execution or write permission.

## Remaining main initialization

The ordered input fixture `resident_startup_scheduler_mmio.json` extends the communication fixture by one explicit completion at `0x21E42`, register `0xFFFFFE18`, value zero. Without it, main's call at `0x99712 -> 0xBE608` stops at that peripheral wait. No completion is inferred from a delay.

With the declared completion and bank model, 84 observed calls from main return. This includes every examined initialization call before the final foreground function. The call at `0x99768` passes zero to native interrupt-mask helper `0x21CE0`. At its return, `0x9976E`, the emulated SR is `0x2000`: its interrupt priority mask bits are zero. This verifies the native instruction path in this model, not physical interrupt acceptance.

Main then selects the pointer at `0xC5A48`, entering `0x4FFE8`. That routine performs CRC work, writes startup handshake byte `A5+0xD0` to one, and waits at `0x5003C` for it to become two. Reply state is still empty at this boundary. The final main call has not returned; the subsequent native foreground path is a wait/counter loop, not an observed successful return from main.

## Native timer and event selection

The saved ISR wrapper at `0xC5B10` selects `0x99790` before initialization flag `A5+0x20BA` is set and `0xBD6D8` afterward. This continuation invokes only the latter native body at explicit synthetic boundaries. It saves/restores foreground CPU registers, provides an ordinary return frame, and starts with interrupt-mask bits set. It does **not** deliver an exception, execute that vector wrapper or `RTE`, establish a real vector assignment, model nested IRQ timing, or prove physical interrupt delivery.

The native body increments its retained tick index, reads masks from `0xBD730`, maintains the divider and slow phase, and calls event dispatcher `0xA4560`. The dispatcher selects actual callbacks from `0xC5A48` with native pre/post hooks. Neither the callback selection nor the startup handshake byte is changed by the host.

The repeatable-site fixture `resident_scheduler_sites.json` declares exact PC/address/size/value assumptions for:

- The encountered profiling waits on `FE18`, returning zero.
- The eleven received input words at the native sampling sites, returning zero.
- Three encountered waits on the `FC1A` busy bit, returning `0x3F0C`.
- One additional received word at `FD00`, returning zero.
- VPW status reads: numeric zero at `0x70AAC`, and numeric `0x10` at `0x70CE2`.

The VPW values select native software branches; they are not asserted to be measured hardware idle/success encodings. Site assumptions are unavailable until all ordered inputs have been consumed. Unlisted reads still stop. Every repeated application is recorded in the result. With no such assumptions, the first synthetic tick stops at the profiling wait `0x9D92C`; the tool does not silently complete it.

## Conditional scheduling result

From the actual post-main counters, 320 synthetic timer-body calls reach the handshake callback. The final call derives event mask `0x7F40` and selects `0x4FEE8` once. Native instruction `0x4FEF8` changes handshake one to two. Resuming the saved foreground context executes its comparison and native store of three, then stops before the counter loop at `0x5004C`.

During that interval, the native dispatcher invokes request dequeue `0xA4A38` 80 times and complete response scheduler `0x238AC` 80 times. The harness does not call those two routines directly. These are invocation counts, not milliseconds, a startup deadline or a timeout recommendation.

The scheduler submits software bytes `49 FE 18 06` with selected response index two at native tick index 63 (the 64th synthetic call). Tracking becomes `0002` while the Mode $23 body remains zero. Because the declared status inputs provide no completion event for that transmission, tracking remains nonzero at the endpoint. This is a conditional retained-response case, not evidence that a real controller fails to complete its transmission.

The native periodic callbacks also request four additional modeled journal programs after the earlier nine startup programs. They update payloads at `0x4A1E` and `0x4A42` and rewrite the associated `FFAA` markers. Exactly eight historical bytes differ at the endpoint: `4A1D`, `4A1E`, `4A23`, `4A29`, `4A2F`, `4A41`, `4A42`, `4A47`. The saved bank hash and every requested old/new payload are retained. No native flash implementation runs.

## What this establishes about freshness

The conditional software path now connects native entry, communication setup, the remaining initialization calls, interrupt unmasking, startup handshake and scheduled dequeue/response selection. It still does not establish a clean bank-read session. Empty Mode $23 body RAM does not imply an empty transmitter, receiver, controller queue, adapter queue or USB queue. The background response above is a concrete example of other traffic and retained tracking after startup.

The [earlier freshness cases](RESIDENT_REPLY_FRESHNESS.md) still govern: replies can be requeued, and the low-16-bit address echo cannot distinguish a delayed upper-bank request from a new lower-bank request. Existing host correlation and terminal-stop behavior remain unchanged. No fixed delay, number of timer calls, initialization flag or unrelated response is promoted to a freshness fence.

Still required are the physical peripheral/IRQ and queue-completion semantics, plus an independently qualified session boundary. Pre-entry bank snapshots must retain their post-startup acquisition epoch, including any ordinary journal activity. Live operations remain disabled.

## Reproduction and checks

Use the existing Capstone/Unicorn environment:

```text
python Tools/AL5/trace_resident_main_startup.py --full-reference PINNED_FULL_IMAGE --output NEW_WAIT_REPORT.json --mmio-inputs Tools/AL5/Fixtures/resident_startup_scheduler_mmio.json --model-bank-programs --stop-before-startup-wait
python Tools/AL5/trace_resident_main_startup.py --full-reference PINNED_FULL_IMAGE --output NEW_SCHEDULER_REPORT.json --mmio-inputs Tools/AL5/Fixtures/resident_startup_scheduler_mmio.json --mmio-site-inputs Tools/AL5/Fixtures/resident_scheduler_sites.json --model-bank-programs --scheduled-ticks 320
python Tools/AL5/test_trace_resident_main_startup.py --full-reference PINNED_FULL_IMAGE
```

Twelve regression methods cover the previous startup boundaries plus remaining main calls, the observed interrupt mask, the strict first-tick dependency, native event/callback selection, the native handshake stores, exact background submission/tracking and bank changes, and rejection of invalid scripted campaigns. Existing production-host tests separately retain the twelve reply-freshness and eleven receiver/restore outcomes. Neither test set grants physical or live-operation authority.

Pass the new scheduler report as the fourth argument to `ResidentFreshnessTest` after the pinned SPS OS, earlier freshness report and receiver-init report. The production campaign consumes the actual native background submission and classifies it as unrelated, preserving its pending bank request with zero acquired bytes. Timeout remains terminal, incomplete export remains rejected, and physical/live gates remain false.
