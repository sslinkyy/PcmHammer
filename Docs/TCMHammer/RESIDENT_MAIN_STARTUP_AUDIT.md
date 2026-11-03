# Pre-entry bank reads: remaining application startup

The native startup audit extends the [receiver initialization trace](RESIDENT_RECEIVER_INITIALIZATION.md) to application entry, MCU setup, C runtime and early main in one emulator instance. It uses the pinned historical full image, synthetic dirty RAM and the existing declared 24-bit RAM alias. It does not open a device. Live read, upload, execution and write authority remain disabled.

## Observed native path

The application pointer at `0x20408` selects `0xC5B74`. Native entry performs register setup, selects the C runtime at `0xBE4F4`, and reaches main at `0x994D0`. From main the audit observes these actual calls and returns, without substituting their results:

- `0x994E0 -> 0xC5B54`: returns.
- Indirect call at `0x994EC -> 0xC5A88`: constructors return.
- `0x994F2 -> 0x21CE0`: interrupt-mask helper returns.
- `0x994F8 -> 0xA96F8`: calibration checks return.
- `0x9952A -> 0x23018`: enters peripheral initialization and has not returned at the audited stop.

With either initial RAM pattern `A5` or `5A`, C-runtime clearing removes the stale response pattern. The body, pending byte, tracking index, request length, TX count and receive-ring bytes remain zero at the strict stop. Both persistent banks `0x4000..0x7FFF` remain byte-identical. This establishes preservation only through the examined path; later startup has not run.

## First hardware-dependent boundary

Inside `0x23018`, helper `0xB41C8` writes command/configuration words at `0xFFFFFE18` and `0xFFFFFE1A`. At `0xB42FC` it repeatedly tests `FE18`; the inert register model retains `0xFDBF`, so the firmware does not advance. Subsequent instructions also wait on `FE1A`, write `0x3F00` to that register, and wait on `FE18` again.

The tool stops on a repeated unchanged read at the same PC/address/size without an intervening register write or explicit input, reporting `unchanged_peripheral_poll`. It detects both single-register and alternating-register waits. This is an analysis progress boundary, not a native timeout or an estimate of physical device timing. Reads of previously written registers assume inert readback; this assumption is also not verified peripheral behavior. Both the internal register range and the known external VPW register window `0xFFE800..0xFFE80F` are treated as device state rather than ordinary RAM.

## Explicit conditional continuation

The optional `--mmio-inputs` document supplies an ordered list of integer `{pc,address,size,value}` records. A record is consumed only at its exact read site; out-of-order records remain unused. Unknown register reads stop, rather than silently returning zero. The report preserves consumed and unused records and the selected document's path and digest.

Supplying zero at the three command-completion read sites (`0xB42FC`, `0xB4302`, `0xB430E`) allows native execution to reach an unknown byte read of `0xFFFFFE20` at `0xB4314`. Explicitly assuming initial zero for `FE20` and `FE21` allows the helper's native invert/write sequence to return. The next native initializer `0x47324` reads the untouched status word `0xFFFFFC08` at `0x47374`.

A further conditional zero for that read reaches `0x475BC`, reading `0xFFFFFA40`. Assuming that value is zero reaches a new unknown byte read at `0x476BE` / `0xFFFFFC1F`. Each added assumption is a hypothesis for code exploration, not a measured reset value. Those early conditional traces retain cleared response fields and unchanged banks.

## Continuation through communication initialization

The public fixture `Tools/AL5/Fixtures/resident_startup_communication_mmio.json` records 27 ordered hypothetical inputs. Beyond the early boundary, it supplies initial values for `FC1F` and `FC1C`; clears only the tested busy bit in the retained `FC1A` word (`BF0C -> 3F0C`) at three transfer waits; and supplies eleven explicit zero-valued received words at `FD02..FD16`. These received words are hypothetical peripheral data, not recorded VPW traffic. It also supplies `FA18`, completion at the two-register `FE18/FE1A` wait, reset status `80`, and the initial watchdog read at `FA26`.

The strict tool still stops before any storage implementation. With this complete peripheral-input document, its first stop is `0x22C3C`, called from `0x229BC`, with a one-word program requested from RAM into bank address `0x4A1C`. Main has reached persistent startup initializer `0x5B8EC`; communication initialization has not yet run.

The optional `--model-bank-programs` continuation reuses the existing `require_programmable` rule and models atomic RAM-to-bank programs, constrained to the two persistent banks and one-to-zero transitions. It writes a synthetic success status and returns to the actual native caller. Erase and tail-copy implementations remain trapped; native flash code is never executed. Each modeled operation records source, destination, length, old/new bytes and `implementation_executed=false`.

Under that explicit model, native startup makes three journal updates:

- Marker `0x4A1C`, ten-byte payload `0x4A1E..0x4A27`.
- Marker `0x4A28`, ten-byte payload `0x4A2A..0x4A33`.
- Marker `0x4A40`, ten-byte payload `0x4A42..0x4A4B`.

Each uses `FFFF -> FFFE`, payload programming, then `FFFE -> FFAA`: nine modeled programs total. Exactly six historical bytes differ at the endpoint: `4A1D`, `4A1E`, `4A29`, `4A2F`, `4A41`, `4A42`. The native startup helpers update persistent bitmap records; this evidence does not establish their physical lifetime or purpose.

Startup then restores context, performs the remaining pre-communication initialization, and follows `0x995E4 -> 0xBDC38` and `0x995EA -> 0xC02F8`. All 25 main calls examined have returned at the bounded stop `0x99604`. Body, pending flag, tracking, request length, TX count and ring body are zero. Ring producer/consumer are both one, receive flags are `00000001000001`, and native eligibility admits Mode $23. The two tested combinations (dirty RAM `A5` with synthetic reset status `80`, and `5A` with `40`) give the same bank changes and receiver state.

This is a conditional entry-to-communication trace, not complete startup: later main initializers, interrupt enablement and foreground scheduling have not executed. It also does not prove that real peripherals complete with the supplied values, or that controller, adapter and USB queues are empty.

## Freshness consequence

No new host freshness permission follows from this audit. The [earlier native scheduling cases](RESIDENT_REPLY_FRESHNESS.md) still show retained/requeued replies and low-16-bit address aliases. The production host continues one pending request per campaign, rejects mismatched replies, stops on timeout, and cannot use a matching echo alone to establish freshness across a new session or bank interval.

The [remaining-main and scheduling continuation](RESIDENT_STARTUP_SCHEDULING.md) now connects this conditional boundary to interrupt unmasking, native timer-driven dispatch and the startup handshake. It exposes background response tracking and further journal activity; it does not close physical freshness. Physical register reset/completion behavior, IRQ delivery, elapsed timing and controller/adapter/USB draining remain qualification gates for the spare. An original bank acquisition must be labelled by its acquisition epoch: resident pre-programming-entry bytes can already include ordinary startup journal updates. It must not be represented as an unchanged snapshot from before power-on. No startup rehearsal authorizes a live backup or write.

## Reproduction

Using the existing Python environment with Capstone and Unicorn available:

```text
python Tools/AL5/trace_resident_main_startup.py --full-reference PINNED_FULL_IMAGE --output NEW_REPORT.json
python Tools/AL5/trace_resident_main_startup.py --full-reference PINNED_FULL_IMAGE --output NEW_CONDITIONAL_REPORT.json --mmio-inputs EXPLICIT_INPUTS.json
python Tools/AL5/trace_resident_main_startup.py --full-reference PINNED_FULL_IMAGE --output NEW_COMMUNICATION_REPORT.json --mmio-inputs Tools/AL5/Fixtures/resident_startup_communication_mmio.json --model-bank-programs --stop-after-communication
python Tools/AL5/test_trace_resident_main_startup.py --full-reference PINNED_FULL_IMAGE
```

The eight regression methods check the strict boundaries, ordered input consumption, changed-image rejection, alternating-register polling, the default storage trap, and conditional continuation through actual communication setup. They verify exact modeled bank mutations and receiver state for both tested RAM/reset combinations. Existing twelve freshness outcomes and eleven receiver/restore outcomes are separately checked against the production host; they do not become full-startup or physical evidence.
