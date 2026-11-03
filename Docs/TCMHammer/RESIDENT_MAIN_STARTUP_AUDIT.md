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

The tool stops on the second unchanged read at the same PC/address/size, reporting `unchanged_peripheral_poll`. This is an analysis progress boundary, not a native timeout or an estimate of physical device timing. Reads of previously written registers assume inert readback; this assumption is also not verified peripheral behavior.

## Explicit conditional continuation

The optional `--mmio-inputs` document supplies an ordered list of integer `{pc,address,size,value}` records. A record is consumed only at its exact read site; out-of-order records remain unused. Unknown register reads stop, rather than silently returning zero. The report preserves consumed and unused records and the selected document's path and digest.

Supplying zero at the three command-completion read sites (`0xB42FC`, `0xB4302`, `0xB430E`) allows native execution to reach an unknown byte read of `0xFFFFFE20` at `0xB4314`. Explicitly assuming initial zero for `FE20` and `FE21` allows the helper's native invert/write sequence to return. The next native initializer `0x47324` reads the untouched status word `0xFFFFFC08` at `0x47374`.

A further conditional zero for that read reaches `0x475BC`, reading `0xFFFFFA40`. Assuming that value is zero reaches a new unknown byte read at `0x476BE` / `0xFFFFFC1F`. Each added assumption is a hypothesis for code exploration, not a measured reset value. These conditional traces still retain cleared response fields and unchanged banks; none has reached communication initializer `0xBDC38` through complete main startup.

## Freshness consequence

No new host freshness permission follows from this audit. The [earlier native scheduling cases](RESIDENT_REPLY_FRESHNESS.md) still show retained/requeued replies and low-16-bit address aliases. The production host continues one pending request per campaign, rejects mismatched replies, stops on timeout, and cannot use a matching echo alone to establish freshness across a new session or bank interval.

The immediate software gap is the remainder of `0x23018` and later main initialization, followed by the complete path through persistent restore, communication setup and scheduler enablement. Real register reset/completion behavior, IRQ delivery, elapsed timing and controller/adapter/USB draining remain physical qualification gates for the spare. A partial native path cannot authorize an original-bank backup or a write.

## Reproduction

Using the existing Python environment with Capstone and Unicorn available:

```text
python Tools/AL5/trace_resident_main_startup.py --full-reference PINNED_FULL_IMAGE --output NEW_REPORT.json
python Tools/AL5/trace_resident_main_startup.py --full-reference PINNED_FULL_IMAGE --output NEW_CONDITIONAL_REPORT.json --mmio-inputs EXPLICIT_INPUTS.json
python Tools/AL5/test_trace_resident_main_startup.py --full-reference PINNED_FULL_IMAGE
```

The five regression methods execute the real native path and check two dirty-RAM patterns, the exact strict boundary, explicit completion consumption and next unknown, out-of-order input rejection, invalid MMIO assumptions, and changed-image rejection. Existing twelve freshness outcomes and eleven receiver/restore outcomes are separately checked against the production host; they do not become full-startup or physical evidence.
