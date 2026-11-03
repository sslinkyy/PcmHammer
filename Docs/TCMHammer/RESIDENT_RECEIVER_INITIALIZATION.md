# Resident receiver initialization and first bank replies

This continuation uses the existing Capstone/Unicorn environment without IDA. It extends the [freshness trace](RESIDENT_REPLY_FRESHNESS.md) from isolated status callbacks to a native initialization/receive/dispatch/scheduler chain. No live read, upload, execution or write is enabled.

## Initialization and persistent restore

Application main at `0x994D0` calls communication initializer `0xBDC38` from both observed branches at `0x995E4` and `0x995F8`. The new emulator executes the real C-runtime initializer, stopping before main, then calls this communication initializer on the same CPU/RAM instance. Other main initializers and MCU configuration are not executed; this is not a complete application-startup qualification.

The initializer calls interface setup `0xC04B8`, native software-state helpers and profile setup `0xB0B94`. In the pinned profile, the default transmit-eligibility mask admits Mode $23. After the C-runtime clear and this path, the old body, pending bit and tracking index remain clear and the receive ring indices are one. Calling the communication initializer alone after an old reply was submitted retains that reply's body and tracking; it is not a substitute for C-runtime initialization.

The native persistent-context restore used by startup was also executed after C-runtime clearing. It selects the historical committed record, restores `0x9F2` bytes into `0xFF8140..0xFF8B31`, and passes the native CRC check. That destination does not overlap the Mode $23 reply body, pending vector or tracking index. The trace retains their cleared state through restore, communication initialization and a subsequent bank reply, with both flash banks unchanged. The remaining main initialization sequence has not been proved to preserve every response field.

## Guarded native receive path

The actual status guard at `0xC3D98` now precedes consumer `0x70AA8`. Six input cases establish software branch behavior:

- With its block flag clear, numeric class `40` reaches the consumer and accumulator.
- Numeric class `20` does not take this guard's consumer path, even though the consumer itself has a class-20 branch.
- Class `60` additionally requires the tested enable byte to equal one.
- The block byte suppresses consumer entry.
- The alternate-receive flag directs the byte away from the ordinary request accumulator.

These are scripted numeric status inputs, not assertions about physical peripheral event meanings. IRQ priority/delivery, FIFO behavior and timing remain unqualified.

The positive chain supplies one eight-byte resident bank request through that guard, runs native event/ring commit, dispatches the committed request at `0xA4A38`, and invokes the complete scheduler function at `0x238AC`. Native eligibility selection chooses index 75, formats the correct bank reply, submits its bytes to inert MMIO and records tracking. Unlike the earlier selected-tail test, this case does not manually choose the response index or invoke the read handler directly.

## Next-request ordering and countdown

Two explicit call interleavings cover consecutive bank requests at `0x4000` and `0x4004`. If dispatch runs first, the new body is submitted. If scheduling runs before dispatch of the next queued request, the retained `4000` reply can be submitted again. After dispatch stages `4004`, the scheduler can hold it behind its native countdown while preserving its pending bit.

The gated case loads countdown `0x640`. The actual timer routine `0xC448C` and generic helper `0xB0A40` expire it after 100 calls with decrement 16; the scheduler then submits the correct `4004` reply. This is an invocation count, not a measured duration or a host timeout recommendation. No timer value is manually zeroed to make the case pass.

Production host tests consume those actual native reply sequences. While `4004` is pending, the repeated `4000` reply is unrelated and leaves the slot open; the subsequent `4004` reply advances coverage. Timeout still permanently stops the campaign, and incomplete banks cannot be exported. The same-echo alias limitation at session start remains unchanged.

## Validation and remaining gates

`trace_resident_receiver_init.py --full-reference PINNED_IMAGE --output NEW_JSON` produces eleven cases with source/code hashes and false hardware/live flags. Use the existing Capstone/Unicorn Python environment.

`dotnet run --project Tools/AL5/ResidentFreshnessTest/ResidentFreshnessTest.csproj -- PINNED_SPS_OS FRESHNESS_REPORT RECEIVER_INIT_REPORT` checks both the previous twelve freshness outcomes and these eleven native outcomes against the production host owner.

The receiver-initialization result is a stronger software rehearsal for the bank-first path. It does not provide a live reader backend or close physical freshness. The [whole-entry startup audit](RESIDENT_MAIN_STARTUP_AUDIT.md) now reaches native communication setup under explicit peripheral inputs and a bounded atomic storage model. It exposes startup journal changes that the isolated restore/receiver slice did not execute. Complete main startup remains untraced. Still required: remaining application startup effects, real IRQ/FIFO/status semantics, elapsed-time bounds, independent controller identity and a controller/adapter/USB boundary. Complete original-flash coverage and recovery remain separate gates.
