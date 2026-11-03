# Resident Mode $23 reply freshness

The [receiver-initialization continuation](RESIDENT_RECEIVER_INITIALIZATION.md) adds the real communication initializer, guarded status entry, complete scheduler selection, native countdown and persistent-context restore. Physical startup and freshness remain unqualified.

This continues the [pre-entry bank trace](RESIDENT_PREENTRY_BANK_BACKUP.md). The new joined native trace distinguishes reply retirement, requeue, interface clearing and application startup. It establishes no physical session boundary and enables no live operation.

## Joined scheduling and status observations

`trace_resident_reply_freshness.py` starts with the actual resident application dequeue/lookup/descriptor/Mode $23 path for `0x04000`. It then executes the selected-index scheduler tail at `0x23ABC`: clear the selected pending bit, format the reply, call native submission `0x70A44`, and track response index 75 through `0xC54E8`. Submission is observed as writes to inert MMIO, not as a physical transmission. The scheduler's eligibility selection, elapsed timers and real interrupts are outside this slice.

The same emulator then executes the actual accumulator, status consumer `0x70AA8`, event handler `0x23428`, ring commit/discard and tracking helpers. Earlier status tests intercepted these callbacks; this continuation runs them together.

For scripted status class `E0`, data `00`, empty TX staging and a nonempty RX accumulation, the native consumer derives event mask `00`. The event handler requeues the tracked Mode $23 pending bit, retains the body and clears the tracking index. Running the scheduler tail again submits identical bytes.

With the same context and data `30`, it derives mask `40`, clears tracking and does not requeue. This is a software retirement witness, not a verified physical-success event. With no RX accumulation, the same numeric input leaves tracking intact. Other tested numeric combinations retain tracking or discard and requeue. Do not identify these masks as physical success/error labels without peripheral evidence.

The native interface clear/reset path at `0xC04FC` is particularly important: it clears TX staging, zeroes the receive ring and resets its indices, but calls `0xC54CC` to requeue the tracked response. The old body can be submitted again. Neither an empty ring nor this reset routine is a freshness fence. Interface initializer `0xC04B8` also retains an existing tracked response/body when invoked alone.

Even after the numeric retirement witness, a later accumulated request for `0x14000` can be committed and dispatched natively. It produces a different data body with the same `4000` address echo as the earlier `0x04000` reply. Retirement of one reply is not retirement of all queued requests or external frames.

## Startup gives a narrower candidate boundary

The separate reset trace supplies dirty response RAM and executes the pinned boot with synthetic reset/status values `80` and `40`, no fault injection and no programming request. Both cases stop at the application-transfer boundary with the selected response fields replaced by the RAM-test pattern `AA`; the banks remain unchanged. These status values are not labeled physical cold/warm-reset causes.

The application entry pointer at `0x20408` targets `0xC5B74`. Static code at `0xC5D30` selects C-runtime initializer `0xBE4F4`. The initializer copies the data section, then its real zeroing helper clears the BSS region containing the Mode $23 body/pending bit, tracked index, RX length, TX count and receive ring. Two executed dirty-pattern cases stop before application main at `0x994D0` and show those fields zeroed. Subsequent interface initialization starts with no old tracking to requeue.

The reset-to-application and CRT experiments are distinct CPU contexts; no continuous handoff through MCU configuration and application main is claimed. The next useful software target is the receiver-enabled boundary after main's initialization. On the spare, the eventual qualification candidate is a verified normal application startup plus a separately justified adapter/USB boundary, followed by the bank-only request sequence. A logical new campaign or interface reset cannot stand in for that startup.

## Host consequences and retained gates

The production saved-bank owner rejects a repeated earlier echo while the next dword is pending, retains the outstanding slot, and stops permanently on timeout. A newly constructed owner requesting `0x04000` still accepts the native `0x14000` same-echo witness as `MatchingLow16Echo`. This is a demonstrated wire-format limitation, not a parser defect that can be fixed by accepting another acknowledgement.

The host tests consume the native report and retain false freshness, full-address identity, physical-acquisition and live-operation flags. The bank exporter still labels its 16 KiB output as saved observations, not an independent complete original backup. No retries, delays, interface resets, security submissions, reader uploads or live reads were added.

## Reproduction

- `trace_resident_reply_freshness.py --full-reference PINNED_IMAGE --output NEW_JSON` produces the twelve joined state cases with source/code hashes.
- `trace_resident_startup_state.py --full-reference PINNED_IMAGE --output NEW_JSON` produces two reset-to-application witnesses. Use the existing Python Capstone/Unicorn environment.
- `dotnet run --project Tools/AL5/ResidentFreshnessTest/ResidentFreshnessTest.csproj -- PINNED_SPS_OS NATIVE_FRESHNESS_JSON` checks the native outcomes and actual host duplicate/alias/stop behavior without hardware.

Keep raw source firmware and result bytes private. Physical reset retention, status meanings, IRQ/FIFO behavior, timing, receiver readiness, controller/adapter/USB drain and complete original-flash coverage remain unqualified.
