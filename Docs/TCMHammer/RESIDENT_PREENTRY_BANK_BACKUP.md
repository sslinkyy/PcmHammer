# Resident reads before programming preparation

The [joined reply-freshness continuation](RESIDENT_REPLY_FRESHNESS.md) distinguishes software retirement/requeue from initialization and identifies application C-runtime clearing as a candidate startup dependency. It does not qualify a physical freshness boundary.

The most direct candidate for preserving the original mutable banks is the resident application Mode $23 path, before any programming-entry request or uploaded reader. The new trace executes more than the isolated read handler. It still does not qualify a live acquisition, and all live operations remain disabled while the spare is in transit.

## Native path observed

Using the fingerprinted historical LOW/HIGH image, `trace_preentry_banks.py` executes:

1. Application request dequeue at `0xA4A38` through `0x23694`.
2. Service-table lookup via `0xBA824`, table `0x99A70`, and the real descriptor callback `0xB1970`.
3. Mode $23 descriptor `0x99A12`, flags `9000`, handler `0xBFDA0`, and its permission helpers.
4. Native pending-response clearing/formatting into the software TX buffer. This does not submit a frame to real hardware.

Twenty-four positive controls cover both bank endpoints/interior boundaries, two synthetic receive-ring offsets, and guard states `00`, `20`, `60`. They reach the resident handler, format the expected four-byte data reply, leave both persistent banks unchanged and do not call preparation or storage. These guard inputs include the native security lock bit. The observation supports investigating bank reads without first submitting a key; it does not establish that every physical session or firmware profile behaves identically.

A complete retained-CPU campaign runs 4,096 sequential dword reads covering `0x4000..0x7FFF`, returning all 16,384 historical fixture bytes exactly. Each request uses a unique low-16 echo within this interval. The production saved-bank campaign consumes the native transcript and reproduces those bytes. Historical fixture data is not newly read controller data.

The unlocked programming control takes descriptor `0x99A30` to `0xBE6D0`, calls preparation `0x5BAB8` and persistent-storage selection `0x226F0`, then stops at erase wrapper `0x22B18` with destination `0x6000`. The erase primitive never executes. This distinguishes the resident read path from the bank-changing entry path at a concrete native boundary.

Negative controls retain locked-entry rejection, malformed programming length, malformed read count, forbidden boot-word permission, unchanged marker/lockout state during a read, and source-identity rejection.

## Bank-first qualification order

On the spare, after separately reviewing the live read path and its physical response/session assumptions:

1. Stay in the ordinary resident application. Do not issue Mode $34, upload or execute a kernel before obtaining the banks.
2. Acquire only the `0x4000..0x7FFF` interval with one pending dword, no echo reuse, and a terminal stop on timeout, negative or malformed response. Do not interleave upper-bank requests that reuse those echoes.
3. Preserve the bank file and transcript with their hashes and coverage. Label its acquisition state honestly; the exporter cannot certify that entry had not run.
4. Only after this evidence is qualified should a separately reviewed programming entry and post-entry full read proceed. Retain both epochs and their delta.

The current live calibration reader is unchanged and does not gain this range. The [file-only exporter](../../Tools/AL5/SavedBackupTool/README.md) now has a resident-bank mode to validate and retain saved transcripts through the existing host campaign. It exports 16 KiB only, never a complete original image.

## Remaining limits

Mode $23 replies echo only two address bytes. An old reply from `0x14000` can still match a pending `0x04000` request. Unique echoes within this bank-only acquisition prevent reuse by this plan; they do not prove a clean physical session. The harness supplies one synthetic ring record per invocation and does not qualify IRQ/FIFO delivery, response requeue, peripheral completion, adapter queues or timing. It does not turn a ring clear, delay or unrelated query into a freshness fence.

The stock handler still excludes six flash bytes elsewhere. A pre-entry bank file plus a post-entry full image is mixed-epoch evidence. Do not automatically label their combination an independent complete original backup; preserving all other regions and acquiring the excluded bytes remain separate gates. The correlated full-reader model and its original/prepared workflow retain their stricter semantics.

The REA Windows Ghidra provider currently admits native x86/x64 PE targets, not this M68K firmware. This continuation uses the existing source-pinned Capstone/Unicorn tools; it makes no Ghidra-provider claim.

## Reproduction

Run `trace_preentry_banks.py --full-reference PINNED_HISTORICAL_IMAGE --output NEW_DIR --complete` using the existing Python Capstone/Unicorn environment. `test_trace_preentry_banks.py --full-reference PINNED_HISTORICAL_IMAGE` runs the negative controls. No dependency installation or hardware access is needed.

Then run `dotnet run --project Tools/AL5/PersistentBankCampaignTest.csproj -- PINNED_SPS_OS NEW_DIR --preentry` to validate the produced transcript through the existing saved-bank owner. The emitter records source/code digests and explicitly false live/physical flags. Keep raw firmware and trace artifacts private.
