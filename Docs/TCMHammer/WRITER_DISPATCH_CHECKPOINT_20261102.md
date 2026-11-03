# AL5 writer dispatch checkpoint: 2026-11-02

This continues the [calibration writer candidate](CALIBRATION_WRITE_CANDIDATE.md) into host dispatch control and tests the production Vehicle/OBDX path offline. It adds no enabled live AL5 write/upload/execution route.

## Dispatch ownership and bounded qualification

`AL5OfflineWriteDispatcher` owns its candidate and snapshots. A request is reserved, then given an explicit adapter-send result, then associated with one reply slot. Reservations are immutable and single use. A duplicate or foreign completion cannot consume another request's reservation. Cancellation/timeout retains unresolved ownership for inspection and rejects late callbacks. Programming broadcasts cannot replace the outstanding data block's reply owner.

The default boundary is **BeforeSecurityKey**. Other immutable boundaries stop before programming entry, loader upload or erase, or after erase before data. The last option already models a destructive erase; it is not an initial read-only test. CompleteOfflineRehearsal must be selected explicitly for a complete dispatcher scenario. Reached boundaries cannot be resumed by a flag change; the model emits no reset, cleanup or further request automatically. They prepare the staged bench tests without adding a live execution path.

Explicit caller-selected time budgets cover send completion, control/erase/data/finalization replies and total session duration. Saved elapsed time must be monotonic. Other-source replies and auxiliary programming broadcasts cannot extend an outstanding data deadline. Arithmetic is checked against equality and near-TimeSpan-maximum cases without adding potentially overflowing absolute deadlines. These are model policies, not physically qualified watchdog or bus deadlines. Omitting the budget retains manual timeout control; it does not create a default live timeout profile.

Checksum retry review is separate from normal request generation, retains the exact rejected packet and obeys a per-block caller budget. A lost reply, ambiguous submission or cancellation never becomes an automatic retry. The stopped protocol phase and pending/last accepted/last reply-owned requests remain available for analysis.

## Profile and security restrictions

Dispatch requires the pinned 16 KiB boot SHA-256 and 679,828-byte OS module SHA-256, valid baseline/candidate calibration checksums and the supported selector-zero setting. Unknown saved firmware or a checksum-correct selector change is rejected before dispatch. This matches saved bytes, not an attached controller.

The observed selector-zero 9CE5/BC08 pair is accepted only as explicit saved security evidence in its current seed slot. A different seed, changed key or short-37 reply stops the model. There is no generic algorithm-50 fallback, no computed default key and no fresh-session authorization claim.

## Executable-loader acknowledgement distinction

The pinned native handoff model executes the successful executable upload into the loader without a positive boot upload ACK. A copy-only upload instead emits `6CF018760073`; a checksum failure emits `6CF018768077`. Startup, IRQ and flash/MMIO effects remain synthetic or suppressed where documented by that model.

File-only review of passive captures 02, 04 and 05 found the complete pinned loader request followed by the loader identity exchange, with no Mode-76 reply between them and no CRC-invalid frames in those selected windows. The raw GT source hashes, line ordinals and adapter timestamp bytes are retained privately. Absence in saved windows does not prove lossless capture or a universal rule.

The dispatcher therefore does not invent a mandatory successful upload-ACK slot. It retains loader identity ownership and separately stops on the native-derived loader checksum/rejection and unqualified copy-ACK stimuli, including when an identity query has already been submitted. It never treats these as data ACKs or permission to re-upload.

## Production GT send fix

`OBDXProDevice.SendMessage` previously discarded the result of `SendDVIPacket` and returned true even on adapter error or missing acknowledgement. It now returns success only for a successful DVI send result. A successful ACK must have the complete one-status-byte shape. The driver still accepts the existing 20/21 ACK command alternatives and preserves bus frames received before the ACK.

A false result or an exception after submitting bytes is **submission unknown**, not proof that the controller received nothing. The integration tests map it accordingly and stop without repeating a destructive request. No initialization, filter or bus-setting behavior was changed by this fix.

## Validation scope

- Dispatcher scenarios derived from all three captured writes finish 192 blocks, exercise the observed checksum rejections, custom BIN data, protected-region mismatches, immutable ownership, concurrent callbacks, timeout budgets and all five qualification boundaries.
- Those strict scenarios explicitly omit 3/6/2 ambiguous no-reply retransmissions, including repeated cleanup queries. They are derived stimuli, not claims of exact raw-capture replay. The previous raw-observation rehearsal remains separate and retains those repeats.
- `ObdxWriteSendTest` exercises the actual production Vehicle and OBDX driver through a sealed scripted IPort whose Open/change-baud/discard methods fail if called. Complete original/custom sessions cover controller replies before and after the adapter ACK. Its mock flash is reconstructed from the bytes actually serialized through OBDX plus explicit synthetic erase/finalization effects, never a physical readback claim.
- Fault cases stop at loader, erase, data and finalization on adapter rejection or an exception after submission. Loader failures queued before the adapter ACK remain correctly attributed after a later identity query.
- The generic PCM writer now explicitly rejects recognized full AL5 images as well as calibration segments. Original, damaged-calibration, known-OS-only and known-boot-only full references are rejected for every forced PCM type and write mode before any device access. Unknown firmware is not claimed to be universally classified by these fingerprints.
- The existing E54/PCM writer safety suite remains a separate regression check. No physical adapter, vehicle, live programming or recovery was tested.

## Application preparation command

The TCM Hammer menu now includes **AL5 Prepare Calibration Write Candidate (Offline)**. It selects calibration, complete saved reference and the pinned loader, checks the dispatch profile and exports a new text plan containing input hashes and all 195 programming requests. The handler accesses files only and refuses to replace an existing output. The Windows build validates compilation; interactive dialog behavior has not been exercised because the app was not launched.

Fresh controller identity/security, qualified pre-entry originals, physical entry/watchdog/VPW behavior, independent readback and recovery remain bench gates. The installed truck TCM is not the qualification target.
