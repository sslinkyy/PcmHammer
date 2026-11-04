# Security and original/prepared backup path

This extends the [four write priorities](FOUR_WRITE_QUALIFICATION_PRIORITIES.md). The spare is in transit. The public write entry still returns `LiveDisabled` before dependency access; no live security, upload, execution or write is enabled.

## Security is one owned exchange

`AL5SavedSecurityExchange` consumes an owned original image matching the existing pinned boot/OS and selector-zero calibration profile. It reads the fixed seed/key words from that saved boot image at `0x3FD8/0x3FDA`. It does not use algorithm 50 as a fallback and does not generate a request automatically.

The dispatcher now binds seed interpretation to the confirmed seed-request send, requires a matching saved seed before key review, permits one reviewed key send, and waits for its reply. Extra, foreign or stale observations do not create another send slot. The saved protocol has no challenge nonce that could prove a physical reply is fresh; ownership here is host ordering, not physical freshness proof.

The recorded/native selector-zero outcomes are distinguished explicitly:

- `67 02 34`: saved acceptance observed; physical authorization remains unverified.
- `67 02 35`: key rejected.
- `67 02 36`: attempts exceeded.
- `67 02 37`: delay required.
- `7F 27 xx`: negative security response with the raw reason retained.
- Short `67 01 37`: unqualified seed response, never an unlock.

Malformed lengths, unexpected seeds, unknown statuses and unsupported profiles stop. A full zero seed remains unsupported by the captured writer lifecycle even though the native synthetic-state audit has an already-unlocked branch. Rejection, lockout and timeout do not schedule another key attempt or guess a delay interval. A new session cannot reuse the old exchange's pending slot.

This is a profile-specific saved-evidence path, not general fresh-controller security support. The [native authorization audit](../AL5/READER_STARTUP_QUIESCE_SECURITY.md#fresh-security-support-audit) remains the source for handler behavior. The spare's boot profile, current selector, physical seed response, acceptance and lockout timing still need qualification.

The complete-reference constructor also exposes an acquisition dependency: stock Mode $23 cannot independently supply the boot security words. If a proposed full-reader handoff itself requires authorization or bank-changing preparation, a historical reference cannot substitute for the spare's missing original bytes. The [multipart checkpoint](WRITE_PROGRESS_20261103.md) selects correlated, coherent acquisition as the primary development path, with external flash acquisition as the fallback when safe pre-entry handoff cannot be qualified.

## Original and prepared acquisition have different sessions

`AL5SavedBackupPath` connects the existing correlated reader campaigns to the writer's required pre-erase review:

1. Acquire every byte of the original 1 MiB in saved replies. No image is available while coverage is incomplete.
2. Explicitly record the entry boundary only after original coverage completes. This records offline ordering; it does not execute entry.
3. Acquire all 16 KiB at `0x4000..0x7FFF` using a different nonce. Replies must also match the pending sequence, full address, count and internal CRC.
4. Bind the completed epochs to the executor by the original-image SHA-256. A different original image cannot satisfy its pre-erase review.

The executor retains the evidence identity, original-image hash, prepared-bank hash and changed-byte count. Original bytes are never replaced by prepared bytes. The post-write preservation comparison uses the explicitly recorded prepared banks while the original remains available for restoration.

The [saved backup exporter](../../Tools/AL5/SavedBackupTool/README.md) validates complete transcripts before producing original and prepared BINs plus a report with input paths, hashes and coverage. It rejects existing output directories and incomplete, out-of-order, unowned or mismatched transcripts. The experimental correlated-reader format is required; a stock Mode $23 trace cannot supply missing session/address correlation merely by relabeling it.

The new path remains a saved-response model. Running the experimental reader without first changing persistent banks is still a physical entry/ownership problem. Historical reconstructed firmware, synthetic responses and supplied files do not prove original pre-entry acquisition or physical address mapping. These flags remain false in every successful export and executor report.

Nonce and full-address correlation also do not make a changing bank an atomic snapshot. The ordinary startup/periodic journal writes now traced through native scheduling require quiescing or an independently validated coherence procedure for an original full acquisition. Epoch labels and complete byte counts cannot conceal mixed-time journal contents.

## Validation scope

The expanded execution suite runs complete capture-derived writer sessions through the production Vehicle/GT binding with scripted I/O, plus explicit security rejection/lockout stops and correlated original/prepared epochs feeding an unchanged-calibration rehearsal and saved full readback. Modeled read data and flash effects are synthetic. The exporter additionally checks complete output, stale-epoch filtering, partial originals, partial prepared banks, wrong nonces, duplicate requests, unowned replies and immutable existing outputs. No hardware port is opened.

Before enabling a separately reviewed live binding, qualify the arriving spare's identity, fresh security, safe reader/entry behavior, original and prepared coverage, independent readback and recovery. Do not substitute software test success for those gates.
