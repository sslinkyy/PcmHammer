# EFILive calibration profile: constructed offline writer

AL5EfiOfflineWritePlan constructs the observed EFILive calibration programming
requests from an explicit 1,590-byte loader, a native-checksum-valid 57,304-byte
calibration and a separate 40,998-byte collateral reference. It has no device,
security sender, upload/execution callback, timer or live enable switch. Caller
loader hashes bind supplied bytes; they do not qualify arbitrary code as safe.

## Distinct programming profiles

The captured EFILive path loads RAM 0xFF9000, explicitly requests subtype EE
erase, programs 0x8000 through 0x1FFFD in 192 blocks, then requests subtype FF
finalization. The final program block has 510 payload bytes, not 512 with
invented padding. The marker at 0x1FFFE is not transferred in those blocks;
the traced finalizer attempts to program it separately. The plan contains
195 distinct requests: loader, erase, 192 data blocks and finalize.

This differs from SPS2's captured full-programming utility at 0xFF9006, 4,096-byte
RAM staging blocks, metadata-derived OS/calibration programming, and internal
erase/fill operations. The two utilities' status contexts and failure paths
must not be merged into one interchangeable protocol. A future SPS2
calibration-only capture would establish an additional profile; it is not
needed to construct and test this already captured EFILive profile.

All three retained EFILive captures have 98,302 distinct transmitted bytes:
57,304 calibration bytes plus 40,998 collateral bytes. Their collateral SHA256
is b8a6f2bd4f514f2df06c4e5affc73f3a8e692b2be90405e56ae66bfa618f9033.
Those collateral bytes are repeating 4AFC, agreeing with the conditional SPS2
lower-tail fill except for the separately finalized marker. These are captured
requests, not independent pre-erase or post-program physical readbacks. The
builder never fills missing references with 4AFC, zeros or FF. Tests change
both ends of a synthetic collateral reference and verify that exact supplied
bytes reach the correct packets, including the mixed calibration/collateral block.

## Integration and failure behavior

AL5CapturedWriteRehearsal accepts the new plan as an optional explicit input.
The previous observation-only constructor remains usable without a plan.
When a plan is supplied, every loader, erase, data and finalize request must
match it exactly before the existing captured state machine consumes it.
Thus a rebalanced transfer checksum cannot conceal a changed collateral byte.
Returned review packets and input snapshots are independently owned copies.
Changing a checksum-correct calibration leaves the supplied loader, erase,
collateral-only packets and finalize request unchanged.

CopyNextOfflineRequest is available only at the selected loader, erase, next
new program block or finalize request boundary. It does not send or advance
state. Pending replies, checksum rejection, stopped attempts and completion
cannot produce an automatic retry request. Identical repeats can still be
observed explicitly when replaying saved captures; observing an existing retry
is distinct from authorizing or generating one. Security, setup, identity and
cleanup remain saved observations through the existing rehearsal.

The native failure findings remain those documented in
[erase failure stacks](ERASE_FAILURE_RETRY_STACKS.md) and
[finalization/recovery](VPW_FINALIZATION_RECOVERY.md): erase/program failures
can retain pending stack frames; a later positive reply does not prove a clean
session; finalization checks a word sum rather than the native CRC; reset and
recovery outcomes remain physically unknown. New constructed-plan tests inject
erase/program/finalize failure statuses and assert that no next generated
request is available. They do not simulate physical erase or recovery.

## Validation and remaining gate

Three complete saved setup-through-cleanup sessions pass with exact matches
for every observed loader/erase/program/finalize transmission:

- Session 02: 212 matching requests, including 17 repeated observations.
- Session 04: 220 matching requests, including 25 repeated observations.
- Session 05: 215 matching requests, including 20 repeated observations.

Each has 195 distinct requests and 192 positive program replies. Existing
checksum-error observation counts remain 15, 20 and 19, respectively. Existing
phase interruption, saved-image assessment and cleanup checks also pass.
Saved marker verification tests use explicitly synthetic snapshots; they must
not be relabeled physical readback. The Windows application builds, and all
210 AL5 write-gate combinations remain rejected before vehicle access.

The useful next proof is independent reading of the collateral/marker and
other protected flash, followed by physical qualification on a recoverable
controller. A calibration BIN or captured transmit stream cannot substitute
for that preservation evidence. Live upload, execution, writes, automatic
retry and readiness remain disabled.
