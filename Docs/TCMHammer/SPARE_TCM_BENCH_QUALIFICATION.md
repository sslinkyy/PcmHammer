# Spare AL5 bench qualification checklist

Planning document only. The spare is ordered, not received or qualified. No adapter, controller, upload, execution, reset or write is started by this checklist. The installed truck TCM remains outside destructive qualification.

## Intake and configuration record

Record the spare's complete service/hardware numbers and clear label/connector photographs. Compare the actual hardware with the target profile; a seller description or matching connector is insufficient. Record physical damage, connector condition and the source of the bench harness pinout. Establish the required supply and ignition feeds from matching service information before powering the unit. No unverified pin-63 or flash-pin instructions are supplied here.

Assign the controller an identity in the local evidence directory. Record adapter model/firmware, host build commit/hash, capture configuration and supply settings. Each test needs its own directory; retain raw captures, application logs, original files, source hashes, timestamps and the exact selected operations. Do not publish vehicle-specific or proprietary blobs to the public repository.

## Gate A: ordinary identity and baseline reads

After hardware setup has been reviewed and the physical connection state confirmed, use only the existing qualified read-only functions first. Record successful identity replies and the operating/calibration identifiers. Read the existing 57,304-byte calibration twice into distinct files; compare hashes and native checksums, and retain both files even if they differ. A mismatch stops progression until explained.

Maintain an explicit byte-coverage record. Distinguish boot 00000..03FFF, persistent banks 04000..07FFF, calibration 08000..15FD7, collateral 15FD8..1FFFD, completion marker 1FFFE..1FFFF, and OS/rest 20000..FFFFF. Unknown bytes stay unknown; SPS modules, expected fill and captures of transmitted bytes are not independent original backups. The current Mode 23 calibration reader does not provide all of this coverage.

Preserve the persistent-bank data before any programming-style application entry. The new full-image prototype starts after entry; its bank contents may already include legitimate preparation updates. Do not call that post-entry image the original bank backup. Establish the qualified pre-entry read path separately.

Gate A passes only for operations actually observed to work. It does not authorize experimental kernel entry or prove the controller's flash-to-CPU mapping, hardware sector protection, current security state or recovery.

## Gate B: isolated read-only entry qualification

Before any live prototype upload/execution, review the source-pinned loader-entry plan, preparation storage side effects, reset cause/retained RAM assumptions, watchdog handling, RAM ownership, VPW configuration and exit procedure. The ordinary programming-entry command may update persistent banks; calling it an entry check does not make it non-destructive.

A future hardware session must have an explicit approved operation list and stop conditions. Start with the smallest bounded read that tests the unresolved handoff/transport facts. Retain capture of setup through cleanup, not only payload transfer. A timeout or unexpected reply stops the session; it does not trigger automatic retry, reset or a write. The prototype remains disabled until this gate is separately reviewed.

## Gate C: preservation and unchanged-calibration programming

Require an independently acquired complete pre-erase baseline and a demonstrated way to recover the qualification module. Preserve the persistent banks as well as the 8000..1FFFF calibration sectors because the normal preparation path can touch 4000/6000.

Review exact module identity, candidate checksum/anchors, byte-address mapping, sector allowlist, collateral restoration and marker finalization. Choose the actual profile: EFILive calibration captures and SPS full-programming captures are distinct; no calibration-only SPS sequence is inferred by dropping OS blocks. Keep capture active before initialization through post-operation cleanup.

The first programming qualification, when authorized, uses unchanged calibration. Success requires independent post-write comparison of the affected sectors and separately checked preserved regions, plus a normal subsequent boot/identity check. A positive programming reply alone is insufficient.

## Gate D: interruption and recovery

Only after the unchanged-programming path and the physical recovery method are demonstrated should controlled interruption qualification be designed for the spare. Separate entry/preparation, erase, partial programming and finalization interruptions. Record actual flash contents and boot behavior after each; do not equate emulated reset injection with physical watchdog/reset behavior.

The original byte backup, usable recovery equipment/procedure and the user's acceptance of the spare's risk are prerequisites. A12 remains an offline hypothesis. No destructive interruption or pin manipulation is scheduled here.

## Stop conditions and current status

Stop progression on unidentified hardware, uncertain wiring, unstable power, inconsistent baseline reads, unknown original bytes in an affected region, unresolved preparation writes, unexpected capture gaps, timeouts or ambiguous replies. Preserve evidence before investigating. Each gate requires explicit evidence; buying a spare does not automatically pass one.

Current status: offline tests only. Live upload, execution, writing, automatic retries, physical recovery verification and ready-to-flash flags remain false.
