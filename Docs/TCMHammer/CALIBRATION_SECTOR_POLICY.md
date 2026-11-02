# Calibration-only sector policy

Implemented in `Apps/PcmLibrary/AL5CalibrationSectorPlan.cs`. This is an offline host/model policy, not an uploaded kernel, hardware protection or live writer. Physical address mapping and sector protection remain unverified.

## Geometry and allowed destinations

Geometry follows AMD/Spansion Am29F800B datasheet 21504E5, Table 3, under the candidate contiguous x16 CPU byte mapping: SA0 00000..03FFF, SA1 04000..05FFF, SA2 06000..07FFF, SA3 08000..0FFFF, and SA4..SA18 10000..FFFFF in 64 KiB sectors. The implementation returns separate byte-address starts/ends for all 19 sectors; it never accepts word indices as CPU byte addresses. Source: https://www.batronix.com/files/Datenblaetter/29__/AM29F800B.pdf#page=14.

The calibration-only erase allowlist contains canonical starts 8000 and 10000. Chip erase and all other sector targets are rejected. This protects the modeled boot prefix, persistent banks and OS from this calibration-profile destination list; it does not constrain the separately traced preparation routine or arbitrary loader code.

Program validation covers the complete nonempty, word-aligned span at 8000..1FFFD using widened arithmetic. Marker word 1FFFE..1FFFF is accepted only through separate finalization validation. Spans may cross the SA3/SA4 boundary because both sectors belong to the profile; they may not cross its protected boundaries. Negative/zero/odd counts, odd addresses, overflow, staging-RAM addresses and protected regions are rejected.

These are array destination checks. They are deliberately not applied to AMD unlock-command cycle addresses or RAM loader upload destinations. There is no new raw flash-command, adapter, upload, execution or write API. The existing EFILive offline plan invokes the validator for each constructed flash-data block; its packet bytes still match all three saved captures. Its conditional erase addresses remain descriptive evidence, not a validated physical erase guarantee.

## Preservation contract

A sector plan requires a native-checksum/anchor-valid 57,304-byte candidate and every one of the 98,304 saved pre-erase bytes at 8000..1FFFF. A 40,998-byte collateral-only file or an image missing the marker cannot meet this constructor contract. Inputs and returned data are copied to preserve ownership.

The desired pre-finalization image replaces only candidate calibration bytes. All 40,998 collateral bytes and the original two-byte marker are retained exactly from the supplied baseline; no gaps are filled with FF, zero or expected data. The original marker is reported separately. `AssessSavedReadback` delegates to the existing writer assessment, checking calibration, collateral and expected final 4AFC marker separately. That assessment does not mark a historical fixture as an independent physical backup.

Tests use an independently specified sector-start golden and existing native-checksum golden. They cover every sector's allow/reject result, overflow/alignment boundaries, omitted marker/extent, caller mutation, exact preservation and readback mismatch detection. The historical compiled-kernel replies also pass through the new sector plan and the production host assessment.

## Arrival of the spare TCM

The owner has ordered a spare, expected by the end of this week. On receipt, establish its label/service number, hardware compatibility, physical condition and verified harness/power requirements. Begin with identity and non-destructive baseline acquisition. Preserve all obtainable original bytes and record which regions remain unknown. Then review the RAM-entry/read-only-kernel qualification before considering any unchanged-calibration programming test.

No hardware operation is authorized or started by this document. Buying a spare does not establish a working recovery procedure. The installed truck TCM remains outside destructive qualification. Live upload, execution, writing, recovery verification and readiness flags remain false.

## Complete-baseline rehearsal provenance

`AL5OfflineProgrammingSession.FromSectorPlan` creates the abstract offline sequence from the immutable sector plan. It retains the complete pre-erase SHA-256 and original bytes; stopped-snapshot assessments retain the same digest. Explicit reconstruction carries that baseline into a new attempt while resetting progress and operation identities. Matching saved bytes never resume the stopped attempt. Existing collateral-only model constructors remain supported but expose no complete baseline and throw if asked to supply one.

The rehearsal validates every modeled calibration/collateral destination and the separate marker word against this policy. These checks still do not establish hardware mapping or transport authority. The historical compiled-reader fixture now passes through the full-baseline rehearsal, lost-reply assessment and fresh reconstruction path while preserving false readiness/recovery flags.
