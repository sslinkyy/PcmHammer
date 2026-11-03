# AL5: 30-point plan for a calibration writer candidate

Updated 2026-11-02 after the owner clarified that writing is the primary deliverable. Points 1-24 are writer implementation/validation; points 25-30 support the first bench write. Existing read evidence is reused. Reader expansion is limited to a demonstrated preservation prerequisite.

All work before arrival remains offline. Live upload, execution, erase/programming and automatic retries stay disabled. The spare starts physical qualification; it does not establish that qualification by arriving.

## Writer implementation: points 1-12

1. **Select the first writer profile.** Use the retained EFILive VPW 1x calibration sequence; keep SPS full programming separate.
2. **Pin the write loader.** Bind the exact captured 1,590-byte loader and its digest; reject substitutions.
3. **Validate custom BIN inputs.** Require the exact 57,304-byte calibration extent and family anchors; reject partial or ambiguous files.
4. **Validate native checksums.** Require CRC16/compensation and word-sum agreement; include a modified, checksum-correct BIN in rehearsal.
5. **Own the original reference.** Require an explicit full saved reference and retain its digest, including all 98,304 pre-erase bytes and the original marker.
6. **Enforce erase scope.** Allow only calibration sectors 0x8000 and 0x10000; reject chip erase and protected destinations.
7. **Construct every programming packet.** Build loader, erase, 192 contiguous data blocks and finalization from the selected inputs.
8. **Represent programming entry.** Join setup, boot request/reply, loader upload and loader identity in one state machine; keep entry side effects explicit.
9. **Separate fresh security from captured keys.** Stop action construction at the dynamic key boundary until current controller/profile authorization is qualified.
10. **Generate fixed setup commands.** Derive them from the same owned rules used for saved-response validation, rather than duplicating a second protocol table.
11. **Validate loader identity.** Require the selected profile's expected reply before permitting the erase phase in rehearsal.
12. **Validate erase completion.** Negative, missing or ambiguous completion cannot advance programming or authorize an automatic retry.

## Writer failure handling and verification: points 13-24

13. **Enforce block ordering and ownership.** Keep one pending block, exact destination/count/data and a single successful advancement.
14. **Classify checksum replies.** Distinguish the observed checksum rejection from positive completion and fatal statuses.
15. **Expose explicit retry review.** Return only the retained checksum-rejected packet; do not turn timeout or a lost acknowledgement into retry authority.
16. **Track ambiguous retransmission.** Retain captured repeats without replies as uncertainty, not proof of a safe live retry rule.
17. **Exercise interruption boundaries.** Stop at every pending data block and each lifecycle phase; stopped attempts cannot resume.
18. **Restore collateral bytes.** Construct their programming data from the explicit baseline and test mismatched collateral independently of calibration.
19. **Separate completion-marker finalization.** Issue the observed finalization only after acknowledged programming; check the marker independently in readback.
20. **Complete cleanup handling.** Generate fixed cleanup requests, validate recorded responses and distinguish cleanup rejection from programming success.
21. **Require complete saved readback.** Calibration-only readback and positive acknowledgements cannot complete full preservation comparison.
22. **Check outside the erase sectors.** Report persistent-bank changes separately from other protected-region changes; unexplained preparation changes do not silently pass.
23. **Export a reviewable candidate.** Save input hashes, generated packets, expected bytes, rehearsal state and remaining hardware gates without opening an adapter.
24. **Build and test PcmHammer integration.** Compile the shared candidate into PcmHammer and verify the real write gate still rejects AL5 before vehicle access.

## Have the bench session ready: points 25-30

25. **Finish only required backup preparation.** Record known coverage and the pre-entry persistent-bank acquisition blocker; do not start another broad reader-development cycle.
26. **Qualify capture cleanup now.** Test USBPcap clean stop and failure cleanup offline; prepare current-topology verification for arrival.
27. **Freeze the bench package.** Include the built app, offline writer tool, source snapshot, results, capture helpers and hashes. Arrival-day verification checks hashes without rerunning long emulations.
28. **Prepare intake and wiring.** Match the arriving spare's actual identity and use matching service pinout information before power; do not guess connector feeds.
29. **Prepare the first-write procedure.** Stage identity/backup checks, separately reviewed entry qualification, unchanged-calibration programming and independent readback, with exact stop conditions.
30. **Prepare recovery qualification.** List available vendor/boot/external-flash options, equipment and missing proof; interruption experiments remain separate from the first unchanged write.

## Current software continuation

The [dispatch checkpoint](WRITER_DISPATCH_CHECKPOINT_20261102.md) implements send/reply ownership, fixed qualification boundaries, saved-profile matching, explicit timeout budgets and production Vehicle/GT integration tests through a scripted port. TCM Hammer includes a file-only write preparation/export command. Live operations remain disabled; no physical qualification gate is marked complete by this work.

## Exit condition

A built offline writer candidate and frozen qualification packet must exist before delivery. Physical questions remain named gates. No routine hours-long offline rerun is scheduled for arrival; a spare mismatch, observed failure or source change triggers only the relevant investigation/checks. The installed truck TCM is not the experimental target.

See [writer candidate](CALIBRATION_WRITE_CANDIDATE.md), [qualification evidence](WRITE_QUALIFICATION_PLAN.md), [sector policy](CALIBRATION_SECTOR_POLICY.md), and [spare qualification gates](SPARE_TCM_BENCH_QUALIFICATION.md).
