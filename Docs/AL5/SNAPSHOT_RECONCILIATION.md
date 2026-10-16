# Offline AL5 snapshot reconciliation

`Tools/AL5/reconcile_al5_snapshot.py` compares a saved conditional flash snapshot
against a validated calibration and an optional independent collateral backup.
It produces a new JSON report; it cannot open an adapter or construct packets.
`write_plan.py` includes its implementation digest in the recovery assessment.

This moves the interruption findings into host-side decision logic. A lost reply
does not establish failure. A saved byte comparison can distinguish a completed
region, remaining one-to-zero differences, and differences that would require
setting cleared bits. The last category rules out simply repeating a word write
under the current flash model. None of these classifications authorizes a retry,
an erase, or continued use of the loader session.

Inputs are deliberately narrow:

- Candidate: exactly 57,304 bytes at `0x8000..0x15FD8`, passing existing layout
  anchors and the native CRC/sum field check.
- Optional snapshot: exactly 98,304 bytes at `0x8000..0x20000`. This range follows
  the conditional model's two sectors; physical geometry remains unverified.
- Optional collateral backup: exactly 40,998 bytes at `0x15FD8..0x1FFFE`, saved
  independently before erase. The tool cannot establish when a supplied file was
  captured or which physical controller it belongs to.

The final marker at `0x1FFFE` is compared separately against `4AFC`. Missing
snapshot or backup remains unknown. Matching calibration alone does not establish
matching collateral or a completion marker. `exact_saved_image_match` requires
all three comparisons to match, and remains a statement about supplied files.

Every supplied file requires its SHA256 pin. For example, from `Tools/AL5`:

```powershell
python reconcile_al5_snapshot.py --candidate candidate.bin --candidate-sha256 <SHA256> --snapshot snapshot_08000_1ffff.bin --snapshot-sha256 <SHA256> --collateral-backup collateral_15fd8_1fffd.bin --collateral-backup-sha256 <SHA256> --output reconciliation.json
```

The report retains absolute input paths, digests, word counts and the first
zero-to-one conflict address. It contains no source bytes, retry payloads or
executable plan. Existing output is preserved. Input reads are bounded before
allocation and lengths are checked before comparison.

The tool deliberately accepts no acknowledgement, controller identity or
session-state assertion as a substitute for a current physical readback. It
always reports operation outcome and loader state as unknown, requires fresh
controller/session qualification, and leaves automatic retry, physical recovery,
live writes and `ready_to_flash` false. Matching bytes cannot reveal pending
stack frames retained by native errors.

Validation combines public file-only CLI tests with original-instruction model
snapshots for a lost acknowledgement, partial block and extra cleared bit. Those
model tests establish consistency with the existing conditional emulator; they
do not qualify physical programming, reset, readback or recovery.

Validation on 2026-10-15: all 11 reconciliation tests passed, including the native
snapshot comparisons and blocked planner integration. The broader regression run
reported 365 tests and two setup errors when existing integrated native groups
exhausted their execution budgets during finalization. Both affected groups
passed separately (23 tests) without changes to their code or budgets. This is
not a claim of a clean single full-suite run. No physical interfaces were used.
