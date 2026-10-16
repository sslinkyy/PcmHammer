// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Linq;
using PcmHacking;

internal static class OfflineProgrammingSessionTest
{
    private static void Check(bool condition, string reason)
    { if (!condition) throw new Exception(reason); }

    private static void Reject(Action action)
    {
        try { action(); }
        catch (ArgumentException) { return; }
        catch (InvalidOperationException) { return; }
        throw new Exception("Invalid transition accepted");
    }

    private static void Blocked(AL5OfflineProgrammingSession session)
    {
        Check(!session.LiveWriteEnabled && !session.AutomaticRetryEnabled && !session.ReadyToFlash &&
            !session.RecoveryVerified && session.PhysicalOperationSucceeded == null && session.LoaderSessionReusable == null,
            "Model sequence conferred physical authority");
    }

    public static int Run(Func<byte[]> fixture)
    {
        byte[] image = fixture();
        byte[] backup = Enumerable.Repeat((byte)0xA5, AL5ProgrammingWorkflow.CollateralLength).ToArray();
        byte[] snapshot = image.Concat(backup).Concat(new byte[] { 0x4A, 0xFC }).ToArray();
        AL5OfflineProgrammingSession New() => new AL5OfflineProgrammingSession(image, backup);
        void Reach(AL5OfflineProgrammingSession session, AL5ProgrammingPhase phase)
        {
            while (session.PendingOperation!.Phase != phase)
                session.RecordModelOutcome(session.PendingOperation, AL5OfflineOutcome.ModelCompleted);
        }
        int passed = 0;
        void Test(string name, Action action) { action(); passed++; Console.WriteLine("PASS AL5 sequence: " + name); }

        Test("dense blocks cover exact ranges including short tails", () =>
        {
            var session = New();
            Check(session.Operations.Count == 389, "Incorrect modeled operation count");
            foreach (var region in new[] {
                new { Phase = AL5ProgrammingPhase.CalibrationBlocks, Start = 0x8000, End = 0x15FD8, Tail = 216 },
                new { Phase = AL5ProgrammingPhase.CollateralRestoration, Start = 0x15FD8, End = 0x1FFFE, Tail = 38 } })
            {
                var blocks = session.Operations.Where(o => o.Phase == region.Phase).ToArray();
                int next = region.Start;
                foreach (var block in blocks)
                {
                    Check(block.StartAddress == next && block.Length > 0 && block.Length <= 256 && block.Length % 2 == 0,
                        "Block overlap, hole or invalid word length");
                    next += block.Length!.Value;
                }
                Check(next == region.End && blocks.Last().Length == region.Tail, "Tail or end wrong");
            }
            Check(session.Operations.Select(o => o.Sequence).SequenceEqual(Enumerable.Range(1, 389)), "Ordinals incorrect");
            Blocked(session);
        });
        Test("model success requires separate saved verification", () =>
        {
            var session = New();
            Reach(session, AL5ProgrammingPhase.IndependentVerification);
            Check(session.State == AL5OfflineRunState.AwaitingSavedVerification && session.Observations.Count == 388,
                "Model completion elevated into verification");
            Reject(() => session.RecordModelOutcome(session.PendingOperation!, AL5OfflineOutcome.ModelCompleted));
            Reject(() => session.RecordModelOutcome(session.PendingOperation!, AL5OfflineOutcome.SavedVerificationMatched));
            var report = session.RecordSavedVerification(session.PendingOperation!, snapshot);
            Check(report.ExactSavedImageMatch && session.State == AL5OfflineRunState.SavedImageVerified &&
                session.PendingOperation == null && session.Observations.Count == 389, "Saved verification failed");
            Check(session.Observations.Last().SnapshotSha256 == report.SnapshotSha256, "Verification evidence lost");
            Reject(() => session.RecordModelOutcome(session.Operations.Last(), AL5OfflineOutcome.ModelCompleted));
            Blocked(session);
        });
        Test("stale, out-of-order and foreign-attempt results leave cursor unchanged", () =>
        {
            var session = New();
            var first = session.PendingOperation!;
            Reject(() => session.RecordModelOutcome(session.Operations[1], AL5OfflineOutcome.ModelCompleted));
            Reject(() => session.RecordModelOutcome(New().PendingOperation!, AL5OfflineOutcome.ModelCompleted));
            Reject(() => session.RecordModelOutcome(first, (AL5OfflineOutcome)999));
            Reject(() => session.RecordSavedVerification(first, snapshot));
            Check(session.Observations.Count == 0 && session.PendingOperation == first, "Rejected event changed journal");
            session.RecordModelOutcome(first, AL5OfflineOutcome.ModelCompleted);
            Reject(() => session.RecordModelOutcome(first, AL5OfflineOutcome.ModelCompleted));
            Check(session.Observations.Count == 1 && session.PendingOperation!.Sequence == 2, "Duplicate advanced cursor");
        });
        Test("all ambiguous outcomes stop every stage without retry", () =>
        {
            foreach (AL5ProgrammingPhase phase in Enum.GetValues(typeof(AL5ProgrammingPhase)))
            foreach (var outcome in new[] { AL5OfflineOutcome.ReplyLost, AL5OfflineOutcome.ModelFailure,
                AL5OfflineOutcome.Interrupted, AL5OfflineOutcome.Cancelled, AL5OfflineOutcome.UnconfirmedModelResult })
            {
                var session = New();
                Reach(session, phase);
                var pending = session.PendingOperation!;
                session.RecordModelOutcome(pending, outcome);
                Check(session.State == AL5OfflineRunState.Stopped && session.PendingOperation == pending &&
                    session.Observations.Last().Outcome == outcome, "Ambiguous result advanced or disappeared");
                var report = session.AssessStoppedSnapshot(snapshot);
                Check(report.ImageAssessment.ExactSavedImageMatch && session.State == AL5OfflineRunState.Stopped,
                    "Matching file resumed stopped session");
                Reject(() => session.RecordModelOutcome(pending, AL5OfflineOutcome.ModelCompleted));
                Reject(() => session.RecordSavedVerification(pending, snapshot));
                Blocked(session);
            }
        });
        Test("verification rejects calibration, collateral and marker damage independently", () =>
        {
            foreach (int offset in new[] { 0x1000, image.Length, snapshot.Length-1 })
            {
                byte[] damaged = (byte[])snapshot.Clone(); damaged[offset] ^= 1;
                var session = New(); Reach(session, AL5ProgrammingPhase.IndependentVerification);
                var report = session.RecordSavedVerification(session.PendingOperation!, damaged);
                Check(!report.ExactSavedImageMatch && session.State == AL5OfflineRunState.Stopped &&
                    session.Observations.Last().Outcome == AL5OfflineOutcome.SavedVerificationFailed, "Damaged region accepted");
                Blocked(session);
            }
        });
        Test("malformed verification has no event or state effect", () =>
        {
            var session = New(); Reach(session, AL5ProgrammingPhase.IndependentVerification);
            Reject(() => session.RecordSavedVerification(session.PendingOperation!, new byte[2]));
            Check(session.State == AL5OfflineRunState.AwaitingSavedVerification && session.Observations.Count == 388,
                "Invalid evidence changed state");
        });
        Test("reconstruction is a separate explicit attempt with fresh operation identities", () =>
        {
            var old = New(); Reach(old, AL5ProgrammingPhase.CalibrationBlocks);
            old.RecordModelOutcome(old.PendingOperation!, AL5OfflineOutcome.Interrupted);
            byte[] damaged = (byte[])snapshot.Clone(); damaged[0x25] &= 0xFE;
            Check(old.AssessStoppedSnapshot(damaged).ImageAssessment.ObservedZeroToOneConflict, "Conflict lost");
            var fresh = New();
            Check(fresh.PendingOperation!.Phase == AL5ProgrammingPhase.BootAndLoaderEntry && fresh.Observations.Count == 0,
                "New attempt inherited old progress");
            Reject(() => fresh.RecordModelOutcome(old.PendingOperation!, AL5OfflineOutcome.ModelCompleted));
            Check(old.State == AL5OfflineRunState.Stopped, "New attempt reopened old session");
            Blocked(fresh);
        });
        Test("candidate/baseline ownership and journal snapshots remain immutable", () =>
        {
            byte[] edited = fixture(), baseline = (byte[])backup.Clone();
            var session = new AL5OfflineProgrammingSession(edited, baseline);
            var emptyJournal = session.Observations;
            edited[0] ^= 1; baseline[0] ^= 1;
            Reach(session, AL5ProgrammingPhase.IndependentVerification);
            Check(emptyJournal.Count == 0 && session.RecordSavedVerification(session.PendingOperation!, snapshot).ExactSavedImageMatch,
                "Mutable inputs or journal altered recorded facts");
        });
        Test("invalid inputs cannot start a reconstruction attempt", () =>
        {
            Reject(() => new AL5OfflineProgrammingSession(new byte[image.Length], backup));
            Reject(() => new AL5OfflineProgrammingSession(image, new byte[2]));
            Reject(() => new AL5OfflineProgrammingSession(image, null!));
        });
        AL5OfflineProgrammingSession Stopped(AL5ProgrammingPhase phase)
        {
            var session = New(); Reach(session, phase);
            session.RecordModelOutcome(session.PendingOperation!, AL5OfflineOutcome.ReplyLost);
            return session;
        }
        Test("lost-ACK block match remains distinct from complete image verification", () =>
        {
            var session = New(); Reach(session, AL5ProgrammingPhase.CalibrationBlocks);
            var decision = session.RecordLoaderModelResult(session.PendingOperation!, new AL5LoaderModelResult(
                Convert.FromHexString("760073"), AL5ModeledSenderState.TimedOutWithSoftwareReentry, 0, 0x8000, 256));
            byte[] partial = Enumerable.Repeat((byte)0xFF, snapshot.Length).ToArray();
            Array.Copy(image, 0, partial, 0, 256);
            var report = session.AssessStoppedSnapshot(partial);
            Check(report.Disposition == AL5PendingRangeDisposition.SavedRangeMatches &&
                report.PendingRangeComparison!.MatchingWords == 128 && !report.ImageAssessment.ExactSavedImageMatch,
                "Block and whole image outcomes conflated");
            Check(report.Operation == session.PendingOperation && !report.RetryEnabled && !report.CanResumeStoppedSession &&
                !report.PhysicalReadbackVerified && session.State == AL5OfflineRunState.Stopped, "Range match resumed attempt");
            Check(report.StopObservation.Outcome == AL5OfflineOutcome.ReplyLost &&
                ReferenceEquals(report.StopObservation.LoaderDecision, decision), "Lost-ACK provenance not bound to reconciliation");
        });
        Test("partial and overprogrammed pending block states differ", () =>
        {
            var session = Stopped(AL5ProgrammingPhase.CalibrationBlocks);
            byte[] partial = Enumerable.Repeat((byte)0xFF, snapshot.Length).ToArray();
            Array.Copy(image, 0, partial, 0, 2);
            var report = session.AssessStoppedSnapshot(partial);
            Check(report.Disposition == AL5PendingRangeDisposition.ClearOnlyDifferences &&
                report.PendingRangeComparison!.AdditionalClearWords == 127, "Partial block arithmetic wrong");
            partial[0x25] = 0xE6; // Desired anchor low byte is E7.
            report = session.AssessStoppedSnapshot(partial);
            Check(report.Disposition == AL5PendingRangeDisposition.ZeroToOneConflict &&
                report.PendingRangeComparison!.FirstRequiresSetAddress == 0x8024, "Extra cleared bit lost");
            Blocked(session);
        });
        Test("short final calibration and collateral blocks compare only their own words", () =>
        {
            foreach (var phase in new[] { AL5ProgrammingPhase.CalibrationBlocks, AL5ProgrammingPhase.CollateralRestoration })
            {
                var session = New(); Reach(session, phase);
                while (session.PendingOperation!.Length == 256)
                    session.RecordModelOutcome(session.PendingOperation, AL5OfflineOutcome.ModelCompleted);
                var pending = session.PendingOperation!;
                session.RecordModelOutcome(pending, AL5OfflineOutcome.Interrupted);
                byte[] partial = (byte[])snapshot.Clone();
                int offset = pending.StartAddress!.Value - 0x8000;
                partial[offset-1] ^= 1; // Outside this block: full-image mismatch, range still matches.
                var report = session.AssessStoppedSnapshot(partial);
                Check(report.PendingRangeComparison!.MatchingWords == pending.Length/2 &&
                    report.Disposition == AL5PendingRangeDisposition.SavedRangeMatches && !report.ImageAssessment.ExactSavedImageMatch,
                    "Short block compared adjacent bytes");
                partial[offset+pending.Length!.Value-1] &= 0xFE;
                report = session.AssessStoppedSnapshot(partial);
                Check(report.Disposition == AL5PendingRangeDisposition.ZeroToOneConflict &&
                    report.PendingRangeComparison!.FirstRequiresSetAddress == pending.StartAddress+pending.Length-2,
                    "Final word omitted from short block");
            }
        });
        Test("erase comparison expects erased bytes, not the candidate image", () =>
        {
            var session = Stopped(AL5ProgrammingPhase.ConditionalErase);
            byte[] erased = Enumerable.Repeat((byte)0xFF, snapshot.Length).ToArray();
            var report = session.AssessStoppedSnapshot(erased);
            Check(report.Disposition == AL5PendingRangeDisposition.SavedRangeMatches &&
                report.PendingRangeComparison!.MatchingWords == 49152 && !report.ImageAssessment.ExactSavedImageMatch,
                "Erase expected target wrong");
            erased[erased.Length-1] = 0xFE;
            report = session.AssessStoppedSnapshot(erased);
            Check(report.Disposition == AL5PendingRangeDisposition.ZeroToOneConflict &&
                report.PendingRangeComparison!.FirstRequiresSetAddress == 0x1FFFE, "Erase scope excluded marker");
        });
        Test("boot has no flash outcome and marker match cannot verify the full image", () =>
        {
            var boot = Stopped(AL5ProgrammingPhase.BootAndLoaderEntry).AssessStoppedSnapshot(snapshot);
            Check(boot.Disposition == AL5PendingRangeDisposition.NoFlashRange && boot.PendingRangeComparison == null,
                "Flash bytes inferred boot/loader entry");
            byte[] damaged = (byte[])snapshot.Clone(); damaged[0x25] &= 0xFE;
            var final = Stopped(AL5ProgrammingPhase.Finalization).AssessStoppedSnapshot(damaged);
            Check(final.Disposition == AL5PendingRangeDisposition.SavedRangeMatches &&
                final.PendingRangeComparison!.MatchingWords == 1 && !final.ImageAssessment.ExactSavedImageMatch,
                "Marker match hid calibration damage");
            var verify = Stopped(AL5ProgrammingPhase.IndependentVerification).AssessStoppedSnapshot(damaged);
            Check(verify.Disposition == AL5PendingRangeDisposition.ZeroToOneConflict &&
                verify.PendingRangeComparison!.FirstRequiresSetAddress == 0x8024, "Verification did not compare complete range");
        });
        Test("stopped range reconciliation preserves journal and immutable snapshot facts", () =>
        {
            var session = Stopped(AL5ProgrammingPhase.CalibrationBlocks);
            int count = session.Observations.Count;
            Reject(() => session.AssessStoppedSnapshot(new byte[2]));
            byte[] current = (byte[])snapshot.Clone();
            var report = session.AssessStoppedSnapshot(current);
            string? hash = report.ImageAssessment.SnapshotSha256;
            current[0] ^= 1;
            Check(report.PendingRangeComparison!.ExactMatch && report.ImageAssessment.SnapshotSha256 == hash &&
                session.Observations.Count == count && session.State == AL5OfflineRunState.Stopped,
                "Reconciliation modified journal or retained mutable bytes");
            Reject(() => New().AssessStoppedSnapshot(snapshot));
        });
        Test("explicit reconstruction starts fresh and binds the chosen source evidence", () =>
        {
            var old = Stopped(AL5ProgrammingPhase.CalibrationBlocks);
            var source = old.AssessStoppedSnapshot(snapshot);
            int oldCount = old.Observations.Count;
            var fresh = old.CreateReconstructionRehearsal(source);
            Check(ReferenceEquals(fresh.ReconstructionSource, source) && fresh.Observations.Count == 0 &&
                fresh.PendingOperation!.Phase == AL5ProgrammingPhase.BootAndLoaderEntry && fresh.PendingOperation.Sequence == 1 &&
                fresh.Operations.Count == 389, "Reconstruction inherited progress or lost source");
            Check(fresh.Assessment.Candidate.Sha256 == old.Assessment.Candidate.Sha256 &&
                fresh.Assessment.CollateralBackupSha256 == source.ImageAssessment.CollateralBackupSha256,
                "Reconstruction changed candidate or baseline identity");
            fresh.RecordModelOutcome(fresh.PendingOperation!, AL5OfflineOutcome.ModelCompleted);
            Check(fresh.PendingOperation!.Phase == AL5ProgrammingPhase.ConditionalErase &&
                old.State == AL5OfflineRunState.Stopped && old.Observations.Count == oldCount, "New attempt resumed old attempt or skipped erase");
            Reject(() => fresh.RecordModelOutcome(old.PendingOperation!, AL5OfflineOutcome.ModelCompleted));
            Blocked(old); Blocked(fresh);
        });
        Test("foreign reconciliation cannot seed a reconstruction", () =>
        {
            var old = Stopped(AL5ProgrammingPhase.CalibrationBlocks);
            var other = Stopped(AL5ProgrammingPhase.CalibrationBlocks);
            Reject(() => old.CreateReconstructionRehearsal(other.AssessStoppedSnapshot(snapshot)));
            Reject(() => old.CreateReconstructionRehearsal(null!));
            Check(old.State == AL5OfflineRunState.Stopped, "Rejected source changed attempt");
        });
        Test("active and completed attempts cannot prepare reconstruction", () =>
        {
            var source = Stopped(AL5ProgrammingPhase.CalibrationBlocks).AssessStoppedSnapshot(snapshot);
            var active = New();
            Reject(() => active.CreateReconstructionRehearsal(source));
            Reach(active, AL5ProgrammingPhase.IndependentVerification);
            active.RecordSavedVerification(active.PendingOperation!, snapshot);
            Reject(() => active.CreateReconstructionRehearsal(source));
            Check(active.State == AL5OfflineRunState.SavedImageVerified, "Completed attempt changed");
        });
        Test("reconstruction requires retained baseline independently of flash snapshots", () =>
        {
            var old = Stopped(AL5ProgrammingPhase.CalibrationBlocks);
            byte[] changed = (byte[])snapshot.Clone(); changed[0x25] &= 0xFE;
            var earlier = old.AssessStoppedSnapshot(changed);
            var later = old.AssessStoppedSnapshot(snapshot);
            var fresh = old.CreateReconstructionRehearsal(earlier);
            Check(fresh.ReconstructionSource!.ImageAssessment.SnapshotSha256 != later.ImageAssessment.SnapshotSha256 &&
                fresh.ReconstructionSource.ImageAssessment.ObservedZeroToOneConflict,
                "Caller-selected reconciliation evidence was replaced");
            Reject(() => new AL5OfflineProgrammingSession(image, Array.Empty<byte>()));
            Blocked(fresh);
        });
        return passed;
    }
}
