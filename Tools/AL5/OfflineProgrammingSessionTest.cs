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
                Check(report.ExactSavedImageMatch && session.State == AL5OfflineRunState.Stopped,
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
            Check(old.AssessStoppedSnapshot(damaged).ObservedZeroToOneConflict, "Conflict lost");
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
        return passed;
    }
}
