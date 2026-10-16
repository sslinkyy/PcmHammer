// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.Linq;
using PcmHacking;

internal static class ProgrammingWorkflowTest
{
    private static void Check(bool condition, string reason)
    { if (!condition) throw new Exception(reason); }

    private static void Blocked(AL5ProgrammingAssessment report)
    {
        Check(!report.LiveWriteEnabled && !report.AutomaticRetryEnabled && !report.ReadyToFlash &&
            !report.PhysicalReadbackVerified && !report.PhysicalEraseGeometryVerified && !report.RecoveryVerified,
            "Offline model granted physical authority");
        Check(report.LastOperationSucceeded == null && report.LoaderSessionReusable == null,
            "Flash files inferred operation or CPU/session state");
    }

    public static int Run(Func<byte[]> fixture)
    {
        int passed = 0;
        void Test(string name, Action action) { action(); passed++; Console.WriteLine("PASS AL5 workflow: " + name); }
        byte[] candidate = fixture();
        byte[] backup = Enumerable.Repeat((byte)0xA5, AL5ProgrammingWorkflow.CollateralLength).ToArray();
        byte[] snapshot = new byte[AL5ProgrammingWorkflow.SnapshotLength];
        Array.Copy(candidate, snapshot, candidate.Length);
        Array.Copy(backup, 0, snapshot, candidate.Length, backup.Length);
        snapshot[snapshot.Length-2] = 0x4A;
        snapshot[snapshot.Length-1] = 0xFC;

        Test("phase order, ranges and bounded dense block counts", () =>
        {
            var report = AL5ProgrammingWorkflow.Assess(candidate);
            Check(report.RetryAssessment == AL5RetryAssessment.SnapshotRequired, "Absent readback inferred success");
            Check(report.Stages.Select(s => s.Phase).SequenceEqual(new[] {
                AL5ProgrammingPhase.BootAndLoaderEntry, AL5ProgrammingPhase.ConditionalErase,
                AL5ProgrammingPhase.CalibrationBlocks, AL5ProgrammingPhase.CollateralRestoration,
                AL5ProgrammingPhase.Finalization, AL5ProgrammingPhase.IndependentVerification }), "Wrong stage order");
            Check(report.Stages[2].ModeledBlockCount == 224 && report.Stages[3].ModeledBlockCount == 161,
                "Partial final blocks lost");
            Check(report.Stages[2].EndAddressExclusive == report.Stages[3].StartAddress &&
                report.Stages[3].EndAddressExclusive == report.Stages[4].StartAddress &&
                report.Stages[4].EndAddressExclusive == 0x20000, "Coverage overlap or gap");
            Blocked(report);
        });
        Test("complete saved image never authorizes retry or session reuse", () =>
        {
            var report = AL5ProgrammingWorkflow.Assess(candidate, snapshot, backup);
            Check(report.ExactSavedImageMatch && report.RetryAssessment == AL5RetryAssessment.SavedImageMatches,
                "Exact saved image lost");
            Check(report.Calibration!.MatchingWords == 28652 && report.Collateral!.MatchingWords == 20499,
                "Word coverage wrong");
            Blocked(report);
        });
        Test("backup loss remains unknown, independently of matching calibration", () =>
        {
            var report = AL5ProgrammingWorkflow.Assess(candidate, snapshot);
            Check(report.Calibration!.ExactMatch && report.Collateral == null && !report.ExactSavedImageMatch &&
                report.RetryAssessment == AL5RetryAssessment.CollateralBaselineRequired, "Missing backup inferred");
            Blocked(report);
        });
        Test("partial block arithmetic differs from extra cleared bits", () =>
        {
            byte[] partial = (byte[])snapshot.Clone();
            partial[0x1000] = 0xFF; partial[0x1001] = 0xFF; // Desired fixture word is zero.
            var report = AL5ProgrammingWorkflow.Assess(candidate, partial, backup);
            Check(report.RetryAssessment == AL5RetryAssessment.ClearOnlyDifferences &&
                report.Calibration!.AdditionalClearWords == 1, "Partial word classified incorrectly");
            // Desired anchor word is 0x00E7: a cleared low bit cannot be restored by a word retry.
            partial[0x25] = 0xE6;
            report = AL5ProgrammingWorkflow.Assess(candidate, partial, backup);
            Check(report.RetryAssessment == AL5RetryAssessment.ZeroToOneConflict &&
                report.Calibration!.FirstRequiresSetAddress == 0x8024, "Conflicting retry permitted");
            Blocked(report);
        });
        Test("marker and collateral independently affect disposition", () =>
        {
            byte[] partial = (byte[])snapshot.Clone();
            partial[partial.Length-2] = partial[partial.Length-1] = 0xFF;
            var report = AL5ProgrammingWorkflow.Assess(candidate, partial, backup);
            Check(report.Calibration!.ExactMatch && report.Collateral!.ExactMatch &&
                !report.CompletionMarker!.ExactMatch && report.RetryAssessment == AL5RetryAssessment.ClearOnlyDifferences,
                "Marker hidden behind calibration checksum");
            partial[candidate.Length] = 0;
            report = AL5ProgrammingWorkflow.Assess(candidate, partial, backup);
            Check(report.Collateral!.FirstRequiresSetAddress == 0x15FD8 &&
                report.RetryAssessment == AL5RetryAssessment.ZeroToOneConflict, "Collateral conflict hidden");
            Blocked(report);
        });
        Test("invalid calibration never yields a programming layout", () =>
        {
            foreach (byte[] invalid in new[] { new byte[0], new byte[1048576], new byte[candidate.Length] })
            {
                var report = AL5ProgrammingWorkflow.Assess(invalid, snapshot, backup);
                Check(report.RetryAssessment == AL5RetryAssessment.InvalidCandidate && report.Stages.Count == 0 &&
                    report.Calibration == null && report.CompletionMarker == null, "Invalid candidate produced a plan");
                Blocked(report);
            }
        });
        Test("malformed saved ranges fail before comparison", () =>
        {
            foreach (bool badSnapshot in new[] { false, true })
            {
                bool rejected = false;
                try { AL5ProgrammingWorkflow.Assess(candidate, badSnapshot ? new byte[2] : snapshot,
                    badSnapshot ? backup : new byte[2]); }
                catch (ArgumentException) { rejected = true; }
                Check(rejected, "Malformed range accepted");
            }
        });
        Test("reports own facts and immutable stage collections", () =>
        {
            byte[] current = (byte[])snapshot.Clone(), original = (byte[])backup.Clone(), edited = fixture();
            var report = AL5ProgrammingWorkflow.Assess(edited, current, original);
            string? hash = report.SnapshotSha256;
            current[0] ^= 1; original[0] ^= 1; edited[0] ^= 1;
            Check(report.ExactSavedImageMatch && report.SnapshotSha256 == hash && report.Candidate.ChecksPass,
                "Report retained mutable caller buffers");
            bool rejected = false;
            try { ((IList<AL5ProgrammingStage>)report.Stages).Clear(); }
            catch (NotSupportedException) { rejected = true; }
            Check(rejected, "Stage list mutable");
        });
        return passed;
    }
}
