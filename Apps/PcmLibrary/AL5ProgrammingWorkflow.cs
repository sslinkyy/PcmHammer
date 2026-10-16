// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Security.Cryptography;

namespace PcmHacking
{
    /// <summary>Conditional offline model only. No Vehicle, adapter, packets or execution callbacks.</summary>
    public static class AL5ProgrammingWorkflow
    {
        public const int SnapshotEndExclusive = 0x20000;
        public const int MarkerAddress = 0x1FFFE;
        public const int SnapshotLength = SnapshotEndExclusive - AL5CalibrationInspection.StartAddress;
        public const int CollateralLength = MarkerAddress - AL5CalibrationInspection.EndAddressExclusive;
        public const int ModeledBlockBytes = 256; // Experiment bound, not a proven protocol maximum.

        public static AL5ProgrammingAssessment Assess(byte[] candidate, byte[]? snapshot = null, byte[]? collateralBackup = null)
        {
            if (candidate == null) throw new ArgumentNullException(nameof(candidate));
            if (snapshot != null && snapshot.Length != SnapshotLength)
                throw new ArgumentException("Expected exactly 98,304 saved bytes at 0x8000.", nameof(snapshot));
            if (collateralBackup != null && collateralBackup.Length != CollateralLength)
                throw new ArgumentException("Expected exactly 40,998 pre-erase collateral bytes at 0x15FD8.", nameof(collateralBackup));
            // Own snapshots for the whole assessment; never retain caller-owned mutable buffers.
            byte[]? image = candidate.Length == AL5CalibrationInspection.Length ? (byte[])candidate.Clone() : null;
            byte[]? observed = snapshot == null ? null : (byte[])snapshot.Clone();
            byte[]? backup = collateralBackup == null ? null : (byte[])collateralBackup.Clone();
            AL5CalibrationFileReport file = AL5CalibrationInspection.Inspect(image ?? candidate);
            var stages = new List<AL5ProgrammingStage>();
            AL5WordComparison? calibration = null, collateral = null, marker = null;
            // Unsupported candidates yield file errors, never a programming layout or retry comparison.
            if (file.ChecksPass && image != null)
            {
                stages.Add(new AL5ProgrammingStage(AL5ProgrammingPhase.BootAndLoaderEntry, null, null, 0));
                stages.Add(new AL5ProgrammingStage(AL5ProgrammingPhase.ConditionalErase, 0x8000, SnapshotEndExclusive, 0));
                stages.Add(new AL5ProgrammingStage(AL5ProgrammingPhase.CalibrationBlocks,
                    AL5CalibrationInspection.StartAddress, AL5CalibrationInspection.EndAddressExclusive,
                    Blocks(AL5CalibrationInspection.Length)));
                stages.Add(new AL5ProgrammingStage(AL5ProgrammingPhase.CollateralRestoration,
                    AL5CalibrationInspection.EndAddressExclusive, MarkerAddress, Blocks(CollateralLength)));
                stages.Add(new AL5ProgrammingStage(AL5ProgrammingPhase.Finalization, MarkerAddress, SnapshotEndExclusive, 0));
                stages.Add(new AL5ProgrammingStage(AL5ProgrammingPhase.IndependentVerification,
                    AL5CalibrationInspection.StartAddress, SnapshotEndExclusive, 0));
                if (observed != null)
                {
                    calibration = CompareWords(observed, 0, image, 0, image.Length, AL5CalibrationInspection.StartAddress);
                    if (backup != null)
                        collateral = CompareWords(observed, image.Length, backup, 0, backup.Length, AL5CalibrationInspection.EndAddressExclusive);
                    marker = CompareWords(observed, SnapshotLength - 2, new byte[] { 0x4A, 0xFC }, 0, 2, MarkerAddress);
                }
            }
            return new AL5ProgrammingAssessment(file, stages, calibration, collateral, marker,
                observed == null ? null : Hash(observed), backup == null ? null : Hash(backup));
        }

        private static int Blocks(int count) => (count + ModeledBlockBytes - 1) / ModeledBlockBytes;

        private static string Hash(byte[] data)
        {
            using (SHA256 sha = SHA256.Create())
                return BitConverter.ToString(sha.ComputeHash(data)).Replace("-", "").ToLowerInvariant();
        }

        internal static AL5WordComparison CompareWords(byte[] observed, int offset, byte[] desired, int desiredOffset, int count, int address)
        {
            int matching = 0, clear = 0, set = 0;
            int? first = null;
            for (int index = 0; index < count; index += 2)
            {
                int actual = (observed[offset+index] << 8) | observed[offset+index+1];
                int target = (desired[desiredOffset+index] << 8) | desired[desiredOffset+index+1];
                if (actual == target) matching++;
                else if ((actual & target) == target) clear++;
                else { set++; if (!first.HasValue) first = address+index; }
            }
            return new AL5WordComparison(matching, clear, set, first);
        }
    }

    public enum AL5ProgrammingPhase
    {
        BootAndLoaderEntry, ConditionalErase, CalibrationBlocks, CollateralRestoration,
        Finalization, IndependentVerification
    }

    public enum AL5RetryAssessment
    {
        InvalidCandidate, SnapshotRequired, ZeroToOneConflict, CollateralBaselineRequired,
        SavedImageMatches, ClearOnlyDifferences
    }

    public sealed class AL5ProgrammingStage
    {
        internal AL5ProgrammingStage(AL5ProgrammingPhase phase, int? start, int? end, int blocks)
        { Phase = phase; StartAddress = start; EndAddressExclusive = end; ModeledBlockCount = blocks; }
        public AL5ProgrammingPhase Phase { get; }
        public int? StartAddress { get; }
        public int? EndAddressExclusive { get; }
        public int ModeledBlockCount { get; }
    }

    public sealed class AL5WordComparison
    {
        internal AL5WordComparison(int matching, int clear, int set, int? first)
        { MatchingWords = matching; AdditionalClearWords = clear; RequiresSetWords = set; FirstRequiresSetAddress = first; }
        public int MatchingWords { get; }
        public int AdditionalClearWords { get; }
        public int RequiresSetWords { get; }
        public int? FirstRequiresSetAddress { get; }
        public bool ExactMatch => AdditionalClearWords == 0 && RequiresSetWords == 0;
    }

    public sealed class AL5ProgrammingAssessment
    {
        internal AL5ProgrammingAssessment(AL5CalibrationFileReport candidate, List<AL5ProgrammingStage> stages,
            AL5WordComparison? calibration, AL5WordComparison? collateral, AL5WordComparison? marker,
            string? snapshotHash, string? backupHash)
        {
            Candidate = candidate;
            Stages = new ReadOnlyCollection<AL5ProgrammingStage>(new List<AL5ProgrammingStage>(stages));
            Calibration = calibration; Collateral = collateral; CompletionMarker = marker;
            SnapshotSha256 = snapshotHash; CollateralBackupSha256 = backupHash;
        }
        public AL5CalibrationFileReport Candidate { get; }
        public IReadOnlyList<AL5ProgrammingStage> Stages { get; }
        public AL5WordComparison? Calibration { get; }
        public AL5WordComparison? Collateral { get; }
        public AL5WordComparison? CompletionMarker { get; }
        public string? SnapshotSha256 { get; }
        public string? CollateralBackupSha256 { get; }
        public bool ExactSavedImageMatch => Calibration?.ExactMatch == true &&
            Collateral?.ExactMatch == true && CompletionMarker?.ExactMatch == true;
        public bool ObservedZeroToOneConflict => Calibration?.RequiresSetWords > 0 ||
            Collateral?.RequiresSetWords > 0 || CompletionMarker?.RequiresSetWords > 0;
        public AL5RetryAssessment RetryAssessment => !Candidate.ChecksPass ? AL5RetryAssessment.InvalidCandidate :
            Calibration == null ? AL5RetryAssessment.SnapshotRequired :
            ObservedZeroToOneConflict ? AL5RetryAssessment.ZeroToOneConflict :
            Collateral == null ? AL5RetryAssessment.CollateralBaselineRequired :
            ExactSavedImageMatch ? AL5RetryAssessment.SavedImageMatches : AL5RetryAssessment.ClearOnlyDifferences;
        public string BlockingReason => !Candidate.ChecksPass ? "Candidate file checks failed; no modeled programming layout is available." :
            "AL5 programming and automatic retry are disabled. Current controller identity, fresh physical readback, loader session state and interrupted-flash recovery remain unverified.";
        public bool? LastOperationSucceeded => null;
        public bool? LoaderSessionReusable => null;
        public bool PhysicalEraseGeometryVerified => false;
        public bool PhysicalReadbackVerified => false;
        public bool RecoveryVerified => false;
        public bool AutomaticRetryEnabled => false;
        public bool LiveWriteEnabled => false;
        public bool ReadyToFlash => false;
    }
}
