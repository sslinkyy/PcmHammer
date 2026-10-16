// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace PcmHacking
{
    /// <summary>Host sequence rehearsal only. Observations are model inputs, never transport authority.</summary>
    public sealed class AL5OfflineProgrammingSession
    {
        private readonly byte[] candidate;
        private readonly byte[] collateralBackup;
        private readonly List<AL5OfflineObservation> observations = new List<AL5OfflineObservation>();
        private int cursor;

        public AL5OfflineProgrammingSession(byte[] candidate, byte[] collateralBackup)
        {
            if (candidate == null) throw new ArgumentNullException(nameof(candidate));
            if (collateralBackup == null) throw new ArgumentNullException(nameof(collateralBackup));
            if (candidate.Length != AL5CalibrationInspection.Length || collateralBackup.Length != AL5ProgrammingWorkflow.CollateralLength)
                throw new ArgumentException("Offline sequencing requires exact calibration and independent pre-erase collateral bytes.");
            this.candidate = (byte[])candidate.Clone();
            this.collateralBackup = (byte[])collateralBackup.Clone();
            Assessment = AL5ProgrammingWorkflow.Assess(this.candidate, collateralBackup: this.collateralBackup);
            if (!Assessment.Candidate.ChecksPass)
                throw new ArgumentException("Candidate must pass AL5 layout and native checksum checks.", nameof(candidate));
            var operations = new List<AL5OfflineOperation>();
            foreach (AL5ProgrammingStage stage in Assessment.Stages)
            {
                int count = stage.ModeledBlockCount == 0 ? 1 : stage.ModeledBlockCount;
                for (int block = 0; block < count; block++)
                {
                    int? start = stage.StartAddress;
                    int? length = stage.EndAddressExclusive - start;
                    if (stage.ModeledBlockCount != 0)
                    {
                        start += block * AL5ProgrammingWorkflow.ModeledBlockBytes;
                        length = Math.Min(AL5ProgrammingWorkflow.ModeledBlockBytes, stage.EndAddressExclusive!.Value - start!.Value);
                    }
                    operations.Add(new AL5OfflineOperation(operations.Count+1, stage.Phase, start, length));
                }
            }
            Operations = new ReadOnlyCollection<AL5OfflineOperation>(operations);
            State = AL5OfflineRunState.AwaitingModelOutcome;
        }

        public AL5ProgrammingAssessment Assessment { get; }
        public IReadOnlyList<AL5OfflineOperation> Operations { get; }
        public IReadOnlyList<AL5OfflineObservation> Observations =>
            new ReadOnlyCollection<AL5OfflineObservation>(new List<AL5OfflineObservation>(observations));
        // Retain the ambiguous/failed operation for inspection after a stop.
        public AL5OfflineOperation? PendingOperation => cursor < Operations.Count ? Operations[cursor] : null;
        public AL5OfflineRunState State { get; private set; }
        public bool LiveWriteEnabled => false;
        public bool AutomaticRetryEnabled => false;
        public bool ReadyToFlash => false;
        public bool RecoveryVerified => false;
        public bool? PhysicalOperationSucceeded => null;
        public bool? LoaderSessionReusable => null;

        public void RecordModelOutcome(AL5OfflineOperation operation, AL5OfflineOutcome outcome)
        {
            RequirePending(operation);
            if (outcome != AL5OfflineOutcome.ModelCompleted && outcome != AL5OfflineOutcome.ReplyLost &&
                outcome != AL5OfflineOutcome.ModelFailure && outcome != AL5OfflineOutcome.Interrupted &&
                outcome != AL5OfflineOutcome.Cancelled && outcome != AL5OfflineOutcome.UnconfirmedModelResult)
                throw new ArgumentOutOfRangeException(nameof(outcome));
            if (operation.Phase == AL5ProgrammingPhase.IndependentVerification && outcome == AL5OfflineOutcome.ModelCompleted)
                throw new InvalidOperationException("Final verification requires saved bytes, not a completion assertion.");
            RecordOutcome(operation, outcome, null);
        }

        public AL5LoaderModelDecision RecordLoaderModelResult(AL5OfflineOperation operation, AL5LoaderModelResult result)
        {
            RequirePending(operation);
            if (result == null) throw new ArgumentNullException(nameof(result));
            AL5LoaderModelDecision decision = AL5LoaderModelDecision.Assess(operation, result);
            RecordOutcome(operation, decision.Outcome, decision);
            return decision;
        }

        private void RecordOutcome(AL5OfflineOperation operation, AL5OfflineOutcome outcome, AL5LoaderModelDecision? decision)
        {
            observations.Add(new AL5OfflineObservation(operation, outcome, null, decision));
            if (outcome != AL5OfflineOutcome.ModelCompleted)
            {
                State = AL5OfflineRunState.Stopped;
                return;
            }
            cursor++;
            State = PendingOperation!.Phase == AL5ProgrammingPhase.IndependentVerification ?
                AL5OfflineRunState.AwaitingSavedVerification : AL5OfflineRunState.AwaitingModelOutcome;
        }

        public AL5ProgrammingAssessment RecordSavedVerification(AL5OfflineOperation operation, byte[] snapshot)
        {
            RequirePending(operation);
            if (State != AL5OfflineRunState.AwaitingSavedVerification)
                throw new InvalidOperationException("Saved verification is only accepted at the verification stage.");
            if (snapshot == null) throw new ArgumentNullException(nameof(snapshot));
            AL5ProgrammingAssessment report = AL5ProgrammingWorkflow.Assess(candidate, snapshot, collateralBackup);
            observations.Add(new AL5OfflineObservation(operation, report.ExactSavedImageMatch ?
                AL5OfflineOutcome.SavedVerificationMatched : AL5OfflineOutcome.SavedVerificationFailed, report.SnapshotSha256));
            if (report.ExactSavedImageMatch)
            {
                cursor++;
                State = AL5OfflineRunState.SavedImageVerified;
            }
            else State = AL5OfflineRunState.Stopped;
            return report;
        }

        public AL5StoppedOperationAssessment AssessStoppedSnapshot(byte[] snapshot)
        {
            if (State != AL5OfflineRunState.Stopped)
                throw new InvalidOperationException("Interruption reconciliation requires a stopped rehearsal.");
            if (snapshot == null) throw new ArgumentNullException(nameof(snapshot));
            if (snapshot.Length != AL5ProgrammingWorkflow.SnapshotLength)
                throw new ArgumentException("Requires the complete saved conditional flash range at 0x8000.", nameof(snapshot));
            // Use one owned snapshot for both the full-image facts/hash and operation comparison.
            byte[] observed = (byte[])snapshot.Clone();
            AL5ProgrammingAssessment image = AL5ProgrammingWorkflow.Assess(candidate, observed, collateralBackup);
            AL5OfflineOperation operation = PendingOperation!;
            AL5WordComparison? range = null;
            if (operation.StartAddress.HasValue)
            {
                byte[] target = new byte[AL5ProgrammingWorkflow.SnapshotLength];
                if (operation.Phase == AL5ProgrammingPhase.ConditionalErase)
                {
                    for (int index = 0; index < target.Length; index++) target[index] = 0xFF;
                }
                else
                {
                    Array.Copy(candidate, target, candidate.Length);
                    Array.Copy(collateralBackup, 0, target, candidate.Length, collateralBackup.Length);
                    target[target.Length-2] = 0x4A; target[target.Length-1] = 0xFC;
                }
                int offset = operation.StartAddress.Value - AL5CalibrationInspection.StartAddress;
                range = AL5ProgrammingWorkflow.CompareWords(observed, offset, target, offset,
                    operation.Length!.Value, operation.StartAddress.Value);
            }
            // Reconciliation never changes the cursor, outcome journal or stopped state.
            return new AL5StoppedOperationAssessment(observations[observations.Count-1], image, range);
        }

        private void RequirePending(AL5OfflineOperation operation)
        {
            if (State == AL5OfflineRunState.Stopped || State == AL5OfflineRunState.SavedImageVerified)
                throw new InvalidOperationException("Offline rehearsal is terminal; no implicit retry or session reuse.");
            // Object identity binds outcomes to this exact attempt, not merely a reused ordinal/address.
            if (operation == null || !ReferenceEquals(operation, PendingOperation))
                throw new ArgumentException("Result does not belong to the pending operation of this rehearsal.", nameof(operation));
        }
    }

    public enum AL5PendingRangeDisposition { NoFlashRange, SavedRangeMatches, ClearOnlyDifferences, ZeroToOneConflict }

    public sealed class AL5StoppedOperationAssessment
    {
        internal AL5StoppedOperationAssessment(AL5OfflineObservation stopObservation, AL5ProgrammingAssessment image, AL5WordComparison? range)
        { StopObservation = stopObservation; ImageAssessment = image; PendingRangeComparison = range; }
        public AL5OfflineObservation StopObservation { get; }
        public AL5OfflineOperation Operation => StopObservation.Operation;
        public AL5ProgrammingAssessment ImageAssessment { get; }
        public AL5WordComparison? PendingRangeComparison { get; }
        public AL5PendingRangeDisposition Disposition => PendingRangeComparison == null ? AL5PendingRangeDisposition.NoFlashRange :
            PendingRangeComparison.RequiresSetWords > 0 ? AL5PendingRangeDisposition.ZeroToOneConflict :
            PendingRangeComparison.ExactMatch ? AL5PendingRangeDisposition.SavedRangeMatches : AL5PendingRangeDisposition.ClearOnlyDifferences;
        public bool RetryEnabled => false;
        public bool CanResumeStoppedSession => false;
        public bool PhysicalReadbackVerified => false;
    }

    public enum AL5OfflineRunState { AwaitingModelOutcome, AwaitingSavedVerification, Stopped, SavedImageVerified }
    public enum AL5OfflineOutcome
    {
        ModelCompleted, ReplyLost, ModelFailure, Interrupted, Cancelled,
        SavedVerificationMatched, SavedVerificationFailed, UnconfirmedModelResult
    }

    public sealed class AL5OfflineOperation
    {
        internal AL5OfflineOperation(int sequence, AL5ProgrammingPhase phase, int? address, int? length)
        { Sequence = sequence; Phase = phase; StartAddress = address; Length = length; }
        public int Sequence { get; }
        public AL5ProgrammingPhase Phase { get; }
        public int? StartAddress { get; }
        public int? Length { get; }
    }

    public sealed class AL5OfflineObservation
    {
        internal AL5OfflineObservation(AL5OfflineOperation operation, AL5OfflineOutcome outcome, string? snapshotHash,
            AL5LoaderModelDecision? loaderDecision = null)
        { Operation = operation; Outcome = outcome; SnapshotSha256 = snapshotHash; LoaderDecision = loaderDecision; }
        public AL5OfflineOperation Operation { get; }
        public AL5OfflineOutcome Outcome { get; }
        public string? SnapshotSha256 { get; }
        public AL5LoaderModelDecision? LoaderDecision { get; }
    }
}
