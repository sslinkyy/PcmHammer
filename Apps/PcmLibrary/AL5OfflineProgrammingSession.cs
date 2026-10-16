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
                outcome != AL5OfflineOutcome.Cancelled)
                throw new ArgumentOutOfRangeException(nameof(outcome));
            if (operation.Phase == AL5ProgrammingPhase.IndependentVerification && outcome == AL5OfflineOutcome.ModelCompleted)
                throw new InvalidOperationException("Final verification requires saved bytes, not a completion assertion.");
            observations.Add(new AL5OfflineObservation(operation, outcome, null));
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

        public AL5ProgrammingAssessment AssessStoppedSnapshot(byte[] snapshot)
        {
            if (State != AL5OfflineRunState.Stopped)
                throw new InvalidOperationException("Interruption reconciliation requires a stopped rehearsal.");
            if (snapshot == null) throw new ArgumentNullException(nameof(snapshot));
            // Reconciliation never changes the cursor/state, even when all saved bytes match.
            return AL5ProgrammingWorkflow.Assess(candidate, snapshot, collateralBackup);
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

    public enum AL5OfflineRunState { AwaitingModelOutcome, AwaitingSavedVerification, Stopped, SavedImageVerified }
    public enum AL5OfflineOutcome
    {
        ModelCompleted, ReplyLost, ModelFailure, Interrupted, Cancelled,
        SavedVerificationMatched, SavedVerificationFailed
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
        internal AL5OfflineObservation(AL5OfflineOperation operation, AL5OfflineOutcome outcome, string? snapshotHash)
        { Operation = operation; Outcome = outcome; SnapshotSha256 = snapshotHash; }
        public AL5OfflineOperation Operation { get; }
        public AL5OfflineOutcome Outcome { get; }
        public string? SnapshotSha256 { get; }
    }
}
