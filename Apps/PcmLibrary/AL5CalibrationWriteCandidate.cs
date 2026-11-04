// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Security.Cryptography;

namespace PcmHacking
{
    public enum AL5OfflineWriteActionKind
    {
        FixedControlRequest, ProgrammingRequest, SavedReplyRequired,
        SecurityKeyEvidenceRequired, ChecksumRetryReviewRequired,
        SavedFullReadbackRequired, Completed, Stopped
    }

    public sealed class AL5OfflineWriteAction
    {
        private readonly byte[]? bytes;
        internal AL5OfflineWriteAction(AL5OfflineWriteActionKind kind, byte[]? request=null)
        { Kind=kind;bytes=request==null?null:(byte[])request.Clone(); }
        public AL5OfflineWriteActionKind Kind { get; }
        public byte[] CopyRequest()
        {
            if(bytes==null)throw new InvalidOperationException("This action has no constructed offline request.");
            return (byte[])bytes.Clone();
        }
    }

    /// <summary>
    /// Transport-free calibration writer candidate. Owns the captured protocol,
    /// full original reference, constructed payload and independent-file comparison.
    /// No method uploads, executes, opens an adapter or confers live authority.
    /// </summary>
    public sealed class AL5CalibrationWriteCandidate
    {
        public const string Profile="AL5-EFILive-VPW-1x-calibration-captured-v1";
        public const string LoaderSha256="b545d9b2d078662466ab32d9cdeb5b3c38c840135e8aeca09f33760ec66780fa";
        private readonly byte[] baseline;
        private readonly AL5CalibrationSectorPlan sectors;
        private readonly AL5EfiOfflineWritePlan plan;
        private readonly AL5CapturedWriteRehearsal session;
        private AL5PreparedBankReference? preparedBanks;
        public string BaselineSha256 { get; }
        public string PreEraseSectorSha256 => sectors.SavedPreEraseSha256;
        public AL5CapturedWriteState State => comparisonFailed ? AL5CapturedWriteState.Stopped : session.State;
        public int PositiveProgramReplies => session.PositiveProgramReplies;
        public int ChecksumErrors => session.ChecksumErrors;
        public int RepeatsWithoutReply => session.RepeatsWithoutReply;
        public bool CompleteSavedComparison { get; private set; }
        public int? ChangedPersistentBankBytes { get; private set; }
        public int? ChangedOtherProtectedBytes { get; private set; }
        public bool LiveUploadEnabled => false;
        public bool LiveExecutionEnabled => false;
        public bool LiveWriteEnabled => false;
        public bool AutomaticRetryEnabled => false;
        public bool ReadyToFlash => false;
        public bool PhysicalReadbackVerified => false;
        public bool RecoveryVerified => false;
        public bool SecurityAuthorizationProven => false;
        public bool ControllerIdentityVerified => false;
        public int ConstructedProgrammingRequests => plan.RequestCount;
        public bool HasSavedPreparedBankReference=>preparedBanks!=null;
        public string? PreparedBanksSha256=>preparedBanks?.PreparedSha256;
        public int? SavedPreparationChangedBytes=>preparedBanks?.ChangedBytes;
        internal void RecordSavedPreparedBanks(byte[] bytes)
        {
            if(State!=AL5CapturedWriteState.EraseRequest || preparedBanks!=null)throw new InvalidOperationException("Record prepared banks once, before erase.");
            var original=new byte[AL5PreparedBankReference.Length];Buffer.BlockCopy(baseline,AL5PreparedBankReference.StartAddress,original,0,original.Length);
            preparedBanks=new AL5PreparedBankReference(original,bytes);
        }

        public AL5CalibrationWriteCandidate(byte[] loader, byte[] calibration, byte[] savedFullBaseline)
        {
            if(savedFullBaseline==null)throw new ArgumentNullException(nameof(savedFullBaseline));
            if(savedFullBaseline.Length!=0x100000)throw new ArgumentException("An explicit complete 1 MiB saved reference is required; partial images are not filled.");
            baseline=(byte[])savedFullBaseline.Clone();
            using(var hash=SHA256.Create())BaselineSha256=BitConverter.ToString(hash.ComputeHash(baseline)).Replace("-","").ToLowerInvariant();
            var before=new byte[AL5ProgrammingWorkflow.SnapshotLength];
            Buffer.BlockCopy(baseline,0x8000,before,0,before.Length);
            sectors=new AL5CalibrationSectorPlan(calibration,before);
            plan=new AL5EfiOfflineWritePlan(loader,LoaderSha256,sectors.CopyCalibration(),sectors.CopyCollateralBackup());
            session=new AL5CapturedWriteRehearsal(plan);
        }

        public AL5OfflineWriteAction NextOfflineAction()
        {
            if(State==AL5CapturedWriteState.Stopped)return new AL5OfflineWriteAction(AL5OfflineWriteActionKind.Stopped);
            if(CompleteSavedComparison)return new AL5OfflineWriteAction(AL5OfflineWriteActionKind.Completed);
            if(State==AL5CapturedWriteState.AwaitingSavedVerification)return new AL5OfflineWriteAction(AL5OfflineWriteActionKind.SavedFullReadbackRequired);
            if(session.ChecksumRetryReviewRequired)return new AL5OfflineWriteAction(AL5OfflineWriteActionKind.ChecksumRetryReviewRequired);
            var control=session.CopyFixedOfflineControlRequest(out bool key);
            if(key)return new AL5OfflineWriteAction(AL5OfflineWriteActionKind.SecurityKeyEvidenceRequired);
            if(control!=null)return new AL5OfflineWriteAction(AL5OfflineWriteActionKind.FixedControlRequest,control);
            if(State==AL5CapturedWriteState.LoaderTransfer || State==AL5CapturedWriteState.EraseRequest || State==AL5CapturedWriteState.FinalizeRequest ||
                State==AL5CapturedWriteState.Programming)
            {
                try{return new AL5OfflineWriteAction(AL5OfflineWriteActionKind.ProgrammingRequest,session.CopyNextOfflineRequest());}
                catch(InvalidOperationException) { /* A pending block needs a reply, not a new request. */ }
            }
            return new AL5OfflineWriteAction(AL5OfflineWriteActionKind.SavedReplyRequired);
        }

        public byte[] CopyChecksumRejectedRequestForOfflineReview() => session.CopyChecksumRejectedOfflineRequest();
        public byte[] CopyConstructedProgrammingRequest(int index) => plan.CopyRequest(index);

        public void ObserveSavedFrame(bool transmitted, byte[] message)
        {
            if(State==AL5CapturedWriteState.Stopped || CompleteSavedComparison)
                throw new InvalidOperationException("Candidate is terminal; a new session requires a new candidate.");
            try{session.Observe(transmitted,message);}
            catch(ArgumentException){session.Interrupt();throw;}
            catch(InvalidOperationException){session.Interrupt();throw;}
        }

        public void TimeoutOrCancel()
        {
            if(CompleteSavedComparison || State==AL5CapturedWriteState.Stopped)throw new InvalidOperationException("Candidate is terminal.");
            session.Interrupt();
        }

        public byte[] CopyExpectedSavedImage()
        {
            var expected=(byte[])baseline.Clone();var desired=sectors.CopyDesiredBeforeFinalization();
            if(preparedBanks!=null)Buffer.BlockCopy(preparedBanks.CopyPrepared(),0,expected,AL5PreparedBankReference.StartAddress,AL5PreparedBankReference.Length);
            Buffer.BlockCopy(desired,0,expected,0x8000,desired.Length);
            expected[0x1FFFE]=0x4A;expected[0x1FFFF]=0xFC;return expected;
        }

        public AL5ProgrammingAssessment VerifySavedFullReadback(byte[] readback)
        {
            if(State!=AL5CapturedWriteState.AwaitingSavedVerification)throw new InvalidOperationException("Complete cleanup is required before saved readback verification.");
            if(readback==null || readback.Length!=0x100000)throw new ArgumentException("Independent saved comparison requires all 1 MiB; missing bytes stay unknown.");
            var observed=(byte[])readback.Clone();int bankChanges=0,otherChanges=0;
            byte[]? prepared=preparedBanks?.CopyPrepared();
            for(int i=0;i<observed.Length;i++)
            {
                if(i>=0x8000 && i<0x20000)continue;
                byte expected=prepared!=null && i>=0x4000 && i<0x8000?prepared[i-0x4000]:baseline[i];
                if(observed[i]==expected)continue;
                if(i>=0x4000 && i<0x8000)bankChanges++;else otherChanges++;
            }
            ChangedPersistentBankBytes=bankChanges;ChangedOtherProtectedBytes=otherChanges;
            var snapshot=new byte[AL5ProgrammingWorkflow.SnapshotLength];Buffer.BlockCopy(observed,0x8000,snapshot,0,snapshot.Length);
            var assessment=session.VerifySavedSnapshot(snapshot,sectors.CopyCollateralBackup());
            CompleteSavedComparison=assessment.ExactSavedImageMatch && bankChanges==0 && otherChanges==0;
            // Preparation bank changes require separate explanation, not silent acceptance.
            // Keep a complete sector match distinct from a full preservation match.
            if(!CompleteSavedComparison)comparisonFailed=true;
            return assessment;
        }

        /// <summary>Diagnostic only. Never changes the strict comparison result, state or live authority.</summary>
        public AL5SavedBankTransitionAssessment DiagnoseSavedStartupBanks(AL5SavedBankTransitionReview review,byte[] fullReadback)
        {
            if(review==null)throw new ArgumentNullException(nameof(review));
            if(State!=AL5CapturedWriteState.AwaitingSavedVerification && !comparisonFailed)
                throw new InvalidOperationException("Complete cleanup is required before saved startup diagnosis.");
            if(preparedBanks==null || review.OriginalSha256!=BaselineSha256 || review.PreparedBanksSha256!=preparedBanks.PreparedSha256)
                throw new ArgumentException("Saved prediction must own this original and prepared-bank epoch.");
            if(fullReadback==null || fullReadback.Length!=baseline.Length)throw new ArgumentException("Complete saved readback required.");
            var banks=new byte[AL5PreparedBankReference.Length];Buffer.BlockCopy(fullReadback,AL5PreparedBankReference.StartAddress,banks,0,banks.Length);
            return review.CompareSavedBanks(banks);
        }

        private bool comparisonFailed;
    }
}
