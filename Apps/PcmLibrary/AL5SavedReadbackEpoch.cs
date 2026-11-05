// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Security.Cryptography;

namespace PcmHacking
{
    public enum AL5SavedReadbackEpochKind { AfterCleanupStartupUnobserved, AfterDeclaredStartup }
    public enum AL5SavedReadbackEpochPhase { BanksBeforeImage, FullImage, BanksAfterImage, Complete, Stopped }
    public enum AL5SavedReadbackEpochStop { None, MalformedReply, TimeoutOrCancel, DeclaredInterveningResetOrStartup }

    public sealed class AL5SavedReadbackEpochAssessment
    {
        internal AL5SavedReadbackEpochAssessment(AL5SavedReadbackEpoch e)
        {
            EvidenceId=e.EvidenceId;Kind=e.Kind;Phase=e.Phase;StopReason=e.StopReason;
            OriginalSha256=e.OriginalSha256;PreparedBanksSha256=e.PreparedBanksSha256;ExpectedImageSha256=e.ExpectedImageSha256;
            BeforeNonceHex=e.BeforeNonceHex;ImageNonceHex=e.ImageNonceHex;AfterNonceHex=e.AfterNonceHex;
            BeforeBankBytes=e.BeforeBankBytes;FullImageBytes=e.FullImageBytes;AfterBankBytes=e.AfterBankBytes;
            MatchedReplies=e.MatchedReplies;BeforeBanksSha256=e.BeforeBanksSha256;ObservedImageSha256=e.ObservedImageSha256;
            ImageBanksSha256=e.ImageBanksSha256;AfterBanksSha256=e.AfterBanksSha256;
            BeforeToImageBankDifferences=e.BeforeToImageBankDifferences;ImageToAfterBankDifferences=e.ImageToAfterBankDifferences;
            BeforeToAfterBankDifferences=e.BeforeToAfterBankDifferences;
            SavedComparisonAttempted=e.SavedComparisonAttempted;StrictSavedComparisonMatched=e.StrictSavedComparisonMatched;
            ChangedPersistentBankBytes=e.ChangedPersistentBankBytes;ChangedOtherProtectedBytes=e.ChangedOtherProtectedBytes;
        }
        public string EvidenceId { get; }
        public AL5SavedReadbackEpochKind Kind { get; }
        public AL5SavedReadbackEpochPhase Phase { get; }
        public AL5SavedReadbackEpochStop StopReason { get; }
        public string OriginalSha256 { get; }
        public string PreparedBanksSha256 { get; }
        public string ExpectedImageSha256 { get; }
        public string BeforeNonceHex { get; }
        public string ImageNonceHex { get; }
        public string AfterNonceHex { get; }
        public int BeforeBankBytes { get; }
        public int FullImageBytes { get; }
        public int AfterBankBytes { get; }
        public int MatchedReplies { get; }
        public string? BeforeBanksSha256 { get; }
        public string? ObservedImageSha256 { get; }
        public string? ImageBanksSha256 { get; }
        public string? AfterBanksSha256 { get; }
        public int? BeforeToImageBankDifferences { get; }
        public int? ImageToAfterBankDifferences { get; }
        public int? BeforeToAfterBankDifferences { get; }
        public bool CompleteCorrelatedCoverage=>Phase==AL5SavedReadbackEpochPhase.Complete;
        public bool? BanksAgreeAcrossSavedObservations=>CompleteCorrelatedCoverage?
            BeforeToImageBankDifferences==0 && ImageToAfterBankDifferences==0:(bool?)null;
        public bool? RawImageMatchesExpectedSavedImage=>ObservedImageSha256==null?(bool?)null:ObservedImageSha256==ExpectedImageSha256;
        public bool SavedComparisonAttempted { get; }
        public bool StrictSavedComparisonMatched { get; }
        public int? ChangedPersistentBankBytes { get; }
        public int? ChangedOtherProtectedBytes { get; }
        public bool SnapshotCoherenceVerified=>false;
        public string AcquisitionKind=>"correlated_saved_readonly_responses";
        public bool ReaderEntryEffectsVerified=>false;
        public bool StartupHistoryPhysicallyVerified=>false;
        public bool CrossSessionNonceUniquenessProven=>false;
        public bool PhysicalReadbackVerified=>false;
        public bool PhysicalResetVerified=>false;
        public bool PreservationVerified=>false;
        public bool LiveUploadEnabled=>false;
        public bool LiveExecutionEnabled=>false;
        public bool LiveWriteEnabled=>false;
        public bool ReadyToFlash=>false;
    }

    /// <summary>
    /// Ordered saved bank/full-image/bank acquisition tied to one completed
    /// candidate. Equal observations are not an atomic-snapshot or hardware proof.
    /// No adapter, clock, uploader or reset mechanism is accepted.
    /// </summary>
    public sealed class AL5SavedReadbackEpoch
    {
        private readonly AL5CalibrationWriteCandidate owner;
        private readonly AL5ReadOnlyRangeCampaign before,after;
        private readonly AL5ReadOnlyFlashCampaign image;
        private AL5SavedReadbackEpoch(AL5CalibrationWriteCandidate owner,string evidenceId,AL5SavedReadbackEpochKind kind,
            byte[] beforeNonce,byte[] imageNonce,byte[] afterNonce)
        {
            if(owner==null)throw new ArgumentNullException(nameof(owner));
            if(string.IsNullOrWhiteSpace(evidenceId))throw new ArgumentException("Explicit readback evidence identity required.");
            if(!Enum.IsDefined(typeof(AL5SavedReadbackEpochKind),kind))throw new ArgumentOutOfRangeException(nameof(kind));
            if(owner.State!=AL5CapturedWriteState.AwaitingSavedVerification || !owner.SavedFinalizationReplyObserved ||
                !owner.SavedCleanupObserved || !owner.HasSavedPreparedBankReference)
                throw new InvalidOperationException("Completed saved cleanup and explicit prepared banks must precede this readback epoch.");
            if(beforeNonce==null || imageNonce==null || afterNonce==null)throw new ArgumentNullException("nonce");
            beforeNonce=(byte[])beforeNonce.Clone();imageNonce=(byte[])imageNonce.Clone();afterNonce=(byte[])afterNonce.Clone();
            // The existing session validates and clones all three nonces.
            before=new AL5ReadOnlyRangeCampaign(new AL5ReadOnlyCoreSession(beforeNonce),0x4000,0x4000);
            image=new AL5ReadOnlyFlashCampaign(imageNonce);
            after=new AL5ReadOnlyRangeCampaign(new AL5ReadOnlyCoreSession(afterNonce),0x4000,0x4000);
            BeforeNonceHex=Hex(beforeNonce);ImageNonceHex=Hex(imageNonce);AfterNonceHex=Hex(afterNonce);
            if(BeforeNonceHex==ImageNonceHex || BeforeNonceHex==AfterNonceHex || ImageNonceHex==AfterNonceHex)
                throw new ArgumentException("All three ordered campaigns require distinct nonces.");
            this.owner=owner;EvidenceId=evidenceId;Kind=kind;OriginalSha256=owner.BaselineSha256;
            PreparedBanksSha256=owner.PreparedBanksSha256!;ExpectedImageSha256=Hash(owner.CopyExpectedSavedImage());
        }
        public static AL5SavedReadbackEpoch CreateForCompletedSavedCandidate(AL5CalibrationWriteCandidate candidate,
            string evidenceId,AL5SavedReadbackEpochKind kind,byte[] beforeNonce,byte[] imageNonce,byte[] afterNonce)=>
            new AL5SavedReadbackEpoch(candidate,evidenceId,kind,beforeNonce,imageNonce,afterNonce);
        /// <summary>Rehearses caller-supplied saved frames, never sends them or computes fresh security.</summary>
        public static AL5SavedReadbackEpoch RehearseSavedLifecycle(byte[] loader,byte[] original,byte[] prepared,
            (bool Transmitted,byte[] Frame)[] frames,string evidenceId,AL5SavedReadbackEpochKind kind,
            byte[] beforeNonce,byte[] imageNonce,byte[] afterNonce)
            =>CreateForCompletedSavedCandidate(RehearseSavedCandidate(loader,original,prepared,frames),
                evidenceId,kind,beforeNonce,imageNonce,afterNonce);
        internal static AL5CalibrationWriteCandidate RehearseSavedCandidate(byte[] loader,byte[] original,byte[] prepared,
            (bool Transmitted,byte[] Frame)[] frames)
        {
            if(original==null || original.Length!=0x100000 || prepared==null || prepared.Length!=0x4000)
                throw new ArgumentException("Complete saved original image and prepared banks required.");
            if(frames==null)throw new ArgumentNullException(nameof(frames));
            original=(byte[])original.Clone();prepared=(byte[])prepared.Clone();
            var calibration=new byte[AL5CalibrationInspection.Length];Buffer.BlockCopy(original,0x8000,calibration,0,calibration.Length);
            if(!AL5CalibrationWriteProfile.InspectSavedReference(original,calibration).SavedBytesMatchProfile)
                throw new ArgumentException("Original reference does not match the supported saved profile.");
            var candidate=new AL5CalibrationWriteCandidate(loader,calibration,original);bool recorded=false;
            foreach(var frame in frames)
            {
                if(!recorded && candidate.State==AL5CapturedWriteState.EraseRequest)
                {candidate.RecordSavedPreparedBanks(prepared);recorded=true;}
                if(frame.Frame==null)throw new ArgumentException("Missing saved lifecycle frame.");
                candidate.ObserveSavedFrame(frame.Transmitted,(byte[])frame.Frame.Clone());
            }
            if(candidate.State!=AL5CapturedWriteState.AwaitingSavedVerification || !candidate.SavedCleanupObserved || !candidate.HasSavedPreparedBankReference)
                throw new InvalidOperationException("Complete saved cleanup and prepared banks required before readback review.");
            return candidate;
        }
        private static string Hex(byte[] b)=>BitConverter.ToString(b).Replace("-","").ToLowerInvariant();
        private static string Hash(byte[] b){using(var h=SHA256.Create())return Hex(h.ComputeHash(b));}
        private static int Differences(byte[] a,byte[] b)
        {int count=0;for(int i=0;i<a.Length;i++)if(a[i]!=b[i])count++;return count;}
        public string EvidenceId { get; }
        public AL5SavedReadbackEpochKind Kind { get; }
        public string OriginalSha256 { get; }
        public string PreparedBanksSha256 { get; }
        public string ExpectedImageSha256 { get; }
        public string BeforeNonceHex { get; }
        public string ImageNonceHex { get; }
        public string AfterNonceHex { get; }
        public AL5SavedReadbackEpochPhase Phase { get; private set; }
        public AL5SavedReadbackEpochStop StopReason { get; private set; }
        public int BeforeBankBytes=>before.BytesObserved;
        public int FullImageBytes=>image.BytesObserved;
        public int AfterBankBytes=>after.BytesObserved;
        public int MatchedReplies=>before.MatchedReplies+image.MatchedReplies+after.MatchedReplies;
        public string? BeforeBanksSha256 { get; private set; }
        public string? ObservedImageSha256 { get; private set; }
        public string? ImageBanksSha256 { get; private set; }
        public string? AfterBanksSha256 { get; private set; }
        public int? BeforeToImageBankDifferences { get; private set; }
        public int? ImageToAfterBankDifferences { get; private set; }
        public int? BeforeToAfterBankDifferences { get; private set; }
        public bool SavedComparisonAttempted { get; private set; }
        public bool StrictSavedComparisonMatched=>SavedComparisonAttempted && owner.CompleteSavedComparison;
        public int? ChangedPersistentBankBytes=>SavedComparisonAttempted?owner.ChangedPersistentBankBytes:null;
        public int? ChangedOtherProtectedBytes=>SavedComparisonAttempted?owner.ChangedOtherProtectedBytes:null;
        public AL5SavedReadbackEpochAssessment AssessSavedEvidence()=>new AL5SavedReadbackEpochAssessment(this);
        private void RequireOpen()
        {
            if(Phase==AL5SavedReadbackEpochPhase.Complete || Phase==AL5SavedReadbackEpochPhase.Stopped)
                throw new InvalidOperationException("Saved readback acquisition is closed; late frames cannot reopen it.");
        }
        public byte[] BeginNextSavedRequest()
        {
            RequireOpen();
            if(Phase==AL5SavedReadbackEpochPhase.BanksBeforeImage)return before.BeginNextSavedVpwRequest();
            if(Phase==AL5SavedReadbackEpochPhase.FullImage)return image.BeginNextSavedVpwRequest();
            return after.BeginNextSavedVpwRequest();
        }
        public AL5ReadOnlyCoreReply ObserveSavedReply(byte[] frame)
        {
            RequireOpen();AL5ReadOnlyCoreReply result;
            if(Phase==AL5SavedReadbackEpochPhase.BanksBeforeImage)
            {
                result=before.ObserveSavedVpwReply(frame);
                if(before.Complete){BeforeBanksSha256=Hash(before.CopySavedBytes());Phase=AL5SavedReadbackEpochPhase.FullImage;}
            }
            else if(Phase==AL5SavedReadbackEpochPhase.FullImage)
            {
                result=image.ObserveSavedVpwReply(frame);
                if(image.Complete)
                {
                    byte[] full=image.CopySavedImage();ObservedImageSha256=Hash(full);
                    var banks=new byte[0x4000];Buffer.BlockCopy(full,0x4000,banks,0,banks.Length);
                    ImageBanksSha256=Hash(banks);BeforeToImageBankDifferences=Differences(before.CopySavedBytes(),banks);
                    Phase=AL5SavedReadbackEpochPhase.BanksAfterImage;
                }
            }
            else
            {
                result=after.ObserveSavedVpwReply(frame);
                if(after.Complete)
                {
                    byte[] banks=after.CopySavedBytes(),full=image.CopySavedImage();var middle=new byte[0x4000];
                    Buffer.BlockCopy(full,0x4000,middle,0,middle.Length);AfterBanksSha256=Hash(banks);
                    ImageToAfterBankDifferences=Differences(middle,banks);BeforeToAfterBankDifferences=Differences(before.CopySavedBytes(),banks);
                    Phase=AL5SavedReadbackEpochPhase.Complete;
                }
            }
            if(result==AL5ReadOnlyCoreReply.Malformed){StopReason=AL5SavedReadbackEpochStop.MalformedReply;Phase=AL5SavedReadbackEpochPhase.Stopped;}
            return result;
        }
        public void TimeoutOrCancel()=>Stop(AL5SavedReadbackEpochStop.TimeoutOrCancel);
        public void RecordInterveningResetOrStartupForOfflineReview()=>Stop(AL5SavedReadbackEpochStop.DeclaredInterveningResetOrStartup);
        private void Stop(AL5SavedReadbackEpochStop reason)
        {
            RequireOpen();
            if(Phase==AL5SavedReadbackEpochPhase.BanksBeforeImage)before.TimeoutOrCancel();
            else if(Phase==AL5SavedReadbackEpochPhase.FullImage)image.TimeoutOrCancel();else after.TimeoutOrCancel();
            StopReason=reason;Phase=AL5SavedReadbackEpochPhase.Stopped;
        }
        /// <summary>Complete image bytes for diagnosis only, even if a later bank campaign stopped.</summary>
        public byte[] CopyObservedImageForDiagnosis()=>image.CopySavedImage();
        public byte[] CopyBeforeBanksForDiagnosis()=>before.CopySavedBytes();
        public byte[] CopyAfterBanksForDiagnosis()=>after.CopySavedBytes();
        public AL5SavedBankTransitionAssessment DiagnoseSavedStartupBanks(AL5SavedBankTransitionReview prediction)
        {
            if(Phase!=AL5SavedReadbackEpochPhase.Complete)throw new InvalidOperationException("Finish all three observation campaigns before epoch diagnosis.");
            return owner.DiagnoseSavedStartupBanks(prediction,image.CopySavedImage());
        }
        public AL5ProgrammingAssessment VerifySavedComparison(AL5CalibrationWriteCandidate candidate)
        {
            if(!Object.ReferenceEquals(owner,candidate))throw new ArgumentException("Foreign candidate cannot consume this acquisition epoch.");
            if(Phase!=AL5SavedReadbackEpochPhase.Complete || AssessSavedEvidence().BanksAgreeAcrossSavedObservations!=true)
                throw new InvalidOperationException("Complete agreeing bank/full-image/bank observations required; keep unstable bytes diagnostic-only.");
            // Reuse the unchanged strict full comparator. Post-startup banks never
            // become their own expected baseline, even when their samples agree.
            var result=owner.VerifySavedFullReadback(image.CopySavedImage());SavedComparisonAttempted=true;return result;
        }
        public AL5ProgrammingAssessment VerifySavedComparison()=>VerifySavedComparison(owner);
    }
}
