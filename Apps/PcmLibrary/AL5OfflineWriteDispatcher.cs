// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace PcmHacking
{
    public enum AL5OfflineSendOutcome { AdapterAccepted, NotSubmitted, SubmissionUnknown }
    public enum AL5OfflineDispatchKind { Control, SecurityEvidence, Loader, Erase, Data, ChecksumRetry, Finalization, Cleanup, ProgrammingBroadcast }
    public enum AL5OfflineDispatchState { ActionAvailable, DispatchPrepared, AwaitingReply, AwaitingSecurityEvidence, ChecksumRetryReview, AwaitingReadback, Completed, Stopped, BoundaryReached }
    public enum AL5OfflineWriteBoundary { BeforeSecurityKey, BeforeProgrammingEntry, BeforeLoaderUpload, BeforeErase, AfterEraseBeforeData, CompleteOfflineRehearsal }
    public enum AL5OfflineDispatchStop { None, Timeout, Cancelled, SendNotSubmitted, SendSubmissionUnknown, UnexpectedReply, InvalidFrame, ProtocolFailure, RetryBudgetExhausted, VerificationFailed, UnsupportedSecurityProfile, LoaderChecksumRejected, LoaderRejected, UnqualifiedLoaderReply, ReceiveFault, InvalidClock, ExecutionWaitFault }

    /// <summary>An immutable, single-use offline send reservation. It is not a live send capability.</summary>
    public sealed class AL5OfflineWriteDispatch
    {
        private readonly byte[] request;
        internal AL5OfflineWriteDispatch(long ordinal, AL5OfflineDispatchKind kind, byte[] bytes,
            AL5CapturedWriteState phase, int acknowledgedBlocks, ushort? savedSeed)
        {
            Ordinal=ordinal;Kind=kind;request=(byte[])bytes.Clone();Phase=phase;
            AcknowledgedBlocks=acknowledgedBlocks;SavedSeed=savedSeed;
        }
        public long Ordinal { get; }
        public AL5OfflineDispatchKind Kind { get; }
        public AL5CapturedWriteState Phase { get; }
        public int AcknowledgedBlocks { get; }
        public ushort? SavedSeed { get; }
        public byte[] CopyRequest() => (byte[])request.Clone();
    }

    /// <summary>
    /// File/model-only orchestration for a future writer binding. Owns its candidate,
    /// one send reservation and one reply slot. No Vehicle, device, callback, clock,
    /// task scheduler or I/O API is accepted. Adapter acceptance is not flash completion.
    /// </summary>
    public sealed class AL5OfflineWriteDispatcher
    {
        private readonly object sync=new object();
        private readonly AL5CalibrationWriteCandidate candidate;
        private AL5OfflineWriteDispatch? pending, lastAccepted, replyOwner, lastReplyOwner;
        private bool awaitingReply;
        private long ordinal;
        private int retriesForBlock;
        private ushort? pendingSecuritySeed,lastObservedSeed;
        private AL5OfflineDispatchStop stopReason;
        private int ignoredOtherSources;
        private int trailingCleanupReplies;
        private AL5OfflineSendOutcome? lastSendOutcome;
        private AL5CapturedWriteState? phaseAtStop;
        private readonly AL5OfflineWriteTimeBudget? timeBudget;
        private long clockTicks,sendStartedTicks,replyStartedTicks;
        private AL5OfflineWriteDispatch? lastLoader;
        private bool awaitingLoaderIdentity;
        private byte[]? lastObservedAl5Reply;
        private int? lastReceivedFrameLength;

        public AL5OfflineWriteDispatcher(byte[] loader,byte[] calibration,byte[] savedFullBaseline,int checksumRetryBudgetPerBlock,
            AL5OfflineWriteTimeBudget? timeBudget=null,AL5OfflineWriteBoundary boundary=AL5OfflineWriteBoundary.BeforeSecurityKey)
        {
            if(checksumRetryBudgetPerBlock<0)throw new ArgumentOutOfRangeException(nameof(checksumRetryBudgetPerBlock));
            if(!Enum.IsDefined(typeof(AL5OfflineWriteBoundary),boundary))throw new ArgumentOutOfRangeException(nameof(boundary));
            // This budget is a caller-selected offline policy, not a discovered firmware limit.
            ChecksumRetryBudgetPerBlock=checksumRetryBudgetPerBlock;
            this.timeBudget=timeBudget;
            Boundary=boundary;
            if(loader==null || calibration==null || savedFullBaseline==null)throw new ArgumentNullException();
            // Profile inspection and candidate construction consume the same owned snapshots.
            var ownedLoader=(byte[])loader.Clone();var ownedCalibration=(byte[])calibration.Clone();var ownedReference=(byte[])savedFullBaseline.Clone();
            SavedProfile=AL5CalibrationWriteProfile.InspectSavedReference(ownedReference,ownedCalibration);
            if(!SavedProfile.SavedBytesMatchProfile)
                throw new ArgumentException("Offline dispatch requires the pinned boot/OS and selector-zero calibration profile; unknown references cannot use this writer.");
            candidate=new AL5CalibrationWriteCandidate(ownedLoader,ownedCalibration,ownedReference);
        }

        public AL5SavedWriteProfileAssessment SavedProfile { get; }
        public int ChecksumRetryBudgetPerBlock { get; }
        public AL5OfflineWriteBoundary Boundary { get; }
        public bool HasExplicitTimeBudget => timeBudget!=null;
        public TimeSpan SavedElapsed { get { lock(sync)return TimeSpan.FromTicks(clockTicks); } }
        public AL5OfflineWriteDispatch? PendingDispatch { get { lock(sync)return pending; } }
        public AL5OfflineWriteDispatch? LastAdapterAcceptedDispatch { get { lock(sync)return lastAccepted; } }
        public AL5OfflineWriteDispatch? ReplyOwnerDispatch { get { lock(sync)return replyOwner; } }
        public AL5OfflineWriteDispatch? LastConsumedReplyOwner { get { lock(sync)return lastReplyOwner; } }
        public AL5OfflineWriteDispatch? LastLoaderDispatch { get { lock(sync)return lastLoader; } }
        public bool AwaitingLoaderIdentity { get { lock(sync)return awaitingLoaderIdentity; } }
        public ushort? LastObservedSeed { get { lock(sync)return lastObservedSeed; } }
        public int? LastReceivedFrameLength { get { lock(sync)return lastReceivedFrameLength; } }
        public byte[]? CopyLastObservedAl5Reply(){lock(sync)return lastObservedAl5Reply==null?null:(byte[])lastObservedAl5Reply.Clone();}
        public AL5OfflineSendOutcome? LastSendOutcome { get { lock(sync)return lastSendOutcome; } }
        public AL5OfflineDispatchStop StopReason { get { lock(sync)return stopReason; } }
        public AL5CapturedWriteState? ProtocolPhaseAtStop { get { lock(sync)return phaseAtStop; } }
        public AL5CapturedWriteState ProtocolState { get { lock(sync)return candidate.State; } }
        public int PositiveProgramReplies { get { lock(sync)return candidate.PositiveProgramReplies; } }
        public int ChecksumErrors { get { lock(sync)return candidate.ChecksumErrors; } }
        public int IgnoredOtherSources { get { lock(sync)return ignoredOtherSources; } }
        public int TrailingCleanupReplies { get { lock(sync)return trailingCleanupReplies; } }
        public bool CompleteSavedComparison { get { lock(sync)return candidate.CompleteSavedComparison; } }
        public int? ChangedPersistentBankBytes { get { lock(sync)return candidate.ChangedPersistentBankBytes; } }
        public int? ChangedOtherProtectedBytes { get { lock(sync)return candidate.ChangedOtherProtectedBytes; } }
        public string OriginalReferenceSha256 { get { lock(sync)return candidate.BaselineSha256; } }
        public bool HasSavedPreparedBankReference { get { lock(sync)return candidate.HasSavedPreparedBankReference; } }
        public string? PreparedBanksSha256 { get { lock(sync)return candidate.PreparedBanksSha256; } }
        public int? SavedPreparationChangedBytes { get { lock(sync)return candidate.SavedPreparationChangedBytes; } }
        internal void RecordSavedPreparedBanks(byte[] bytes)
        {
            lock(sync)
            {
                RequireSendSlot();
                if(candidate.State!=AL5CapturedWriteState.EraseRequest)throw new InvalidOperationException("Prepared reference belongs only to the before-erase phase.");
                candidate.RecordSavedPreparedBanks(bytes);
            }
        }
        public bool LiveUploadEnabled => false;
        public bool LiveExecutionEnabled => false;
        public bool LiveWriteEnabled => false;
        public bool AutomaticRetryEnabled => false;
        public bool ReadyToFlash => false;
        public bool SecurityAuthorizationProven => false;
        public bool ReplyFreshnessProven => false;
        public bool PhysicalOperationSucceededKnown => false;

        public AL5OfflineDispatchState State
        {
            get
            {
                lock(sync)
                {
                    if(stopReason!=AL5OfflineDispatchStop.None || candidate.State==AL5CapturedWriteState.Stopped)return AL5OfflineDispatchState.Stopped;
                    if(pending!=null)return AL5OfflineDispatchState.DispatchPrepared;
                    if(awaitingReply)return AL5OfflineDispatchState.AwaitingReply;
                    if(IsBoundaryReached())return AL5OfflineDispatchState.BoundaryReached;
                    switch(candidate.NextOfflineAction().Kind)
                    {
                        case AL5OfflineWriteActionKind.SecurityKeyEvidenceRequired:return AL5OfflineDispatchState.AwaitingSecurityEvidence;
                        case AL5OfflineWriteActionKind.ChecksumRetryReviewRequired:return AL5OfflineDispatchState.ChecksumRetryReview;
                        case AL5OfflineWriteActionKind.SavedFullReadbackRequired:return AL5OfflineDispatchState.AwaitingReadback;
                        case AL5OfflineWriteActionKind.Completed:return AL5OfflineDispatchState.Completed;
                        case AL5OfflineWriteActionKind.Stopped:return AL5OfflineDispatchState.Stopped;
                        default:return AL5OfflineDispatchState.ActionAvailable;
                    }
                }
            }
        }

        private void RequireOpen()
        {
            if(State==AL5OfflineDispatchState.Stopped || State==AL5OfflineDispatchState.Completed || State==AL5OfflineDispatchState.BoundaryReached)
                throw new InvalidOperationException("Offline dispatcher is terminal; late callbacks cannot reopen it.");
        }
        private bool IsBoundaryReached()
        {
            switch(Boundary)
            {
                case AL5OfflineWriteBoundary.BeforeSecurityKey:return candidate.NextOfflineAction().Kind==AL5OfflineWriteActionKind.SecurityKeyEvidenceRequired;
                case AL5OfflineWriteBoundary.BeforeProgrammingEntry:return candidate.State==AL5CapturedWriteState.BootRequest;
                case AL5OfflineWriteBoundary.BeforeLoaderUpload:return candidate.State==AL5CapturedWriteState.LoaderTransfer;
                case AL5OfflineWriteBoundary.BeforeErase:return candidate.State==AL5CapturedWriteState.EraseRequest;
                case AL5OfflineWriteBoundary.AfterEraseBeforeData:return candidate.State==AL5CapturedWriteState.Programming;
                default:return false;
            }
        }
        private void RequireSendSlot(bool allowWhileAwaitingReply=false)
        {
            RequireOpen();
            if(pending!=null || (awaitingReply && !allowWhileAwaitingReply))
                throw new InvalidOperationException("A send/reply slot already owns this operation.");
        }
        private AL5OfflineWriteDispatch Reserve(AL5OfflineDispatchKind kind,byte[] bytes)
        {
            sendStartedTicks=clockTicks;
            pending=new AL5OfflineWriteDispatch(checked(++ordinal),kind,bytes,candidate.State,candidate.PositiveProgramReplies,
                kind==AL5OfflineDispatchKind.SecurityEvidence?pendingSecuritySeed:null);
            return pending;
        }

        public AL5OfflineWriteDispatch PrepareNextOfflineDispatch()
        {
            lock(sync)
            {
                RequireSendSlot();var action=candidate.NextOfflineAction();
                if(action.Kind!=AL5OfflineWriteActionKind.FixedControlRequest && action.Kind!=AL5OfflineWriteActionKind.ProgrammingRequest)
                    throw new InvalidOperationException("This phase requires a reply, security evidence, explicit checksum retry review or readback.");
                var kind=AL5OfflineDispatchKind.Control;
                switch(candidate.State)
                {
                    case AL5CapturedWriteState.LoaderTransfer:kind=AL5OfflineDispatchKind.Loader;break;
                    case AL5CapturedWriteState.EraseRequest:kind=AL5OfflineDispatchKind.Erase;break;
                    case AL5CapturedWriteState.Programming:kind=AL5OfflineDispatchKind.Data;break;
                    case AL5CapturedWriteState.FinalizeRequest:kind=AL5OfflineDispatchKind.Finalization;break;
                    case AL5CapturedWriteState.Cleanup:kind=AL5OfflineDispatchKind.Cleanup;break;
                }
                return Reserve(kind,action.CopyRequest());
            }
        }

        public AL5OfflineWriteDispatch PrepareSavedSecurityEvidence(byte[] savedRequest)
        {
            lock(sync)
            {
                RequireSendSlot();
                if(candidate.NextOfflineAction().Kind!=AL5OfflineWriteActionKind.SecurityKeyEvidenceRequired || !pendingSecuritySeed.HasValue)
                    throw new InvalidOperationException("A current saved seed observation must own the key evidence slot.");
                if(savedRequest==null || savedRequest.Length!=7)
                    throw new ArgumentException("Exact saved AL5 key-request evidence required; no key is computed.");
                savedRequest=(byte[])savedRequest.Clone();
                if(savedRequest[0]!=0x6C || savedRequest[1]!=0x18 || savedRequest[2]!=0xF0 || savedRequest[3]!=0x27 || savedRequest[4]!=2)
                    throw new ArgumentException("Exact saved AL5 key-request evidence required; no key is computed.");
                if(pendingSecuritySeed!=AL5CalibrationWriteProfile.SavedSelectorZeroSeed ||
                    ((savedRequest[5]<<8)|savedRequest[6])!=AL5CalibrationWriteProfile.SavedSelectorZeroKey)
                {
                    Stop(AL5OfflineDispatchStop.UnsupportedSecurityProfile);
                    throw new ArgumentException("Saved key evidence differs from the pinned selector-zero profile; no algorithm fallback is permitted.");
                }
                return Reserve(AL5OfflineDispatchKind.SecurityEvidence,savedRequest);
            }
        }

        public AL5OfflineWriteDispatch PrepareChecksumRetryForOfflineReview()
        {
            lock(sync)
            {
                RequireSendSlot();
                if(candidate.NextOfflineAction().Kind!=AL5OfflineWriteActionKind.ChecksumRetryReviewRequired)
                    throw new InvalidOperationException("No checksum-rejected packet owns a retry review slot.");
                if(retriesForBlock>=ChecksumRetryBudgetPerBlock)
                {
                    Stop(AL5OfflineDispatchStop.RetryBudgetExhausted);
                    throw new InvalidOperationException("Caller-selected offline checksum retry budget exhausted.");
                }
                var bytes=candidate.CopyChecksumRejectedRequestForOfflineReview();retriesForBlock++;
                return Reserve(AL5OfflineDispatchKind.ChecksumRetry,bytes);
            }
        }

        public AL5OfflineWriteDispatch PrepareSavedProgrammingBroadcast()
        {
            lock(sync)
            {
                RequireSendSlot(true);
                if(candidate.State!=AL5CapturedWriteState.Programming)throw new InvalidOperationException("Outside captured programming-broadcast phase.");
                return Reserve(AL5OfflineDispatchKind.ProgrammingBroadcast,new byte[]{0x6C,0xFE,0xF0,0x28,0});
            }
        }

        public void CompleteSavedSend(AL5OfflineWriteDispatch dispatch,AL5OfflineSendOutcome outcome)
        {
            lock(sync)
            {
                RequireOpen();
                if(dispatch==null || !Object.ReferenceEquals(pending,dispatch))
                    throw new InvalidOperationException("Stale, foreign or duplicate send completion does not own the current reservation.");
                if(outcome!=AL5OfflineSendOutcome.AdapterAccepted && outcome!=AL5OfflineSendOutcome.NotSubmitted && outcome!=AL5OfflineSendOutcome.SubmissionUnknown)
                    throw new ArgumentOutOfRangeException(nameof(outcome));
                lastSendOutcome=outcome;
                if(outcome!=AL5OfflineSendOutcome.AdapterAccepted)
                {Stop(outcome==AL5OfflineSendOutcome.NotSubmitted?AL5OfflineDispatchStop.SendNotSubmitted:AL5OfflineDispatchStop.SendSubmissionUnknown);return;}
                try{candidate.ObserveSavedFrame(true,dispatch.CopyRequest());}
                catch(ArgumentException){Stop(AL5OfflineDispatchStop.InvalidFrame,dispatch.Phase);throw;}
                catch(InvalidOperationException){Stop(AL5OfflineDispatchStop.ProtocolFailure,dispatch.Phase);throw;}
                pending=null;lastAccepted=dispatch;
                if(dispatch.Kind==AL5OfflineDispatchKind.Loader){lastLoader=dispatch;awaitingLoaderIdentity=true;}
                if(dispatch.Kind!=AL5OfflineDispatchKind.ProgrammingBroadcast)
                {
                    awaitingReply=candidate.NextOfflineAction().Kind==AL5OfflineWriteActionKind.SavedReplyRequired;
                    replyOwner=awaitingReply?dispatch:null;
                    if(awaitingReply)replyStartedTicks=clockTicks;
                }
                if(dispatch.Kind==AL5OfflineDispatchKind.SecurityEvidence)pendingSecuritySeed=null;
            }
        }

        public void ObserveSavedReply(byte[] message)
        {
            lock(sync)
            {
                RequireOpen();
                lastReceivedFrameLength=message?.Length;
                if(message==null || message.Length<3 || message.Length>1602)
                {Stop(AL5OfflineDispatchStop.InvalidFrame);throw new ArgumentException("Saved reply outside the bounded profile.");}
                message=(byte[])message.Clone();
                if(message[2]!=0x18){ignoredOtherSources++;return;}
                lastObservedAl5Reply=message;
                if(awaitingLoaderIdentity)
                {
                    // Native executable upload can jump without a positive ACK.
                    // Its failure/copy-only responses must not become data-block ACKs.
                    if(Exact(message,0x6C,0xF0,0x18,0x76,0x80,0x77))
                    {Stop(AL5OfflineDispatchStop.LoaderChecksumRejected,AL5CapturedWriteState.LoaderTransfer);return;}
                    if(Exact(message,0x6C,0xF0,0x18,0x7F,0x36,0x80,0x06,0x36,0xFF,0x90,0x22))
                    {Stop(AL5OfflineDispatchStop.LoaderRejected,AL5CapturedWriteState.LoaderTransfer);return;}
                    if(Exact(message,0x6C,0xF0,0x18,0x76,0,0x73))
                    {Stop(AL5OfflineDispatchStop.UnqualifiedLoaderReply,AL5CapturedWriteState.LoaderTransfer);return;}
                }
                if(pending==null && !awaitingReply && candidate.State==AL5CapturedWriteState.AwaitingSavedVerification)
                {
                    // The candidate owns the one optional, captured rejected cleanup service.
                    // It is not a new programming reply slot or evidence of recovery.
                    try{candidate.ObserveSavedFrame(false,message);trailingCleanupReplies++;return;}
                    catch(ArgumentException){Stop(AL5OfflineDispatchStop.InvalidFrame,AL5CapturedWriteState.AwaitingSavedVerification);throw;}
                    catch(InvalidOperationException){Stop(AL5OfflineDispatchStop.UnexpectedReply,AL5CapturedWriteState.AwaitingSavedVerification);throw;}
                }
                if(pending!=null || !awaitingReply)
                {Stop(AL5OfflineDispatchStop.UnexpectedReply);throw new InvalidOperationException("No confirmed send owns this AL5 reply.");}
                int before=candidate.PositiveProgramReplies;
                var priorPhase=candidate.State;
                try{candidate.ObserveSavedFrame(false,message);}
                catch(ArgumentException){Stop(AL5OfflineDispatchStop.InvalidFrame,priorPhase);throw;}
                catch(InvalidOperationException){Stop(AL5OfflineDispatchStop.ProtocolFailure,priorPhase);throw;}
                if(candidate.State==AL5CapturedWriteState.Stopped){Stop(AL5OfflineDispatchStop.ProtocolFailure,priorPhase);return;}
                if(priorPhase==AL5CapturedWriteState.LoaderIdentityReply && candidate.State==AL5CapturedWriteState.LoaderSerial)
                    awaitingLoaderIdentity=false;
                lastReplyOwner=replyOwner;
                awaitingReply=candidate.NextOfflineAction().Kind==AL5OfflineWriteActionKind.SavedReplyRequired;
                if(!awaitingReply)replyOwner=null;
                if(before!=candidate.PositiveProgramReplies)retriesForBlock=0;
                if(candidate.NextOfflineAction().Kind==AL5OfflineWriteActionKind.SecurityKeyEvidenceRequired)
                {
                    var seed=AL5SavedSecuritySeed.Parse(message);
                    if(seed.Kind!=AL5SavedSeedKind.Seed){Stop(AL5OfflineDispatchStop.InvalidFrame);return;}
                    pendingSecuritySeed=seed.Seed;lastObservedSeed=seed.Seed;
                    if(seed.Seed!=AL5CalibrationWriteProfile.SavedSelectorZeroSeed)
                    {Stop(AL5OfflineDispatchStop.UnsupportedSecurityProfile);return;}
                }
            }
        }

        private void Stop(AL5OfflineDispatchStop reason,AL5CapturedWriteState? priorPhase=null)
        {
            stopReason=reason;
            if(!phaseAtStop.HasValue)phaseAtStop=priorPhase??candidate.State;
            if(candidate.State!=AL5CapturedWriteState.Stopped && !candidate.CompleteSavedComparison)candidate.TimeoutOrCancel();
            // Preserve pending/lastAccepted records for outcome analysis; do not clear and reuse them.
        }
        private static bool Exact(byte[] message,params byte[] expected)
        {
            if(message.Length!=expected.Length)return false;
            for(int i=0;i<message.Length;i++)if(message[i]!=expected[i])return false;
            return true;
        }
        public void Timeout(){lock(sync){RequireOpen();Stop(AL5OfflineDispatchStop.Timeout);}}
        public void Cancel(){lock(sync){RequireOpen();Stop(AL5OfflineDispatchStop.Cancelled);}}
        internal void StopFromExecutionBinding(AL5OfflineDispatchStop reason)
        {
            lock(sync)
            {
                RequireOpen();
                if(reason!=AL5OfflineDispatchStop.ReceiveFault && reason!=AL5OfflineDispatchStop.InvalidClock && reason!=AL5OfflineDispatchStop.ExecutionWaitFault)throw new ArgumentOutOfRangeException(nameof(reason));
                Stop(reason);
            }
        }
        internal TimeSpan RemainingExecutionWait()
        {
            lock(sync)
            {
                if(timeBudget==null)throw new InvalidOperationException("Execution requires explicit time budgets.");
                long remaining=timeBudget.TotalSession.Ticks-clockTicks;
                if(pending!=null)remaining=Math.Min(remaining,timeBudget.Send.Ticks-(clockTicks-sendStartedTicks));
                if(awaitingReply && replyOwner!=null)remaining=Math.Min(remaining,timeBudget.ReplyBudget(replyOwner).Ticks-(clockTicks-replyStartedTicks));
                return TimeSpan.FromTicks(Math.Max(0,remaining));
            }
        }
        public void AdvanceSavedElapsed(TimeSpan elapsed)
        {
            lock(sync)
            {
                RequireOpen();
                if(elapsed.Ticks<clockTicks)throw new ArgumentOutOfRangeException(nameof(elapsed),"Saved elapsed time must be nonnegative and monotonic.");
                clockTicks=elapsed.Ticks;
                if(timeBudget==null)return;
                // Differences avoid adding a duration to a near-overflow timestamp.
                // Other-source RX and auxiliary broadcasts cannot extend a data reply's deadline.
                if(clockTicks>=timeBudget.TotalSession.Ticks ||
                    (pending!=null && clockTicks-sendStartedTicks>=timeBudget.Send.Ticks) ||
                    (awaitingReply && replyOwner!=null && clockTicks-replyStartedTicks>=timeBudget.ReplyBudget(replyOwner).Ticks))
                    Stop(AL5OfflineDispatchStop.Timeout);
            }
        }
        public byte[] CopyExpectedSavedImage(){lock(sync)return candidate.CopyExpectedSavedImage();}
        public AL5ProgrammingAssessment VerifySavedFullReadback(byte[] image)
        {
            lock(sync)
            {
                RequireOpen();
                if(State!=AL5OfflineDispatchState.AwaitingReadback)throw new InvalidOperationException("Cleanup and all pending operations must finish before verification.");
                var assessment=candidate.VerifySavedFullReadback(image);
                if(!candidate.CompleteSavedComparison)
                {stopReason=AL5OfflineDispatchStop.VerificationFailed;phaseAtStop=AL5CapturedWriteState.AwaitingSavedVerification;}
                return assessment;
            }
        }
    }
}
