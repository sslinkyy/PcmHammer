// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace PcmHacking
{
    public enum AL5WriteExecutionOutcome { LiveDisabled, BoundaryReached, SecurityReviewRequired, ChecksumReviewRequired, ReadbackRequired, SavedComparisonMatched, Stopped, Executing, PreparationBackupReviewRequired, CleanupIdentityPollReviewRequired }

    public sealed class AL5WriteExecutionReport
    {
        internal AL5WriteExecutionReport(AL5WriteExecutionOutcome outcome,AL5OfflineDispatchState? state,
            AL5OfflineDispatchStop? reason,int sends,int receives,int blocks,bool outstanding,string? error,
            string? originalHash=null,string? preparedHash=null,int? preparationChanges=null,
            AL5SavedSecurityState? securityState=null,AL5SavedSecurityFailure? securityFailure=null,byte? securityStatus=null,string? backupEvidenceId=null,
            bool savedFinalizationReplyObserved=false,bool savedCleanupObserved=false,
            int cleanupIdentityPollAttempts=0,bool savedCleanupIdentityObserved=false,AL5OfflineCleanupPollPolicy? cleanupPolicy=null)
        {Outcome=outcome;DispatcherState=state;StopReason=reason;SendCalls=sends;ReceiveCalls=receives;AcknowledgedBlocks=blocks;TransportCallOutstanding=outstanding;TransportError=error;OriginalReferenceSha256=originalHash;PreparedBanksSha256=preparedHash;SavedPreparationChangedBytes=preparationChanges;SavedSecurityState=securityState;SavedSecurityFailure=securityFailure;SavedSecurityStatus=securityStatus;BackupEvidenceId=backupEvidenceId;SavedFinalizationReplyObserved=savedFinalizationReplyObserved;SavedCleanupObserved=savedCleanupObserved;CleanupIdentityPollAttempts=cleanupIdentityPollAttempts;SavedCleanupIdentityObserved=savedCleanupIdentityObserved;CleanupIdentityPollLimit=cleanupPolicy?.MaximumAttempts;CleanupIdentityPollWindow=cleanupPolicy?.TotalWindow;}
        public AL5WriteExecutionOutcome Outcome { get; }
        public AL5OfflineDispatchState? DispatcherState { get; }
        public AL5OfflineDispatchStop? StopReason { get; }
        public int SendCalls { get; }
        public int ReceiveCalls { get; }
        public int AcknowledgedBlocks { get; }
        public bool TransportCallOutstanding { get; }
        public string? TransportError { get; }
        public string? OriginalReferenceSha256 { get; }
        public string? PreparedBanksSha256 { get; }
        public int? SavedPreparationChangedBytes { get; }
        public AL5SavedSecurityState? SavedSecurityState { get; }
        public AL5SavedSecurityFailure? SavedSecurityFailure { get; }
        public byte? SavedSecurityStatus { get; }
        public string? BackupEvidenceId { get; }
        public bool PhysicalBackupVerified=>false;
        public bool LiveUploadEnabled => false;
        public bool LiveExecutionEnabled => false;
        public bool LiveWriteEnabled => false;
        public bool ReadyToFlash => false;
        public bool PhysicalReadbackVerified => false;
        public bool RecoveryVerified => false;
        public bool SavedFinalizationReplyObserved { get; }
        public bool SavedCleanupObserved { get; }
        public int CleanupIdentityPollAttempts { get; }
        public bool SavedCleanupIdentityObserved { get; }
        public int? CleanupIdentityPollLimit { get; }
        public TimeSpan? CleanupIdentityPollWindow { get; }
        public bool CleanupIdentityResponsePairingProven=>false;
        public bool PhysicalResetVerified=>false;
        public bool PostFinalizationReadbackWindowVerified=>false;
        public bool PhysicalDeadlinesQualified=>false;
        internal static AL5WriteExecutionReport Disabled()=>new AL5WriteExecutionReport(AL5WriteExecutionOutcome.LiveDisabled,null,null,0,0,0,false,null);
    }

    /// <summary>The production entry point is unconditionally disabled before any dependency access.</summary>
    public static class AL5CalibrationWriteExecutor
    {
        public static Task<AL5WriteExecutionReport> WriteUnchangedCalibrationAsync(Vehicle vehicle,byte[] loader,
            byte[] calibration,byte[] fullOriginalReference,AL5OfflineWriteTimeBudget budgets,CancellationToken cancellationToken)
        {
            // No force option, capability boolean, captured key default or environment override.
            // Hardware qualification and a separately reviewed binding are still required.
            return Task.FromResult(AL5WriteExecutionReport.Disabled());
        }
    }

    internal abstract class AL5WriteExecutionIo
    {
        private object? owner;
        internal void Claim(object session)
        {
            if(Interlocked.CompareExchange(ref owner,session,null)!=null)
                throw new InvalidOperationException("This one-shot execution link already belongs to a session; it cannot be reused after a pause or failure.");
        }
        public abstract Task<AL5OfflineSendOutcome> SendAsync(byte[] request);
        public abstract Task<byte[]?> ReceiveAsync();
    }

    /// <summary>Compiled Vehicle binding, constructed only by internal scripted tests at this checkpoint.</summary>
    internal sealed class AL5VehicleWriteExecutionIo : AL5WriteExecutionIo
    {
        private readonly Vehicle vehicle;
        internal AL5VehicleWriteExecutionIo(Vehicle vehicle){this.vehicle=vehicle??throw new ArgumentNullException(nameof(vehicle));}
        public override async Task<AL5OfflineSendOutcome> SendAsync(byte[] request)
        {
            bool accepted=await vehicle.SendMessage(new Message(request)).ConfigureAwait(false);
            // A false result may follow a transmitted packet. Never classify it as not submitted.
            return accepted?AL5OfflineSendOutcome.AdapterAccepted:AL5OfflineSendOutcome.SubmissionUnknown;
        }
        public override async Task<byte[]?> ReceiveAsync()
        {
            Message reply=await vehicle.ReceiveMessage().ConfigureAwait(false);
            return reply?.GetBytes();
        }
    }

    internal interface IAL5WriteExecutionClock { TimeSpan Elapsed { get; } }
    internal sealed class AL5StopwatchExecutionClock : IAL5WriteExecutionClock
    {
        private readonly Stopwatch watch=Stopwatch.StartNew();
        public TimeSpan Elapsed=>watch.Elapsed;
    }
    internal enum AL5WriteWaitOutcome { Completed, TimedOut, Cancelled }
    internal interface IAL5WriteExecutionWaiter
    {
        Task<AL5WriteWaitOutcome> WaitAsync(Task operation,TimeSpan remaining,CancellationToken cancellationToken);
    }
    internal sealed class AL5TaskWriteExecutionWaiter : IAL5WriteExecutionWaiter
    {
        public async Task<AL5WriteWaitOutcome> WaitAsync(Task operation,TimeSpan remaining,CancellationToken cancellationToken)
        {
            if(operation.IsCompleted)return AL5WriteWaitOutcome.Completed;
            if(cancellationToken.IsCancellationRequested)return AL5WriteWaitOutcome.Cancelled;
            if(remaining<=TimeSpan.Zero)return AL5WriteWaitOutcome.TimedOut;
            using(var timer=CancellationTokenSource.CreateLinkedTokenSource(cancellationToken,CancellationToken.None))
            {
                Task delay=Task.Delay(remaining,timer.Token);
                await Task.WhenAny(operation,delay).ConfigureAwait(false);
                if(operation.IsCompleted){timer.Cancel();return AL5WriteWaitOutcome.Completed;}
                return cancellationToken.IsCancellationRequested?AL5WriteWaitOutcome.Cancelled:AL5WriteWaitOutcome.TimedOut;
            }
        }
    }

    /// <summary>
    /// Shared asynchronous execution core. Internal test access exercises the production Vehicle binding
    /// using a scripted Device. The public live entry point above never constructs this core or its I/O.
    /// No captured-key fallback, automatic checksum retry, reset, queue clear or device disposal exists.
    /// </summary>
    internal sealed class AL5WriteExecutionSession
    {
        private readonly AL5OfflineWriteDispatcher dispatcher;
        private readonly AL5WriteExecutionIo io;
        private readonly IAL5WriteExecutionClock clock;
        private readonly IAL5WriteExecutionWaiter waiter;
        private Task? ownedOperation;
        private int running,sends,receives;
        private string? transportError;
        private string? backupEvidenceId;
        private readonly TimeSpan clockOrigin;

        internal AL5WriteExecutionSession(byte[] loader,byte[] calibration,byte[] reference,int retryBudget,
            AL5OfflineWriteTimeBudget budgets,AL5OfflineWriteBoundary boundary,AL5WriteExecutionIo io,
            IAL5WriteExecutionClock clock,IAL5WriteExecutionWaiter waiter,AL5OfflineCleanupPollPolicy? cleanupPollPolicy=null)
        {
            if(budgets==null || io==null || clock==null || waiter==null)throw new ArgumentNullException();
            // Task.Delay on this netstandard runtime cannot represent a wait beyond Int32 milliseconds.
            foreach(var duration in new[]{budgets.Send,budgets.ControlReply,budgets.EraseReply,budgets.DataReply,budgets.FinalizationReply,budgets.TotalSession})
                if(duration.TotalMilliseconds>int.MaxValue)throw new ArgumentOutOfRangeException(nameof(budgets),"Execution wait exceeds the runtime Task.Delay limit.");
            if(reference==null || reference.Length!=0x100000 || calibration==null || calibration.Length!=AL5CalibrationInspection.Length)
                throw new ArgumentException("Exact original reference and calibration required.");
            var original=(byte[])reference.Clone();var candidate=(byte[])calibration.Clone();
            for(int i=0;i<candidate.Length;i++)if(candidate[i]!=original[0x8000+i])
                throw new ArgumentException("The first qualification executor accepts unchanged calibration only.");
            dispatcher=new AL5OfflineWriteDispatcher(loader,candidate,original,retryBudget,budgets,boundary,cleanupPollPolicy);
            this.io=io;this.clock=clock;this.waiter=waiter;
            clockOrigin=clock.Elapsed;
            if(clockOrigin<TimeSpan.Zero)throw new ArgumentOutOfRangeException(nameof(clock),"Execution clock must be nonnegative.");
            io.Claim(this);
        }

        internal AL5OfflineWriteDispatch? PendingDispatch=>dispatcher.PendingDispatch;
        internal AL5OfflineWriteDispatch? ReplyOwner=>dispatcher.ReplyOwnerDispatch;
        internal TaskStatus? OwnedOperationStatus=>ownedOperation?.Status;
        internal bool TransportCallOutstanding=>ownedOperation!=null && !ownedOperation.IsCompleted;
        internal AL5WriteExecutionReport Snapshot()
        {
            var state=dispatcher.State;AL5WriteExecutionOutcome outcome;
            switch(state)
            {
                case AL5OfflineDispatchState.BoundaryReached:outcome=AL5WriteExecutionOutcome.BoundaryReached;break;
                case AL5OfflineDispatchState.AwaitingSecurityEvidence:outcome=AL5WriteExecutionOutcome.SecurityReviewRequired;break;
                case AL5OfflineDispatchState.ChecksumRetryReview:outcome=AL5WriteExecutionOutcome.ChecksumReviewRequired;break;
                case AL5OfflineDispatchState.CleanupIdentityPollReview:outcome=AL5WriteExecutionOutcome.CleanupIdentityPollReviewRequired;break;
                case AL5OfflineDispatchState.AwaitingReadback:outcome=AL5WriteExecutionOutcome.ReadbackRequired;break;
                case AL5OfflineDispatchState.Completed:outcome=AL5WriteExecutionOutcome.SavedComparisonMatched;break;
                case AL5OfflineDispatchState.ActionAvailable:
                case AL5OfflineDispatchState.DispatchPrepared:
                case AL5OfflineDispatchState.AwaitingReply:outcome=AL5WriteExecutionOutcome.Executing;break;
                default:outcome=AL5WriteExecutionOutcome.Stopped;break;
            }
            if(state==AL5OfflineDispatchState.ActionAvailable && dispatcher.ProtocolState==AL5CapturedWriteState.EraseRequest && !dispatcher.HasSavedPreparedBankReference)
                outcome=AL5WriteExecutionOutcome.PreparationBackupReviewRequired;
            return new AL5WriteExecutionReport(outcome,state,dispatcher.StopReason,sends,receives,dispatcher.PositiveProgramReplies,TransportCallOutstanding,transportError,
                dispatcher.OriginalReferenceSha256,dispatcher.PreparedBanksSha256,dispatcher.SavedPreparationChangedBytes,
                dispatcher.SavedSecurityState,dispatcher.SavedSecurityFailure,dispatcher.SavedSecurityStatus,backupEvidenceId,
                dispatcher.SavedFinalizationReplyObserved,dispatcher.SavedCleanupObserved,
                dispatcher.CleanupIdentityPollAttempts,dispatcher.SavedCleanupIdentityObserved,dispatcher.CleanupPollPolicy);
        }

        internal Task<AL5WriteExecutionReport> RunUntilReviewAsync(CancellationToken token)=>RunExclusiveAsync(null,false,null,token);
        internal Task<AL5WriteExecutionReport> SubmitSavedSecurityEvidenceAsync(byte[] request,CancellationToken token)=>RunExclusiveAsync(request,false,null,token);
        internal Task<AL5WriteExecutionReport> ReviewChecksumRetryAsync(CancellationToken token)=>RunExclusiveAsync(null,true,null,token);
        internal Task<AL5WriteExecutionReport> ReviewCleanupIdentityPollAsync(CancellationToken token)=>RunExclusiveAsync(null,false,null,token,null,true);
        internal Task<AL5WriteExecutionReport> RecordSavedPreparedBanksAsync(byte[] banks,CancellationToken token)=>RunExclusiveAsync(null,false,banks,token);
        internal Task<AL5WriteExecutionReport> RecordSavedBackupPathAsync(AL5SavedBackupPath backup,CancellationToken token)
        {
            if(backup==null)throw new ArgumentNullException(nameof(backup));
            return RunExclusiveAsync(null,false,null,token,backup);
        }
        private async Task<AL5WriteExecutionReport> RunExclusiveAsync(byte[]? keyEvidence,bool retry,byte[]? preparedBanks,CancellationToken token,AL5SavedBackupPath? backup=null,bool cleanupPollReview=false)
        {
            if(Interlocked.CompareExchange(ref running,1,0)!=0)throw new InvalidOperationException("An execution call already owns this session.");
            try
            {
                if(IsTerminal())return Snapshot();
                if(!AdvanceOrStop(token))return Snapshot();
                if(backup!=null)
                {
                    var epochs=backup.CopyPreparedReference();
                    if(backup.OriginalSha256!=dispatcher.OriginalReferenceSha256)
                        throw new ArgumentException("The correlated backup belongs to a different original image.");
                    dispatcher.RecordSavedPreparedBanks(epochs.CopyPrepared());
                    backupEvidenceId=backup.EvidenceId;
                }
                if(preparedBanks!=null)dispatcher.RecordSavedPreparedBanks(preparedBanks);
                if(keyEvidence!=null || retry || cleanupPollReview)
                {
                    AL5OfflineWriteDispatch request;
                    try{request=cleanupPollReview?dispatcher.PrepareCleanupIdentityPollForOfflineReview():retry?dispatcher.PrepareChecksumRetryForOfflineReview():dispatcher.PrepareSavedSecurityEvidence(keyEvidence!);}
                    catch(InvalidOperationException){if(IsTerminal())return Snapshot();throw;}
                    if(!await SendAsync(request,token).ConfigureAwait(false))return Snapshot();
                }
                while(!IsTerminal())
                {
                    if(!AdvanceOrStop(token))break;
                    if(dispatcher.State==AL5OfflineDispatchState.ActionAvailable)
                    {
                        if(dispatcher.ProtocolState==AL5CapturedWriteState.EraseRequest && !dispatcher.HasSavedPreparedBankReference)break;
                        if(!await SendAsync(dispatcher.PrepareNextOfflineDispatch(),token).ConfigureAwait(false))break;
                    }
                    else if(dispatcher.State==AL5OfflineDispatchState.AwaitingReply)
                    {
                        if(!await ReceiveAsync(token).ConfigureAwait(false))break;
                    }
                    else break; // An explicit review/readback/boundary is required, never an automatic retry/key.
                }
                return Snapshot();
            }
            finally{Interlocked.Exchange(ref running,0);}
        }

        private bool IsTerminal()=>dispatcher.State==AL5OfflineDispatchState.Stopped || dispatcher.State==AL5OfflineDispatchState.Completed || dispatcher.State==AL5OfflineDispatchState.BoundaryReached;
        private bool AdvanceOrStop(CancellationToken token)
        {
            if(IsTerminal())return false;
            if(token.IsCancellationRequested){dispatcher.Cancel();return false;}
            return AdvanceClockOrStop();
        }
        private bool AdvanceClockOrStop()
        {
            if(IsTerminal())return false;
            try
            {
                var observed=clock.Elapsed;
                if(observed<clockOrigin)throw new ArgumentOutOfRangeException(nameof(clock),"Execution clock moved before its origin.");
                dispatcher.AdvanceSavedElapsed(observed-clockOrigin);
            }
            catch(Exception error){transportError=error.Message;dispatcher.StopFromExecutionBinding(AL5OfflineDispatchStop.InvalidClock);}
            return !IsTerminal();
        }
        private void Own(Task operation)
        {
            if(TransportCallOutstanding)throw new InvalidOperationException("An unresolved transport call still belongs to this session.");
            ownedOperation=operation;
            // Observe a late fault without ever applying a late result to the stopped dispatcher.
            _=operation.ContinueWith(ObserveLateFault,CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted|TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
        }
        private void ObserveLateFault(Task task)
        {
            // Instance continuation retains this owner until an outstanding operation settles.
            var error=task.Exception;if(error!=null)transportError=error.GetBaseException().Message;
        }
        private async Task<bool> WaitAsync(Task operation,CancellationToken token)
        {
            Own(operation);
            AL5WriteWaitOutcome result;
            try{result=await waiter.WaitAsync(operation,dispatcher.RemainingExecutionWait(),token).ConfigureAwait(false);}
            catch(Exception error)
            {transportError=error.Message;dispatcher.StopFromExecutionBinding(AL5OfflineDispatchStop.ExecutionWaitFault);return false;}
            if(result==AL5WriteWaitOutcome.Completed)return true;
            if(result!=AL5WriteWaitOutcome.Cancelled && result!=AL5WriteWaitOutcome.TimedOut)
            {transportError="Unsupported execution wait outcome: "+result;dispatcher.StopFromExecutionBinding(AL5OfflineDispatchStop.ExecutionWaitFault);return false;}
            if(result==AL5WriteWaitOutcome.Cancelled)dispatcher.Cancel();else dispatcher.Timeout();
            return false; // ownedOperation remains retained, even though awaiting it stopped.
        }
        private async Task<bool> SendAsync(AL5OfflineWriteDispatch request,CancellationToken token)
        {
            Task<AL5OfflineSendOutcome> operation;
            try{sends++;operation=io.SendAsync(request.CopyRequest())??throw new InvalidOperationException("Send returned no task.");}
            catch(Exception error){transportError=error.Message;dispatcher.CompleteSavedSend(request,AL5OfflineSendOutcome.SubmissionUnknown);return false;}
            if(!await WaitAsync(operation,token).ConfigureAwait(false))return false;
            AL5OfflineSendOutcome outcome;
            try{outcome=await operation.ConfigureAwait(false);}
            catch(Exception error){transportError=error.Message;outcome=AL5OfflineSendOutcome.SubmissionUnknown;}
            if(outcome!=AL5OfflineSendOutcome.AdapterAccepted && outcome!=AL5OfflineSendOutcome.NotSubmitted && outcome!=AL5OfflineSendOutcome.SubmissionUnknown)
            {transportError="Unsupported send outcome: "+outcome;outcome=AL5OfflineSendOutcome.SubmissionUnknown;}
            if(!AdvanceClockOrStop())return false;
            // Record the actual completed send before honoring a racing cancellation.
            dispatcher.CompleteSavedSend(request,outcome);
            return AdvanceOrStop(token);
        }
        private async Task<bool> ReceiveAsync(CancellationToken token)
        {
            Task<byte[]?> operation;
            try{receives++;operation=io.ReceiveAsync()??throw new InvalidOperationException("Receive returned no task.");}
            catch(Exception error){transportError=error.Message;dispatcher.StopFromExecutionBinding(AL5OfflineDispatchStop.ReceiveFault);return false;}
            if(!await WaitAsync(operation,token).ConfigureAwait(false))return false;
            byte[]? reply;
            try{reply=await operation.ConfigureAwait(false);}
            catch(Exception error){transportError=error.Message;dispatcher.StopFromExecutionBinding(AL5OfflineDispatchStop.ReceiveFault);return false;}
            if(!AdvanceOrStop(token))return false;
            if(reply==null){dispatcher.RecordCompletedEmptyReceive();return false;}
            try{dispatcher.ObserveSavedReply(reply);}
            catch(ArgumentException error){transportError=error.Message;return false;}
            catch(InvalidOperationException error){transportError=error.Message;return false;}
            return !IsTerminal();
        }

        internal AL5WriteExecutionReport VerifySavedReadback(byte[] bytes)
        {
            if(Interlocked.CompareExchange(ref running,1,0)!=0)throw new InvalidOperationException("An execution call already owns this session.");
            try
            {
                if(TransportCallOutstanding)throw new InvalidOperationException("Transport ownership must settle before saved readback verification.");
                dispatcher.VerifySavedFullReadback(bytes);return Snapshot();
            }
            finally{Interlocked.Exchange(ref running,0);}
        }
        internal async Task ObserveOutstandingTransportCompletionAsync()
        {
            Task? operation=ownedOperation;if(operation==null)return;
            try{await operation.ConfigureAwait(false);}catch(Exception error){transportError=error.Message;}
            // No CompleteSavedSend, response application, session restart or transport cleanup.
        }
    }
}
