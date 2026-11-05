using PcmHacking;

static partial class Program
{
    static async Task CleanupPollCases(string source,bool faultCases)
    {
        AL5WriteExecutionSession Create(MemoryIo io,AL5OfflineCleanupPollPolicy? policy=null,Clock? clock=null,
            AL5OfflineWriteTimeBudget? budgets=null)=>new(loader,calibration,original,3,budgets??Budgets(),
                AL5OfflineWriteBoundary.CompleteOfflineRehearsal,io,clock??new Clock(),new AL5TaskWriteExecutionWaiter(),
                policy??new AL5OfflineCleanupPollPolicy(2,TimeSpan.FromSeconds(5)));
        Peer Template()=>new Peer(lines,original,preserveCleanupRepeats:true);
        void Closed(AL5WriteExecutionReport r)=>Check(!r.PhysicalResetVerified && !r.PostFinalizationReadbackWindowVerified &&
            !r.PhysicalDeadlinesQualified && !r.CleanupIdentityResponsePairingProven && !r.LiveWriteEnabled,
            "Review and identity observation never prove physical reset, correlation or a flash-readback epoch");
        void Record(string name,AL5WriteExecutionReport r)=>results.Add(new {name,source,passed=true,
            outcome=r.Outcome.ToString(),stop_reason=r.StopReason.ToString(),r.CleanupIdentityPollAttempts,
            r.CleanupIdentityPollLimit,r.CleanupIdentityPollWindow,r.SavedFinalizationReplyObserved,
            r.SavedCleanupIdentityObserved,r.SavedCleanupObserved,r.PostFinalizationReadbackWindowVerified});

        {
            var peer=Template();var io=new MemoryIo(peer);var session=Create(io);var r=await Drive(session,peer);
            Check(r.Outcome==AL5WriteExecutionOutcome.CleanupIdentityPollReviewRequired &&
                r.CleanupIdentityPollAttempts==1 && !r.TransportCallOutstanding,"Settled empty cleanup receive owns one review slot");
            Reject(()=>session.VerifySavedReadback(peer.Flash));int sends=io.Sends;
            r=await session.RunUntilReviewAsync(CancellationToken.None);
            Check(io.Sends==sends,"Ordinary resume cannot automatically repeat the cleanup query");
            await RejectAsync(()=>session.ReviewChecksumRetryAsync(CancellationToken.None));
            Check(io.Sends==sends,"Checksum review cannot consume a cleanup review slot");
            r=await session.ReviewCleanupIdentityPollAsync(CancellationToken.None);
            Check(r.Outcome==AL5WriteExecutionOutcome.ReadbackRequired && r.CleanupIdentityPollAttempts==2 &&
                r.SavedCleanupIdentityObserved && r.SavedCleanupObserved && peer.FinalizationsSubmitted==1 &&
                peer.CleanupQueriesSubmitted==2,"Explicit review sends only the second captured cleanup identity query");
            Closed(r);await RejectAsync(()=>session.ReviewCleanupIdentityPollAsync(CancellationToken.None));
            r=session.VerifySavedReadback(peer.Flash);Check(r.Outcome==AL5WriteExecutionOutcome.SavedComparisonMatched,
                "Independent modeled full-image equality remains separate from cleanup polling");
            Closed(r);Record("cleanup_review_replays_captured_two_query_tail",r);
        }
        if(!faultCases)return;
        Reject(()=>new AL5OfflineCleanupPollPolicy(0,TimeSpan.FromSeconds(1)));
        Reject(()=>new AL5OfflineCleanupPollPolicy(2,TimeSpan.Zero));
        Reject(()=>new AL5OfflineCleanupPollPolicy(2,TimeSpan.FromTicks(-1)));
        {
            var peer=Template();var io=new MemoryIo(peer);var session=Create(io);
            await RejectAsync(()=>session.ReviewCleanupIdentityPollAsync(CancellationToken.None));
            Check(io.Sends==0,"Early review cannot send keys, setup, erase, data or finalization");
            Record("cleanup_review_rejects_early_phase_and_invalid_policy",session.Snapshot());
        }
        foreach(int attempts in new[]{1,2})
        {
            var peer=Template();var io=new MemoryIo(peer);
            io.OnReceive=()=>{if(peer.CleanupQueriesSubmitted>=2)io.Mode="empty_receive";};
            var session=Create(io,new AL5OfflineCleanupPollPolicy(attempts,TimeSpan.FromSeconds(5)));
            var r=await Drive(session,peer);
            if(attempts==2)r=await session.ReviewCleanupIdentityPollAsync(CancellationToken.None);
            Check(r.Outcome==AL5WriteExecutionOutcome.Stopped && r.StopReason==AL5OfflineDispatchStop.CleanupPollAttemptsExhausted &&
                peer.CleanupQueriesSubmitted==attempts && peer.FinalizationsSubmitted==1,"Attempt cap includes the first accepted cleanup query");
            int sends=io.Sends;r=await session.ReviewCleanupIdentityPollAsync(CancellationToken.None);
            Check(io.Sends==sends,"Exhausted polling cannot reopen a terminal session");Closed(r);Record("cleanup_attempt_cap_"+attempts,r);
        }
        foreach(bool atDeadline in new[]{false,true})
        {
            var clock=new Clock();var peer=Template();var io=new MemoryIo(peer);
            var window=TimeSpan.FromSeconds(1);var session=Create(io,new AL5OfflineCleanupPollPolicy(2,window),clock);
            var r=await Drive(session,peer);int sends=io.Sends;
            clock.Now=atDeadline?window:window-TimeSpan.FromTicks(1);
            r=await session.ReviewCleanupIdentityPollAsync(CancellationToken.None);
            Check(atDeadline?r.StopReason==AL5OfflineDispatchStop.CleanupPollWindowExpired && io.Sends==sends:
                r.Outcome==AL5WriteExecutionOutcome.ReadbackRequired,"Total polling window includes time spent at review, with an exact boundary");
            Closed(r);Record("cleanup_window_"+(atDeadline?"at_deadline":"one_tick_before"),r);
        }
        {
            var peer=Template();var io=new MemoryIo(peer);var session=Create(io);await Drive(session,peer);
            using var cancel=new CancellationTokenSource();cancel.Cancel();int sends=io.Sends;
            var r=await session.ReviewCleanupIdentityPollAsync(cancel.Token);
            Check(r.StopReason==AL5OfflineDispatchStop.Cancelled && io.Sends==sends,"Cancellation at review does not send another query");
            Closed(r);Record("cleanup_cancel_at_review",r);
        }
        foreach(string mode in new[]{"unknown_send","async_send_fault","async_receive_fault"})
        {
            var peer=Template();var io=new MemoryIo(peer);var session=Create(io);await Drive(session,peer);
            if(mode=="async_receive_fault")io.OnReceive=()=>io.Mode=mode;else io.Mode=mode;
            var r=await session.ReviewCleanupIdentityPollAsync(CancellationToken.None);
            Check(r.Outcome==AL5WriteExecutionOutcome.Stopped && r.StopReason==(mode=="async_receive_fault"?
                AL5OfflineDispatchStop.ReceiveFault:AL5OfflineDispatchStop.SendSubmissionUnknown),"Fault or ambiguous submission cannot grant another poll");
            int sends=io.Sends;await session.ReviewCleanupIdentityPollAsync(CancellationToken.None);
            Check(io.Sends==sends,"Fault remains terminal");Closed(r);Record("cleanup_"+mode,r);
        }
        foreach(string prefix in new[]{"6c18f036ee","6d18f03600","6c18f036ff"})
        {
            var peer=Template();var io=new MemoryIo(peer);
            io.OnReceive=()=>{if(peer.LastSubmittedPrefix==prefix)io.Mode="empty_receive";};
            var session=Create(io);var r=await Drive(session,peer);
            Check(r.StopReason==AL5OfflineDispatchStop.Timeout && r.CleanupIdentityPollAttempts==0,
                "Empty erase, data or finalization receive is not a cleanup identity review");
            int sends=io.Sends;await session.ReviewCleanupIdentityPollAsync(CancellationToken.None);
            Check(io.Sends==sends,"Cleanup policy cannot repeat a destructive phase");Closed(r);Record("cleanup_policy_excludes_"+prefix,r);
        }
        {
            var peer=Template();var io=new MemoryIo(peer);var session=Create(io);await Drive(session,peer);
            io.OnSend=()=>{if(peer.CleanupQueriesSubmitted==2)throw new IOException("Scripted later cleanup send failure");};
            var r=await session.ReviewCleanupIdentityPollAsync(CancellationToken.None);
            Check(r.SavedCleanupIdentityObserved && !r.SavedCleanupObserved && r.Outcome==AL5WriteExecutionOutcome.Stopped,
                "Identity reply does not imply that the remaining cleanup exchanges completed");
            Reject(()=>session.VerifySavedReadback(peer.Flash));Closed(r);Record("cleanup_identity_alone_does_not_unlock_verification",r);
        }
        {
            var peer=Template();var io=new MemoryIo(peer);var session=Create(io);await Drive(session,peer);
            io.OnReceive=()=>{if(peer.LastSubmittedPrefix=="6cfef020")io.Mode="empty_receive";};
            var r=await session.ReviewCleanupIdentityPollAsync(CancellationToken.None);
            Check(r.StopReason==AL5OfflineDispatchStop.Timeout && r.SavedCleanupIdentityObserved && r.CleanupIdentityPollAttempts==2,
                "Other cleanup controls cannot reuse the identity-poll exception");Closed(r);Record("cleanup_policy_excludes_later_controls",r);
        }
        {
            var clock=new Clock();var peer=Template();var io=new MemoryIo(peer);
            var window=TimeSpan.FromMilliseconds(100);var session=Create(io,new AL5OfflineCleanupPollPolicy(2,window),clock);
            await Drive(session,peer);
            io.OnSend=()=>{if(peer.CleanupQueriesSubmitted==2)clock.Now=window;};
            var r=await session.ReviewCleanupIdentityPollAsync(CancellationToken.None);
            Check(r.Outcome==AL5WriteExecutionOutcome.ReadbackRequired && r.SavedCleanupIdentityObserved,
                "Identity-poll window ends at observed identity; later cleanup still has its ordinary control/session budgets");
            Closed(r);Record("cleanup_identity_window_does_not_cover_later_controls",r);
        }
        {
            var peer=Template();var io=new MemoryIo(peer);var session=Create(io,budgets:Budgets(25,1000,60000));
            await Drive(session,peer);io.Mode="hold_send";var r=await session.ReviewCleanupIdentityPollAsync(CancellationToken.None);
            Check(r.TransportCallOutstanding && r.StopReason==AL5OfflineDispatchStop.Timeout && peer.CleanupQueriesSubmitted==1,
                "A pending second-query send is retained, not classified as an empty receive");
            int sends=io.Sends;io.SendCompletion.SetResult(AL5OfflineSendOutcome.AdapterAccepted);
            await session.ObserveOutstandingTransportCompletionAsync();r=await session.ReviewCleanupIdentityPollAsync(CancellationToken.None);
            Check(io.Sends==sends && r.CleanupIdentityPollAttempts==1,"Late send completion cannot reopen cleanup");
            Closed(r);Record("cleanup_pending_send_timeout",r);
        }
        foreach(bool cancelPending in new[]{false,true})
        {
            var peer=Template();var io=new MemoryIo(peer);using var cancel=new CancellationTokenSource();
            io.OnReceive=()=>{if(peer.CleanupQueriesSubmitted==1){io.Mode="hold_receive";if(cancelPending)cancel.Cancel();}};
            var session=Create(io,clock:null,budgets:Budgets(1000,25,60000));
            var r=await Drive(session,peer,cancel.Token);
            Check(r.Outcome==AL5WriteExecutionOutcome.Stopped && r.TransportCallOutstanding && r.StopReason==
                (cancelPending?AL5OfflineDispatchStop.Cancelled:AL5OfflineDispatchStop.Timeout),"Outstanding receive is retained; it is not a settled empty response");
            int sends=io.Sends;io.ReceiveCompletion.SetResult(Hex("6cf0187c550a0012"));
            await session.ObserveOutstandingTransportCompletionAsync();r=await session.ReviewCleanupIdentityPollAsync(CancellationToken.None);
            Check(io.Sends==sends && !r.SavedCleanupIdentityObserved && !r.SavedCleanupObserved,
                "Late identity completion cannot mutate stopped evidence or authorize a repeated poll");
            Reject(()=>session.VerifySavedReadback(peer.Flash));Closed(r);Record("cleanup_pending_"+(cancelPending?"cancel":"timeout"),r);
        }
    }
}
