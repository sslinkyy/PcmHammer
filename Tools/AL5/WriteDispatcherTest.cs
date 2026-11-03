using System;
using System.IO;
using System.Linq;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using PcmHacking;

static class WriteDispatcherTest
{
    static byte[] loader=Array.Empty<byte>(),reference=Array.Empty<byte>(),calibration=Array.Empty<byte>();
    static string[] lines=Array.Empty<string>();
    static int checks;
    static void Check(bool value,string why)
    {checks++;if(!value)throw new Exception("Dispatcher: "+why);}
    static void Reject(Action action)
    {checks++;try{action();}catch(ArgumentException){return;}catch(InvalidOperationException){return;}throw new Exception("Expected dispatch rejection");}
    static byte[] Bytes(string line)=>Convert.FromHexString(line.Substring(2));
    static bool Data(byte[] m)=>m.Length>12 && m[3]==0x36 && m[4]==0;
    static bool Broadcast(byte[] m)=>m.SequenceEqual(Convert.FromHexString("6cfef02800"));
    static AL5OfflineWriteDispatcher New(int budget=3,byte[]? custom=null,AL5OfflineWriteTimeBudget? timing=null,
        AL5OfflineWriteBoundary boundary=AL5OfflineWriteBoundary.CompleteOfflineRehearsal)=>new AL5OfflineWriteDispatcher(loader,custom??calibration,reference,budget,timing,boundary);
    static void Blocked(AL5OfflineWriteDispatcher d)=>Check(!d.LiveUploadEnabled && !d.LiveExecutionEnabled &&
        !d.LiveWriteEnabled && !d.ReadyToFlash && !d.AutomaticRetryEnabled && !d.SecurityAuthorizationProven &&
        !d.ReplyFreshnessProven && !d.PhysicalOperationSucceededKnown,"physical authority stays false");

    // This driver uses captured replies as test stimuli. Omitted ambiguous repeats
    // are counted explicitly: this is a derived scenario, not an exact raw replay.
    static bool Apply(AL5OfflineWriteDispatcher d,string line,bool allowOmittedRepeats,bool substituteData=false)
    {
        bool tx=line[0]=='T';var m=Bytes(line);
        if(!tx){d.ObserveSavedReply(m);return true;}
        AL5OfflineWriteDispatch dispatch;
        if(Broadcast(m) && d.ProtocolState==AL5CapturedWriteState.Programming)
            dispatch=d.PrepareSavedProgrammingBroadcast();
        else if(d.State==AL5OfflineDispatchState.AwaitingReply)
        {
            Check(d.ReplyOwnerDispatch!=null,"repeat has a preceding reply owner");
            if(!substituteData || !Data(m))Check(d.ReplyOwnerDispatch!.CopyRequest().SequenceEqual(m),"omitted repeat bytes identical");
            Reject(()=>d.PrepareNextOfflineDispatch());
            if(!allowOmittedRepeats)throw new InvalidOperationException("Raw capture has an unqualified repeat without a reply.");
            return false;
        }
        else if(d.State==AL5OfflineDispatchState.AwaitingSecurityEvidence)
        {
            Reject(()=>d.PrepareNextOfflineDispatch());dispatch=d.PrepareSavedSecurityEvidence(m);
            Check(dispatch.SavedSeed==0x9CE5,"key evidence belongs to current saved seed");
        }
        else if(d.State==AL5OfflineDispatchState.ChecksumRetryReview)
        {Reject(()=>d.PrepareNextOfflineDispatch());dispatch=d.PrepareChecksumRetryForOfflineReview();}
        else dispatch=d.PrepareNextOfflineDispatch();
        var bytes=dispatch.CopyRequest();
        if(!substituteData || !Data(m))Check(bytes.SequenceEqual(m),"constructed send matches scenario");
        else Check(bytes.Length==m.Length && bytes.Take(10).SequenceEqual(m.Take(10)),"custom block retains extent/header");
        Check(d.State==AL5OfflineDispatchState.DispatchPrepared,"reservation precedes send outcome");
        Reject(()=>d.PrepareNextOfflineDispatch());
        d.CompleteSavedSend(dispatch,AL5OfflineSendOutcome.AdapterAccepted);
        Reject(()=>d.CompleteSavedSend(dispatch,AL5OfflineSendOutcome.AdapterAccepted));
        return true;
    }
    static AL5OfflineWriteDispatcher ThroughFirstData(int budget=3)
    {
        var d=New(budget);
        foreach(var line in lines)
        {
            Apply(d,line,true);
            if(line[0]=='T' && Data(Bytes(line)))
            {Check(d.State==AL5OfflineDispatchState.AwaitingReply,"first data waits for reply");return d;}
        }
        throw new Exception("No data request");
    }
    static void OwnershipAndSendOutcomes()
    {
        foreach(var outcome in new[]{AL5OfflineSendOutcome.NotSubmitted,AL5OfflineSendOutcome.SubmissionUnknown})
        {
            var d=New();var dispatch=d.PrepareNextOfflineDispatch();var phase=d.ProtocolState;
            var other=New();var foreign=other.PrepareNextOfflineDispatch();
            Reject(()=>d.CompleteSavedSend(foreign,AL5OfflineSendOutcome.AdapterAccepted));
            Check(d.ProtocolState==phase && Object.ReferenceEquals(d.PendingDispatch,dispatch),"foreign completion cannot consume owner");
            Reject(()=>d.CompleteSavedSend(dispatch,(AL5OfflineSendOutcome)99));
            var copy=dispatch.CopyRequest();copy[0]^=1;Check(copy[0]!=dispatch.CopyRequest()[0],"dispatch bytes owned");
            d.CompleteSavedSend(dispatch,outcome);
            Check(d.State==AL5OfflineDispatchState.Stopped && Object.ReferenceEquals(d.PendingDispatch,dispatch),"failed submission retains reservation");
            Check(d.ProtocolPhaseAtStop==phase,"failed submission retains the protocol phase");
            Check(d.LastSendOutcome==outcome && d.LastAdapterAcceptedDispatch==null,"no fictitious successful send");
            Check(d.StopReason==(outcome==AL5OfflineSendOutcome.NotSubmitted?AL5OfflineDispatchStop.SendNotSubmitted:AL5OfflineDispatchStop.SendSubmissionUnknown),"submission uncertainty kept distinct");
            Reject(()=>d.CompleteSavedSend(dispatch,AL5OfflineSendOutcome.AdapterAccepted));Blocked(d);
        }
        foreach(bool cancel in new[]{false,true})
        {
            var d=New();var request=d.PrepareNextOfflineDispatch();
            if(cancel)d.Cancel();else d.Timeout();
            Check(d.StopReason==(cancel?AL5OfflineDispatchStop.Cancelled:AL5OfflineDispatchStop.Timeout),"cancel/timeout distinguished");
            Check(Object.ReferenceEquals(request,d.PendingDispatch),"unresolved send retained after stop");
            Reject(()=>d.CompleteSavedSend(request,AL5OfflineSendOutcome.AdapterAccepted));
            Reject(()=>d.PrepareNextOfflineDispatch());Blocked(d);
        }
        var early=New();early.PrepareNextOfflineDispatch();
        Reject(()=>early.ObserveSavedReply(Convert.FromHexString("6cf0187c550a0012")));
        Check(early.StopReason==AL5OfflineDispatchStop.UnexpectedReply,"reply before send completion cannot advance");
        var normal=New();var first=normal.PrepareNextOfflineDispatch();normal.CompleteSavedSend(first,AL5OfflineSendOutcome.AdapterAccepted);
        normal.ObserveSavedReply(Convert.FromHexString("6cf0107c550a0012"));Check(normal.IgnoredOtherSources==1,"other module ignored");
        normal.ObserveSavedReply(Convert.FromHexString("6cf0187c550a0012"));var second=normal.PrepareNextOfflineDispatch();
        Reject(()=>normal.CompleteSavedSend(first,AL5OfflineSendOutcome.AdapterAccepted));
        Check(Object.ReferenceEquals(second,normal.PendingDispatch),"late first completion leaves second owner intact");
        normal.CompleteSavedSend(second,AL5OfflineSendOutcome.AdapterAccepted);Blocked(normal);
    }
    static void ProfileAndSecurityGates()
    {
        Check(AL5CalibrationWriteProfile.InspectSavedReference(reference,calibration).SavedBytesMatchProfile,"saved firmware profile matches");
        foreach(int address in new[]{0,0x3FD8,0x20000,0xC5F93})
        {
            var changed=(byte[])reference.Clone();changed[address]^=1;
            Reject(()=>new AL5OfflineWriteDispatcher(loader,calibration,changed,3));
            Check(!AL5CalibrationWriteProfile.InspectSavedReference(changed,calibration).SavedBytesMatchProfile,"changed boot/OS rejected");
        }
        var selector=(byte[])calibration.Clone();selector[AL5CalibrationWriteProfile.SecuritySelectorAddress-0x8000]=1;
        Convert.FromHexString(AL5CalibrationInspection.Inspect(selector).ComputedChecksumHex!).CopyTo(selector,selector.Length-4);
        Check(AL5CalibrationInspection.Inspect(selector).ChecksPass,"unsupported selector fixture is checksum-correct");
        Reject(()=>New(custom:selector));
        var baselineSelector=(byte[])reference.Clone();baselineSelector[AL5CalibrationWriteProfile.SecuritySelectorAddress]=1;
        Reject(()=>new AL5OfflineWriteDispatcher(loader,calibration,baselineSelector,3));
        var brokenBaseline=(byte[])reference.Clone();brokenBaseline[0x8100]^=1;
        Reject(()=>new AL5OfflineWriteDispatcher(loader,calibration,brokenBaseline,3));
        Reject(()=>New(-1));
        var owned=(byte[])reference.Clone();var ownedCal=(byte[])calibration.Clone();var ownedLoader=(byte[])loader.Clone();
        var stable=new AL5OfflineWriteDispatcher(ownedLoader,ownedCal,owned,3);var before=stable.CopyExpectedSavedImage();
        owned[0]^=1;ownedCal[0]^=1;ownedLoader[0]^=1;
        Check(stable.CopyExpectedSavedImage().SequenceEqual(before) && stable.SavedProfile.SavedBytesMatchProfile,"dispatcher snapshots own profile inputs");
        Check(!stable.SavedProfile.LiveControllerIdentityVerified && !stable.SavedProfile.LiveSecurityAuthorizationVerified,"saved profile is not a connected target identity");
        foreach(string scenario in new[]{"unknown_seed","short37","wrong_key","replayed_seed"})
        {
            var d=New();bool injected=false;
            foreach(string line in lines)
            {
                var message=Bytes(line);
                if(line.StartsWith("R 6cf0186701",StringComparison.Ordinal))
                {
                    if(scenario=="unknown_seed")
                    {
                        var different=(byte[])message.Clone();different[5]=0x12;different[6]=0x34;d.ObserveSavedReply(different);
                        Check(d.StopReason==AL5OfflineDispatchStop.UnsupportedSecurityProfile,"unknown seed has no generic algorithm fallback");
                        different[5]=0;Check(d.LastObservedSeed==0x1234 && d.CopyLastObservedAl5Reply()![5]==0x12,"unsupported seed observation survives caller mutation");
                        var copy=d.CopyLastObservedAl5Reply()!;copy[5]=0;Check(d.CopyLastObservedAl5Reply()![5]==0x12,"diagnostic reply is independently owned");
                    }
                    else if(scenario=="short37")
                    {
                        Reject(()=>d.ObserveSavedReply(Convert.FromHexString("6cf018670137")));
                        Check(d.State==AL5OfflineDispatchState.Stopped,"short 37 cannot authorize");
                    }
                    else
                    {
                        d.ObserveSavedReply(message);
                        if(scenario=="wrong_key")
                        {
                            Reject(()=>d.PrepareSavedSecurityEvidence(Convert.FromHexString("6c18f02702bc09")));
                            Check(d.StopReason==AL5OfflineDispatchStop.UnsupportedSecurityProfile,"wrong saved key evidence stops");
                        }
                        else
                        {
                            Reject(()=>d.ObserveSavedReply(message));
                            Check(d.StopReason==AL5OfflineDispatchStop.UnexpectedReply,"duplicate seed has no unowned reply slot");
                        }
                    }
                    injected=true;Blocked(d);break;
                }
                Apply(d,line,true);
            }
            Check(injected,"security injection reached current seed boundary");
        }
    }
    static void ConcurrentCallbacks()
    {
        for(int round=0;round<8;round++)
        {
            var d=New();var reserved=new ConcurrentBag<AL5OfflineWriteDispatch>();int failures=0;
            using(var start=new Barrier(3))
            {
                Action prepare=()=>{start.SignalAndWait();try{reserved.Add(d.PrepareNextOfflineDispatch());}catch(InvalidOperationException){Interlocked.Increment(ref failures);}};
                var a=Task.Run(prepare);var b=Task.Run(prepare);start.SignalAndWait();Task.WaitAll(a,b);
            }
            Check(reserved.Count==1 && failures==1,"simultaneous preparations reserve exactly one owner");
            var dispatch=reserved.Single();int completions=0;failures=0;
            using(var start=new Barrier(3))
            {
                Action complete=()=>{start.SignalAndWait();try{d.CompleteSavedSend(dispatch,AL5OfflineSendOutcome.AdapterAccepted);Interlocked.Increment(ref completions);}catch(InvalidOperationException){Interlocked.Increment(ref failures);}};
                var a=Task.Run(complete);var b=Task.Run(complete);start.SignalAndWait();Task.WaitAll(a,b);
            }
            Check(completions==1 && failures==1 && d.State==AL5OfflineDispatchState.AwaitingReply,"duplicate simultaneous completions advance once");
            d=New();dispatch=d.PrepareNextOfflineDispatch();completions=0;
            using(var start=new Barrier(3))
            {
                var a=Task.Run(()=>{start.SignalAndWait();try{d.CompleteSavedSend(dispatch,AL5OfflineSendOutcome.AdapterAccepted);Interlocked.Increment(ref completions);}catch(InvalidOperationException){}});
                var b=Task.Run(()=>{start.SignalAndWait();d.Cancel();});start.SignalAndWait();Task.WaitAll(a,b);
            }
            Check(d.State==AL5OfflineDispatchState.Stopped && d.StopReason==AL5OfflineDispatchStop.Cancelled,"cancellation wins final state against send callback");
            Check(completions==0?Object.ReferenceEquals(d.PendingDispatch,dispatch):Object.ReferenceEquals(d.ReplyOwnerDispatch,dispatch),"race retains the correct unresolved operation");
            Reject(()=>d.CompleteSavedSend(dispatch,AL5OfflineSendOutcome.AdapterAccepted));Blocked(d);
        }
    }
    static void TimingBudgets()
    {
        TimeSpan Ms(int n)=>TimeSpan.FromMilliseconds(n);
        var limits=new AL5OfflineWriteTimeBudget(Ms(10),Ms(20),Ms(30),Ms(40),Ms(50),Ms(100));
        Reject(()=>new AL5OfflineWriteTimeBudget(TimeSpan.Zero,Ms(1),Ms(1),Ms(1),Ms(1),Ms(1)));
        Check(!limits.PhysicalDeadlinesQualified,"test time budgets confer no physical timing qualification");
        var d=New(timing:limits);Check(d.HasExplicitTimeBudget,"budget must be explicit");
        d.AdvanceSavedElapsed(Ms(5));var send=d.PrepareNextOfflineDispatch();d.AdvanceSavedElapsed(Ms(14));
        Check(d.State==AL5OfflineDispatchState.DispatchPrepared,"send budget starts at reservation");
        Reject(()=>d.AdvanceSavedElapsed(Ms(13)));Check(d.SavedElapsed==Ms(14),"regressing clock cannot change elapsed");
        d.AdvanceSavedElapsed(Ms(15));Check(d.StopReason==AL5OfflineDispatchStop.Timeout,"send deadline stops at equality");
        Check(Object.ReferenceEquals(d.PendingDispatch,send),"timed-out send retains uncertain reservation");
        Reject(()=>d.CompleteSavedSend(send,AL5OfflineSendOutcome.AdapterAccepted));Blocked(d);
        d=New(timing:limits);send=d.PrepareNextOfflineDispatch();d.CompleteSavedSend(send,AL5OfflineSendOutcome.AdapterAccepted);
        d.AdvanceSavedElapsed(Ms(19));Check(d.State==AL5OfflineDispatchState.AwaitingReply,"control reply budget");
        d.AdvanceSavedElapsed(Ms(20));Check(d.StopReason==AL5OfflineDispatchStop.Timeout,"control deadline equality");
        foreach(var kind in new[]{AL5OfflineDispatchKind.Erase,AL5OfflineDispatchKind.Data,AL5OfflineDispatchKind.Finalization})
        {
            d=New(timing:limits);bool reached=false;
            foreach(string line in lines)
            {
                Apply(d,line,true);
                if(line[0]=='T' && d.ReplyOwnerDispatch?.Kind==kind && d.State==AL5OfflineDispatchState.AwaitingReply)
                {reached=true;break;}
            }
            Check(reached,"phase-specific reply deadline reached");int duration=kind==AL5OfflineDispatchKind.Erase?30:kind==AL5OfflineDispatchKind.Data?40:50;
            d.AdvanceSavedElapsed(Ms(duration-1));Check(d.State==AL5OfflineDispatchState.AwaitingReply,"phase-specific budget does not use shorter control budget");
            d.AdvanceSavedElapsed(Ms(duration));Check(d.StopReason==AL5OfflineDispatchStop.Timeout,"phase-specific deadline stops");Blocked(d);
        }
        d=New(timing:limits);
        foreach(string line in lines){Apply(d,line,true);if(line[0]=='T' && Data(Bytes(line)))break;}
        var data=d.ReplyOwnerDispatch;d.AdvanceSavedElapsed(Ms(25));
        d.ObserveSavedReply(Convert.FromHexString("6cf010760073"));
        var broadcast=d.PrepareSavedProgrammingBroadcast();d.CompleteSavedSend(broadcast,AL5OfflineSendOutcome.AdapterAccepted);
        Check(Object.ReferenceEquals(data,d.ReplyOwnerDispatch),"auxiliary activity retains reply deadline owner");
        d.AdvanceSavedElapsed(Ms(39));Check(d.State==AL5OfflineDispatchState.AwaitingReply,"data deadline not shortened");
        d.AdvanceSavedElapsed(Ms(40));Check(d.StopReason==AL5OfflineDispatchStop.Timeout,"other traffic and broadcast do not extend deadline");
        var shortSession=new AL5OfflineWriteTimeBudget(Ms(10),Ms(20),Ms(30),Ms(40),Ms(50),Ms(5));
        d=New(timing:shortSession);d.AdvanceSavedElapsed(Ms(5));Check(d.State==AL5OfflineDispatchState.Stopped,"overall budget also covers idle/evidence wait");
        var maximum=new AL5OfflineWriteTimeBudget(TimeSpan.MaxValue,TimeSpan.MaxValue,TimeSpan.MaxValue,TimeSpan.MaxValue,TimeSpan.MaxValue,TimeSpan.MaxValue);
        d=New(timing:maximum);d.AdvanceSavedElapsed(TimeSpan.FromTicks(long.MaxValue-1));d.PrepareNextOfflineDispatch();
        d.AdvanceSavedElapsed(TimeSpan.MaxValue);Check(d.State==AL5OfflineDispatchState.Stopped,"deadline arithmetic cannot wrap near TimeSpan maximum");
    }
    static void LoaderFailureWindow()
    {
        foreach(var failure in new[]{("6cf018768077",AL5OfflineDispatchStop.LoaderChecksumRejected),
            ("6cf0187f36800636ff9022",AL5OfflineDispatchStop.LoaderRejected),
            ("6cf018760073",AL5OfflineDispatchStop.UnqualifiedLoaderReply)})
            foreach(int progress in new[]{0,1,2})
            {
                var d=New();bool reached=false;
                foreach(string line in lines)
                {
                    Apply(d,line,true);
                    if(d.LastAdapterAcceptedDispatch?.Kind==AL5OfflineDispatchKind.Loader){reached=true;break;}
                }
                Check(reached && d.AwaitingLoaderIdentity && d.State==AL5OfflineDispatchState.ActionAvailable,"executable upload has no invented positive-ACK slot");
                var loaderOwner=d.LastLoaderDispatch;AL5OfflineWriteDispatch? identity=null;
                if(progress>0)
                {
                    identity=d.PrepareNextOfflineDispatch();
                    if(progress==2)d.CompleteSavedSend(identity,AL5OfflineSendOutcome.AdapterAccepted);
                }
                d.ObserveSavedReply(Convert.FromHexString(failure.Item1));
                Check(d.State==AL5OfflineDispatchState.Stopped && d.StopReason==failure.Item2,"loader failure classified before data programming");
                Check(d.ProtocolPhaseAtStop==AL5CapturedWriteState.LoaderTransfer && Object.ReferenceEquals(loaderOwner,d.LastLoaderDispatch),"loader origin survives later identity-query ownership");
                if(progress==1)Check(Object.ReferenceEquals(identity,d.PendingDispatch),"unconfirmed identity send remains retained");
                if(progress==2)Check(Object.ReferenceEquals(identity,d.ReplyOwnerDispatch),"identity reply slot remains retained after loader error");
                Reject(()=>d.PrepareNextOfflineDispatch());Reject(()=>d.PrepareChecksumRetryForOfflineReview());Blocked(d);
            }
    }
    static void QualificationBoundaries()
    {
        Check(new AL5OfflineWriteDispatcher(loader,calibration,reference,0).Boundary==AL5OfflineWriteBoundary.BeforeSecurityKey,"default pauses before key submission");
        Reject(()=>New(boundary:(AL5OfflineWriteBoundary)999));
        foreach(var boundary in new[]{AL5OfflineWriteBoundary.BeforeSecurityKey,AL5OfflineWriteBoundary.BeforeProgrammingEntry,
            AL5OfflineWriteBoundary.BeforeLoaderUpload,AL5OfflineWriteBoundary.BeforeErase,AL5OfflineWriteBoundary.AfterEraseBeforeData})
        {
            var d=New(boundary:boundary);int consumed=0;
            foreach(string line in lines)
            {
                if(d.State==AL5OfflineDispatchState.BoundaryReached)break;
                Apply(d,line,true);consumed++;
            }
            Check(d.State==AL5OfflineDispatchState.BoundaryReached && consumed<lines.Length,"selected qualification boundary reached");
            Check(d.PendingDispatch==null && d.ReplyOwnerDispatch==null,"pause has no new send or awaited reply");
            Check(d.StopReason==AL5OfflineDispatchStop.None && d.PositiveProgramReplies==0,"boundary is a pause, not successful programming or failure");
            Reject(()=>d.PrepareNextOfflineDispatch());Reject(()=>d.PrepareSavedSecurityEvidence(Convert.FromHexString("6c18f02702bc08")));
            Reject(()=>d.CompleteSavedSend(d.LastAdapterAcceptedDispatch!,AL5OfflineSendOutcome.AdapterAccepted));
            Reject(()=>d.ObserveSavedReply(Convert.FromHexString("6df018760073")));Blocked(d);
        }
    }
    static void RetryOwnership()
    {
        byte[] error=Convert.FromHexString("6df018760077"),success=Convert.FromHexString("6df018760073");
        var d=ThroughFirstData(2);var original=d.LastAdapterAcceptedDispatch!.CopyRequest();
        Reject(()=>d.PrepareChecksumRetryForOfflineReview());
        for(int i=0;i<2;i++)
        {
            d.ObserveSavedReply(error);Check(d.State==AL5OfflineDispatchState.ChecksumRetryReview,"rejection asks for explicit review");
            var retry=d.PrepareChecksumRetryForOfflineReview();Check(retry.CopyRequest().SequenceEqual(original),"exact rejected request retained");
            d.CompleteSavedSend(retry,AL5OfflineSendOutcome.AdapterAccepted);
        }
        d.ObserveSavedReply(error);Reject(()=>d.PrepareChecksumRetryForOfflineReview());
        Check(d.StopReason==AL5OfflineDispatchStop.RetryBudgetExhausted,"configured budget stops");Blocked(d);
        d=ThroughFirstData(0);d.ObserveSavedReply(error);Reject(()=>d.PrepareChecksumRetryForOfflineReview());Blocked(d);
        d=ThroughFirstData(1);d.ObserveSavedReply(error);
        var one=d.PrepareChecksumRetryForOfflineReview();d.CompleteSavedSend(one,AL5OfflineSendOutcome.AdapterAccepted);d.ObserveSavedReply(success);
        var next=d.PrepareNextOfflineDispatch();d.CompleteSavedSend(next,AL5OfflineSendOutcome.AdapterAccepted);d.ObserveSavedReply(error);
        one=d.PrepareChecksumRetryForOfflineReview();Check(one.AcknowledgedBlocks==1,"retry budget resets only after acknowledged advancement");
        d.CompleteSavedSend(one,AL5OfflineSendOutcome.AdapterAccepted);d.ObserveSavedReply(success);
        Check(d.PositiveProgramReplies==2,"two sequential blocks acknowledged");
        // Identical stale ACK bodies have no address/sequence identity on this protocol.
        next=d.PrepareNextOfflineDispatch();d.CompleteSavedSend(next,AL5OfflineSendOutcome.AdapterAccepted);d.ObserveSavedReply(success);
        Check(d.PositiveProgramReplies==3 && !d.ReplyFreshnessProven,"same-body ACK cannot establish wire freshness");
        d=ThroughFirstData();Reject(()=>d.ObserveSavedReply(new byte[]{0x6D,0xF0,0x18}));
        Check(d.State==AL5OfflineDispatchState.Stopped,"malformed reply stops");
        Check(d.ProtocolPhaseAtStop==AL5CapturedWriteState.Programming,"failed reply preserves programming phase");
        d=ThroughFirstData();d.ObserveSavedReply(Convert.FromHexString("6df0187600f8"));
        Check(d.StopReason==AL5OfflineDispatchStop.ProtocolFailure,"fatal programming status stops");
        d=ThroughFirstData();var pending=d.LastAdapterAcceptedDispatch;var broadcast=d.PrepareSavedProgrammingBroadcast();
        d.CompleteSavedSend(broadcast,AL5OfflineSendOutcome.AdapterAccepted);
        Check(d.State==AL5OfflineDispatchState.AwaitingReply,"auxiliary broadcast does not release pending data reply");
        Check(Object.ReferenceEquals(pending,d.ReplyOwnerDispatch),"broadcast does not replace data reply identity");
        d.ObserveSavedReply(success);Check(d.PositiveProgramReplies==1 && Object.ReferenceEquals(pending,d.LastConsumedReplyOwner),"data owner survives broadcast");
    }
    static void CompletionAndPreservation()
    {
        var d=New();int omitted=0;
        foreach(var line in lines)if(!Apply(d,line,true))omitted++;
        Check(d.State==AL5OfflineDispatchState.AwaitingReadback && d.PositiveProgramReplies==192,"all data and cleanup require independent comparison");
        Check(!d.CompleteSavedComparison,"ACKs alone do not complete writer");
        Reject(()=>d.VerifySavedFullReadback(calibration));
        var expected=d.CopyExpectedSavedImage();Check(d.VerifySavedFullReadback(expected).ExactSavedImageMatch,"synthetic expected reference compares");
        Check(d.State==AL5OfflineDispatchState.Completed && d.CompleteSavedComparison,"full saved comparison completes only offline");
        Reject(()=>d.PrepareNextOfflineDispatch());Reject(()=>d.ObserveSavedReply(Convert.FromHexString("6df018760073")));Blocked(d);
        foreach(int address in new[]{0x4000,0x6000,0x15FD8,0x1FFFF,0x20000})
        {
            d=New();foreach(var line in lines)Apply(d,line,true);
            var corrupt=d.CopyExpectedSavedImage();corrupt[address]^=1;d.VerifySavedFullReadback(corrupt);
            Check(d.StopReason==AL5OfflineDispatchStop.VerificationFailed && !d.CompleteSavedComparison,"preservation mismatch stops");
            if(address>=0x4000 && address<0x8000)Check(d.ChangedPersistentBankBytes==1,"bank mismatch reported separately");
            if(address>=0x20000)Check(d.ChangedOtherProtectedBytes==1,"OS mismatch reported separately");Blocked(d);
        }
        var custom=(byte[])calibration.Clone();custom[0x100]^=1;
        Convert.FromHexString(AL5CalibrationInspection.Inspect(custom).ComputedChecksumHex!).CopyTo(custom,custom.Length-4);
        d=New(custom:custom);foreach(var line in lines)Apply(d,line,true,true);
        Check(d.PositiveProgramReplies==192,"custom candidate dispatched from constructed bytes");
        Check(d.CopyExpectedSavedImage().Skip(0x8000).Take(custom.Length).SequenceEqual(custom),"custom bytes retained");Blocked(d);
        Console.WriteLine($"PASS strict dispatcher model: 192 blocks, {d.ChecksumErrors} checksum rejections; {omitted} raw no-reply repeats explicitly omitted from derived scenario; custom payload and preservation checks.");
    }
    static void Main(string[] args)
    {
        if(args.Length<4 || args.Length%2!=0)throw new ArgumentException("Use loader.bin full-reference.bin then saved-template/calibration pairs.");
        loader=File.ReadAllBytes(args[0]);var original=File.ReadAllBytes(args[1]);
        for(int index=2;index<args.Length;index+=2)
        {
            lines=File.ReadAllLines(args[index]);calibration=File.ReadAllBytes(args[index+1]);
            // Synthetic complete reference with explicit capture-derived sector bytes.
            reference=(byte[])original.Clone();var image=new AL5CapturedProgramImage();
            foreach(var line in lines)if(line[0]=='T' && Data(Bytes(line)))image.Observe(Bytes(line));
            image.CopyCompleteImage().CopyTo(reference,0x8000);
            ProfileAndSecurityGates();OwnershipAndSendOutcomes();RetryOwnership();CompletionAndPreservation();
            if(index==2){ConcurrentCallbacks();TimingBudgets();LoaderFailureWindow();QualificationBoundaries();}
        }
        Console.WriteLine($"PASS {checks} dispatcher checks. No Vehicle/device/channel is accepted; live operations remain disabled.");
    }
}
