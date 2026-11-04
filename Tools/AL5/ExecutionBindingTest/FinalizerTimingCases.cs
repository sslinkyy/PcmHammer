using PcmHacking;

static partial class Program
{
    static async Task FinalizerTimingCases()
    {
        AL5CalibrationWriteCandidate Pending()
        {
            var candidate=new AL5CalibrationWriteCandidate(loader,calibration,original);
            foreach(string line in lines)
            {
                candidate.ObserveSavedFrame(line[0]=='T',Hex(line.Substring(2)));
                if(candidate.State==AL5CapturedWriteState.FinalizeReply)return candidate;
            }
            throw new Exception("Captured template has no owned finalization reply slot");
        }
        var pending=Pending();Check(!pending.SavedFinalizationReplyObserved && !pending.SavedCleanupObserved,"Submitted finalization is not an observed acknowledgement");
        Reject(()=>pending.VerifySavedFullReadback(pending.CopyExpectedSavedImage()));
        pending.ObserveSavedFrame(false,Hex("6cf018760086"));
        Check(pending.State==AL5CapturedWriteState.Cleanup && pending.SavedFinalizationReplyObserved && !pending.SavedCleanupObserved,"Success reply precedes the separate saved cleanup epoch");
        Reject(()=>pending.VerifySavedFullReadback(pending.CopyExpectedSavedImage()));
        pending.TimeoutOrCancel();Check(pending.State==AL5CapturedWriteState.Stopped && pending.SavedFinalizationReplyObserved && !pending.SavedCleanupObserved,"Stopping after status retains evidence without granting a readback window");
        results.Add(new {name="finalization_reply_is_not_reset_or_readback_permission",passed=true});
        foreach(byte status in new byte[]{0xFF,0xF8})
        {
            var rejected=Pending();rejected.ObserveSavedFrame(false,new byte[]{0x6C,0xF0,0x18,0x76,0,status});
            Check(!rejected.SavedFinalizationReplyObserved && !rejected.SavedCleanupObserved && rejected.State==AL5CapturedWriteState.Stopped && !rejected.AutomaticRetryEnabled,"Native error status is not success or retry authority even if its native tail can park");
            results.Add(new {name="finalizer_error_retains_closed_readback_gate",status,passed=true});
        }
        var peer=new Peer(lines,original);var io=new MemoryIo(peer);
        io.OnSend=()=>{if(peer.FinalizationsSubmitted>0)throw new IOException("Scripted first cleanup submission failure");};
        var session=Session(io);var report=await Drive(session,peer);
        Check(report.Outcome==AL5WriteExecutionOutcome.Stopped && report.StopReason==AL5OfflineDispatchStop.SendSubmissionUnknown &&
            report.SavedFinalizationReplyObserved && !report.SavedCleanupObserved,"Async stop retains final status without claiming cleanup");
        Check(!report.PhysicalResetVerified && !report.PostFinalizationReadbackWindowVerified && !report.PhysicalDeadlinesQualified,"Final status cannot qualify timing or physical reset");
        Reject(()=>session.VerifySavedReadback(peer.Flash));int sends=io.Sends;
        await session.RunUntilReviewAsync(CancellationToken.None);Check(io.Sends==sends,"Cleanup fault is terminal and cannot repeat finalization");
        results.Add(new {name="async_cleanup_fault_preserves_final_reply_without_reset_claim",passed=true});
    }
}
