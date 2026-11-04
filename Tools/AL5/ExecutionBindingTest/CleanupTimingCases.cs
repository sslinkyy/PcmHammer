using PcmHacking;

static partial class Program
{
    static async Task CapturedCleanupOrderingCase(string source)
    {
        // Preserve the unanswered cleanup query; earlier program repeats remain
        // normalized exactly as in the existing peer. This is a targeted tail
        // test, not a claim of unmodified full-session replay or real timing.
        var peer=new Peer(lines,original,preserveCleanupRepeats:true);
        Check(peer.PreservedCleanupQueryRepeats==1,"Selected captured tail must retain its one repeated identity query");
        var io=new MemoryIo(peer);var session=Session(io);var report=await Drive(session,peer);
        Check(report.Outcome==AL5WriteExecutionOutcome.Stopped && report.StopReason==AL5OfflineDispatchStop.Timeout,
            "Completed empty receive at first cleanup poll remains a terminal stop; no automatic retry");
        Check(report.AcknowledgedBlocks==192 && report.SavedFinalizationReplyObserved && !report.SavedCleanupObserved,
            "Full modeled programming and final ACK do not establish cleanup or independent readback");
        Check(peer.CleanupQueriesSubmitted==1 && peer.FinalizationsSubmitted==1,
            "Executor must not invent the second identity poll or repeat finalization");
        Check(!report.TransportCallOutstanding && !report.PhysicalResetVerified &&
            !report.PostFinalizationReadbackWindowVerified && !report.PhysicalDeadlinesQualified,
            "Completed synthetic silence is distinct from outstanding I/O and physical timing proof");
        Reject(()=>session.VerifySavedReadback(peer.Flash));int sends=io.Sends;
        await session.RunUntilReviewAsync(CancellationToken.None);
        Check(io.Sends==sends,"Terminal cleanup stop cannot resume an additional cleanup send");

        // The chronological candidate can consume both saved queries. The
        // unresolved gap is bounded scheduling in the executor, not packet grammar.
        var candidate=new AL5CalibrationWriteCandidate(loader,calibration,original);
        foreach(string line in lines)candidate.ObserveSavedFrame(line[0]=='T',Hex(line.Substring(2)));
        Check(candidate.State==AL5CapturedWriteState.AwaitingSavedVerification &&
            candidate.SavedCleanupObserved,"Chronological saved tail is accepted by the candidate grammar");
        results.Add(new {name="captured_unanswered_cleanup_query_not_normalized",source,passed=true,
            peer.PreservedCleanupQueryRepeats,peer.OmittedNoReplyRepeats,peer.OmittedProgrammingBroadcasts,
            peer.CleanupQueriesSubmitted,peer.FinalizationsSubmitted,report.AcknowledgedBlocks,
            outcome=report.Outcome.ToString(),stop_reason=report.StopReason.ToString(),
            report.SavedFinalizationReplyObserved,report.SavedCleanupObserved,
            report.PostFinalizationReadbackWindowVerified,
            limitation="Other no-reply repeats remain normalized; no real timing, hardware or retry policy tested."});
    }
}
