using System;
using System.Linq;
using PcmHacking;

static class CalibrationWriteCandidateTest
{
    static void Check(bool value) { if(!value)throw new Exception("Calibration writer candidate assertion failed"); }
    static void Reject(Action action)
    { try{action();}catch(ArgumentException){return;}catch(InvalidOperationException){return;}throw new Exception("Expected candidate rejection"); }
    static void Blocked(AL5CalibrationWriteCandidate c) => Check(!c.LiveUploadEnabled && !c.LiveExecutionEnabled &&
        !c.LiveWriteEnabled && !c.ReadyToFlash && !c.PhysicalReadbackVerified && !c.RecoveryVerified &&
        !c.SecurityAuthorizationProven && !c.AutomaticRetryEnabled);
    static bool Program(byte[] m)=>m.Length>12 && m[3]==0x36 && m[4]==0;
    static bool OptionalBroadcast(byte[] m)=>m.SequenceEqual(Convert.FromHexString("6cfef02800"));
    static AL5CalibrationWriteCandidate Replay(string[] lines,byte[] loader,byte[] calibration,byte[] baseline,
        AL5EfiOfflineWritePlan? replacement=null)
    {
        var c=new AL5CalibrationWriteCandidate(loader,calibration,baseline);
        int controls=0,keyEvidence=0,retryReviews=0;
        foreach(string line in lines)
        {
            bool tx=line[0]=='T';byte[] m=Convert.FromHexString(line.Substring(2));
            if(tx && replacement!=null && Program(m))
            { int address=(m[7]<<16)|(m[8]<<8)|m[9];m=replacement.CopyRequest(2+(address-0x8000)/512); }
            var next=c.NextOfflineAction();
            if(tx)
            {
                if(next.Kind==AL5OfflineWriteActionKind.FixedControlRequest)
                {Check(next.CopyRequest().SequenceEqual(m));controls++;}
                else if(next.Kind==AL5OfflineWriteActionKind.SecurityKeyEvidenceRequired)
                {Reject(()=>next.CopyRequest());keyEvidence++;}
                else if(next.Kind==AL5OfflineWriteActionKind.ProgrammingRequest && !OptionalBroadcast(m))
                    Check(next.CopyRequest().SequenceEqual(m));
                else if(next.Kind==AL5OfflineWriteActionKind.ChecksumRetryReviewRequired && Program(m))
                { Check(c.CopyChecksumRejectedRequestForOfflineReview().SequenceEqual(m));retryReviews++; }
            }
            c.ObserveSavedFrame(tx,m);
        }
        Check(controls>10 && keyEvidence==1 && retryReviews==c.ChecksumErrors && c.PositiveProgramReplies==192);
        Check(c.State==AL5CapturedWriteState.AwaitingSavedVerification && !c.CompleteSavedComparison);
        Check(c.NextOfflineAction().Kind==AL5OfflineWriteActionKind.SavedFullReadbackRequired);Blocked(c);return c;
    }
    public static void Run(string[] lines,byte[] loader,byte[] calibration,byte[] collateral)
    {
        // Explicit synthetic full reference plus capture-derived sectors. Never an original backup.
        var baseline=Enumerable.Range(0,0x100000).Select(i=>(byte)(i^(i>>9))).ToArray();
        calibration.CopyTo(baseline,0x8000);collateral.CopyTo(baseline,0x15FD8);
        baseline[0x1FFFE]=0x12;baseline[0x1FFFF]=0x34;
        Reject(()=>new AL5CalibrationWriteCandidate(loader,calibration,new byte[57304]));
        var wrong=(byte[])loader.Clone();wrong[0]^=1;Reject(()=>new AL5CalibrationWriteCandidate(wrong,calibration,baseline));
        var c=Replay(lines,loader,calibration,baseline);
        var desired=c.CopyExpectedSavedImage();
        Check(desired[0x1FFFE]==0x4A && desired[0x1FFFF]==0xFC);
        Reject(()=>c.VerifySavedFullReadback(calibration));Check(!c.CompleteSavedComparison);
        Check(c.VerifySavedFullReadback(desired).ExactSavedImageMatch && c.CompleteSavedComparison);
        Check(c.NextOfflineAction().Kind==AL5OfflineWriteActionKind.Completed);Blocked(c);
        Reject(()=>c.ObserveSavedFrame(true,new byte[]{0x6C,0x18,0xF0,0x34}));Reject(()=>c.TimeoutOrCancel());
        foreach(int address in new[]{0,0x4000,0x6000,0x8000,0x15FD8,0x1FFFF,0x20000,0xFFFFF})
        {
            c=Replay(lines,loader,calibration,baseline);var changed=c.CopyExpectedSavedImage();changed[address]^=1;
            c.VerifySavedFullReadback(changed);
            Check(!c.CompleteSavedComparison && c.State==AL5CapturedWriteState.Stopped);
            Check(c.NextOfflineAction().Kind==AL5OfflineWriteActionKind.Stopped);Blocked(c);
        }
        // A custom calibration is generated from its own bytes/checksum, not replayed stock data.
        var custom=(byte[])calibration.Clone();custom[0x100]^=1;
        var checksum=Convert.FromHexString(AL5CalibrationInspection.Inspect(custom).ComputedChecksumHex!);
        checksum.CopyTo(custom,custom.Length-4);Check(AL5CalibrationInspection.Inspect(custom).ChecksPass);
        var replacement=new AL5EfiOfflineWritePlan(loader,AL5CalibrationWriteCandidate.LoaderSha256,custom,collateral);
        c=Replay(lines,loader,custom,baseline,replacement);desired=c.CopyExpectedSavedImage();
        Check(!desired.Skip(0x8000).Take(calibration.Length).SequenceEqual(calibration));
        Check(c.VerifySavedFullReadback(desired).ExactSavedImageMatch && c.CompleteSavedComparison);Blocked(c);

        // Every phase and every block's pending reply can stop without resuming or retrying.
        c=new AL5CalibrationWriteCandidate(loader,calibration,baseline);
        var phases=new System.Collections.Generic.HashSet<AL5CapturedWriteState>();int interruptions=0;
        for(int i=0;i<lines.Length;i++)
        {
            var m=Convert.FromHexString(lines[i].Substring(2));c.ObserveSavedFrame(lines[i][0]=='T',m);
            bool phase=phases.Add(c.State);
            if(!phase && !(lines[i][0]=='T' && Program(m)))continue;
            var stopped=new AL5CalibrationWriteCandidate(loader,calibration,baseline);
            for(int n=0;n<=i;n++)stopped.ObserveSavedFrame(lines[n][0]=='T',Convert.FromHexString(lines[n].Substring(2)));
            stopped.TimeoutOrCancel();Check(stopped.NextOfflineAction().Kind==AL5OfflineWriteActionKind.Stopped);
            Reject(()=>stopped.ObserveSavedFrame(true,m));Reject(()=>stopped.CopyChecksumRejectedRequestForOfflineReview());Blocked(stopped);interruptions++;
        }
        // Malformed observations latch a stop rather than preserving a permissive retry slot.
        c=new AL5CalibrationWriteCandidate(loader,calibration,baseline);
        Reject(()=>c.ObserveSavedFrame(true,new byte[]{0}));Check(c.State==AL5CapturedWriteState.Stopped);
        Console.WriteLine($"PASS writer candidate: generated controls, opaque key boundary, captured checksum retry review, custom BIN/checksum, full preservation comparison and {interruptions} interruption points; live gates closed.");
    }
}
