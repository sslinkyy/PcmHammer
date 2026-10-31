using System;
using System.IO;
using System.Linq;
using PcmHacking;

internal static class CapturedWriteRehearsalTest
{
    static void Check(bool value) { if(!value)throw new Exception("Rehearsal assertion failed"); }
    static AL5CapturedWriteRehearsal Replay(string[] lines,byte[] candidate,string loader)
    {
        var session=new AL5CapturedWriteRehearsal(candidate,loader);
        foreach(var line in lines)session.Observe(line[0]=='T',Convert.FromHexString(line.Substring(2)));
        return session;
    }
    public static int Run(string[] args)
    {
        if(args.Length%3!=0)throw new ArgumentException("Use corpus/reference/loader-hash triples");
        for(int i=0;i<args.Length;i+=3)
        {
            var lines=File.ReadAllLines(args[i]);var candidate=File.ReadAllBytes(args[i+1]);string loader=args[i+2];
            var session=Replay(lines,candidate,loader);
            Check(session.State==AL5CapturedWriteState.AwaitingSavedVerification && session.PositiveProgramReplies==192);
            Check(session.CleanupObserved && session.CleanupQueryRepeats==1);
            Check(session.CleanupNegative14Observed==lines.Contains("R 6cf0187f1423"));
            session.CompareSavedCalibration(candidate);
            Check(session.SavedCalibrationMatches==true && session.State==AL5CapturedWriteState.AwaitingSavedVerification);
            Check(!session.ReadyToFlash && !session.LiveWriteEnabled && !session.PhysicalReadbackVerified);
            // Synthetic snapshot only: explicitly fabricated test fixture, never real recovery evidence.
            var image=new AL5CapturedProgramImage();
            foreach(var line in lines.Where(l=>l.StartsWith("T 6d18f03600")))image.Observe(Convert.FromHexString(line.Substring(2)));
            byte[] captured=image.CopyCompleteImage();var snapshot=new byte[AL5ProgrammingWorkflow.SnapshotLength];
            captured.CopyTo(snapshot,0);snapshot[snapshot.Length-2]=0x4A;snapshot[snapshot.Length-1]=0xFC;
            Check(AL5SavedReadCoverage.SupplementalDwordCount==10250 && AL5SavedReadCoverage.LastDwordAddress==0x1FFFC);
            Check(!AL5SavedReadCoverage.ExtendedLiveReadEnabled && !AL5SavedReadCoverage.SupplementalReadabilityProven);
            var supplement=snapshot.Skip(candidate.Length).ToArray();
            Check(AL5SavedReadCoverage.AssembleSavedSnapshot(candidate,supplement).SequenceEqual(snapshot));
            supplement[supplement.Length-1]=0;
            Check(AL5SavedReadCoverage.AssembleSavedSnapshot(candidate,supplement).Last()==0);
            try{AL5SavedReadCoverage.AssembleSavedSnapshot(candidate,new byte[supplement.Length-2]);throw new Exception("Missing marker invented");}catch(ArgumentException){}
            var collateral=new byte[AL5ProgrammingWorkflow.CollateralLength];Array.Copy(captured,candidate.Length,collateral,0,collateral.Length);
            Check(session.VerifySavedSnapshot(snapshot,collateral).ExactSavedImageMatch);
            Check(session.State==AL5CapturedWriteState.SavedImageVerified && !session.ReadyToFlash);
            var corrupt=Replay(lines,candidate,loader);snapshot[snapshot.Length-1]^=1;
            Check(!corrupt.VerifySavedSnapshot(snapshot,collateral).ExactSavedImageMatch && corrupt.State==AL5CapturedWriteState.Stopped);
            var early=new AL5CapturedWriteRehearsal(candidate,loader);
            try{early.Observe(true,Convert.FromHexString("6c18f036ff"));throw new Exception("Early finalization accepted");}catch(ArgumentException){}
            Check(early.State==AL5CapturedWriteState.Setup);
            try{early.VerifySavedSnapshot(snapshot,collateral);throw new Exception("Early verification accepted");}catch(InvalidOperationException){}
            // Every observed phase boundary can be interrupted without enabling resume.
            var states=new System.Collections.Generic.HashSet<AL5CapturedWriteState>();
            for(int n=0;n<lines.Length;n++)
            {
                early.Observe(lines[n][0]=='T',Convert.FromHexString(lines[n].Substring(2)));
                if(!states.Add(early.State))continue;
                var stopped=Replay(lines.Take(n+1).ToArray(),candidate,loader);stopped.Interrupt();
                try{stopped.Observe(true,Convert.FromHexString("6c18f034"));throw new Exception("Interrupted attempt resumed");}catch(InvalidOperationException){}
            }
            var invalid=new AL5CapturedWriteRehearsal(candidate,new string('0',64));
            bool rejected=false;
            try{foreach(var line in lines)invalid.Observe(line[0]=='T',Convert.FromHexString(line.Substring(2)));}
            catch(ArgumentException){rejected=true;}
            Check(rejected && invalid.State==AL5CapturedWriteState.LoaderTransfer);
            int finalReply=Array.IndexOf(lines,"R 6cf018760086");Check(finalReply>=0);
            var notClean=Replay(lines.Take(finalReply+1).ToArray(),candidate,loader);
            Check(notClean.State==AL5CapturedWriteState.Cleanup && !notClean.CleanupObserved);
            try{notClean.CompareSavedCalibration(candidate);throw new Exception("Cleanup skipped");}catch(InvalidOperationException){}
            var setupFailed=new AL5CapturedWriteRehearsal(candidate,loader);
            setupFailed.Observe(true,Convert.FromHexString("6c18f03c55"));
            setupFailed.Observe(false,Convert.FromHexString("6cf0187f3c23"));Check(setupFailed.State==AL5CapturedWriteState.Stopped);
            foreach(string request in new[]{"T 6c18f036ee","T 6c18f036ff"})
            {
                int index=Array.IndexOf(lines,request);Check(index>=0);
                var failed=Replay(lines.Take(index+1).ToArray(),candidate,loader);
                failed.Observe(false,Convert.FromHexString("6cf0187600f8"));
                Check(failed.State==AL5CapturedWriteState.Stopped);
                try{failed.Observe(false,Convert.FromHexString(lines[index+1].Substring(2)));throw new Exception("Failed phase resumed");}catch(InvalidOperationException){}
            }
            Console.WriteLine("PASS full captured write: "+session.PositiveProgramReplies+" blocks; "+session.ChecksumErrors+" checksum retries; "+states.Count+" interruption boundaries; saved-file-only verification");
        }
        return 0;
    }
}
