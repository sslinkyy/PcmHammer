using PcmHacking;
using System.Security.Cryptography;
using System.Text.Json;

static partial class Program
{
    static void JournalCases(string reportPath,byte[] nativeBaseline)
    {
        using var document=JsonDocument.Parse(File.ReadAllBytes(reportPath));var root=document.RootElement;
        string fullHash=Convert.ToHexString(SHA256.HashData(nativeBaseline)).ToLowerInvariant();
        Check(root.GetProperty("schema").GetString()=="al5-native-journal-restart-v1" && root.GetProperty("reference_sha256").GetString()==fullHash,"Native journal source matches selected full baseline");
        byte[] calibration=nativeBaseline.AsSpan(0x8000,AL5CalibrationInspection.Length).ToArray();
        var sectors=new AL5CalibrationSectorPlan(calibration,nativeBaseline.AsSpan(0x8000,AL5ProgrammingWorkflow.SnapshotLength).ToArray());
        var plan=new AL5EfiOfflineWritePlan(loader,AL5CalibrationWriteCandidate.LoaderSha256,calibration,sectors.CopyCollateralBackup());
        string directory=Path.GetDirectoryName(reportPath)!;
        foreach(var item in root.GetProperty("cases").EnumerateArray())
        {
            string label=item.GetProperty("case").GetString()!;var observed=item.GetProperty("observed");
            byte[] before=File.ReadAllBytes(Path.Combine(directory,label+".before.bin"));
            var operations=observed.GetProperty("synthetic_bank_programs").EnumerateArray().Select(op=>new AL5SavedBankProgram(
                op.GetProperty("caller_return").GetInt32(),op.GetProperty("destination").GetInt32(),
                Convert.FromHexString(op.GetProperty("before").GetString()!),Convert.FromHexString(op.GetProperty("after").GetString()!))).ToArray();
            var review=new AL5SavedBankTransitionReview("native-saved-"+label,fullHash,before,operations);
            Check(review.CopyPredictedBanks().SequenceEqual(File.ReadAllBytes(Path.Combine(directory,label+".after.bin"))),"Production diagnostic reproduces every native modeled bank byte");
            AL5CalibrationWriteCandidate Rehearse()
            {
                var candidate=new AL5CalibrationWriteCandidate(loader,calibration,nativeBaseline);bool recorded=false;
                Reject(()=>candidate.DiagnoseSavedStartupBanks(review,nativeBaseline));
                foreach(string line in lines)
                {
                    bool tx=line[0]=='T';byte[] frame=Convert.FromHexString(line.Substring(2));
                    if(!recorded && candidate.State==AL5CapturedWriteState.EraseRequest){candidate.RecordSavedPreparedBanks(before);recorded=true;}
                    if(tx && frame.Length>12 && frame[3]==0x36 && frame[4]==0)
                    {int address=(frame[7]<<16)|(frame[8]<<8)|frame[9];frame=plan.CopyRequest(2+(address-0x8000)/512);}
                    candidate.ObserveSavedFrame(tx,frame);
                }
                Check(recorded && candidate.State==AL5CapturedWriteState.AwaitingSavedVerification,"Full scripted cleanup precedes diagnosis");return candidate;
            }
            var candidate=Rehearse();byte[] readback=candidate.CopyExpectedSavedImage();review.CopyPredictedBanks().CopyTo(readback,0x4000);
            var diagnosis=candidate.DiagnoseSavedStartupBanks(review,readback);
            Check(diagnosis.MatchesSavedPrediction && diagnosis.ChangedFromPreparedBytes==observed.GetProperty("bank_comparison").GetProperty("changed_addresses").GetArrayLength(),"Exact native prediction diagnoses the owned epoch");
            Check(!candidate.CompleteSavedComparison && !diagnosis.PreservationVerified && !diagnosis.PhysicalTransitionVerified && !diagnosis.ReadyToFlash,"Diagnosis never authorizes preservation or live readiness");
            var match=candidate.VerifySavedFullReadback(readback);
            Check(match.ExactSavedImageMatch && !candidate.CompleteSavedComparison && candidate.State==AL5CapturedWriteState.Stopped && candidate.ChangedPersistentBankBytes==diagnosis.ChangedFromPreparedBytes,"Native startup differences still fail strict preservation");
            Check(candidate.DiagnoseSavedStartupBanks(review,readback).MatchesSavedPrediction && candidate.State==AL5CapturedWriteState.Stopped,"Post-failure diagnosis cannot clear the terminal stop");
            var corrupt=(byte[])readback.Clone();corrupt[diagnosis.CopyChangedAddresses()[0]]^=1;
            Check(candidate.DiagnoseSavedStartupBanks(review,corrupt).DifferencesFromPrediction==1,"Corruption at a legitimately changing address is still detected");
            corrupt=(byte[])readback.Clone();corrupt[0x6005]^=1;
            Check(candidate.DiagnoseSavedStartupBanks(review,corrupt).DifferencesFromPrediction==1,"Other bank-byte corruption is detected");
            var outside=Rehearse();corrupt=(byte[])readback.Clone();corrupt[0]^=1;
            Check(outside.DiagnoseSavedStartupBanks(review,corrupt).MatchesSavedPrediction,"Bank-only diagnosis makes no claim about boot bytes");
            outside.VerifySavedFullReadback(corrupt);Check(!outside.CompleteSavedComparison && outside.ChangedOtherProtectedBytes==1,"Strict full comparator still detects boot corruption");
            var wrong=new AL5SavedBankTransitionReview("foreign-original",new string('0',64),before,operations);
            Reject(()=>candidate.DiagnoseSavedStartupBanks(wrong,readback));Reject(()=>candidate.DiagnoseSavedStartupBanks(review,new byte[0x80000]));
            var wrongBanks=(byte[])before.Clone();wrongBanks[0]^=1;
            wrong=new AL5SavedBankTransitionReview("foreign-prepared",fullHash,wrongBanks,Array.Empty<AL5SavedBankProgram>());
            Reject(()=>candidate.DiagnoseSavedStartupBanks(wrong,readback));
            var reordered=(AL5SavedBankProgram[])operations.Clone();Array.Reverse(reordered);
            Reject(()=>new AL5SavedBankTransitionReview("reordered",fullHash,before,reordered));
            results.Add(new {name="native_journal_diagnosis_keeps_preservation_strict",epoch=label,passed=true,model_only=true,changed=diagnosis.ChangedFromPreparedBytes});
        }
        var blank=Enumerable.Repeat((byte)255,0x4000).ToArray();
        Reject(()=>new AL5SavedBankTransitionReview("short",fullHash,new byte[3],Array.Empty<AL5SavedBankProgram>()));
        Reject(()=>new AL5SavedBankTransitionReview("outside",fullHash,blank,new[]{new AL5SavedBankProgram(0x229DC,0x8000,new byte[10],new byte[10])}));
        Reject(()=>new AL5SavedBankTransitionReview("wrong-caller",fullHash,blank,new[]{new AL5SavedBankProgram(0x229C0,0x4A1C,Hex("ffff"),Hex("fffe"))}));
        Reject(()=>new AL5SavedBankTransitionReview("wrong-before",fullHash,blank,new[]{new AL5SavedBankProgram(0x229C2,0x4A1C,Hex("fffe"),Hex("fffe"))}));
        var zero=(byte[])blank.Clone();zero[0xA1C]=0;
        Reject(()=>new AL5SavedBankTransitionReview("requires-erase",fullHash,zero,new[]{new AL5SavedBankProgram(0x229F6,0x4A1C,Hex("00ff"),Hex("ffaa"))}));
        var after=Hex("fffe");var immutable=new AL5SavedBankProgram(0x229C2,0x4A1C,Hex("ffff"),after);after[1]=0;
        var reviewClone=new AL5SavedBankTransitionReview("immutable",fullHash,blank,new[]{immutable});blank[0xA1C]=0;
        var exported=reviewClone.CopyPredictedBanks();exported[0]=0;
        Check(reviewClone.CopyPredictedBanks()[0]==255 && reviewClone.CopyPredictedBanks()[0xA1D]==254,"Saved prediction owns inputs and outputs");
        results.Add(new {name="journal_operation_layout_order_ownership_guards",passed=true});
    }
}
