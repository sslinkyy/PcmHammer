using System.Text.Json;
using PcmHacking;

static partial class Program
{
    static int ReadbackEpoch(string[] args)
    {
        if(args.Length!=14)throw new ArgumentException("--readback-epoch ORIGINAL-full.bin PREPARED-banks.bin LOADER.bin SAVED-lifecycle.txt BANKS-before.txt FULL-image.txt BANKS-after.txt BEFORE-nonce IMAGE-nonce AFTER-nonce startup-unobserved|declared-startup evidence-id NEW-directory");
        string output=Path.GetFullPath(args[13]);
        if(Directory.Exists(output) || File.Exists(output))throw new ArgumentException("New output directory required; existing evidence is retained.");
        byte[] original=ReadFullChip(args[1]),prepared=ReadSizedFile(args[2],0x4000),loader=ReadSizedFile(args[3],1590),lifecycle=File.ReadAllBytes(args[4]);
        var frames=new List<(bool Transmitted,byte[] Frame)>();
        using(var reader=new StreamReader(new MemoryStream(lifecycle),new System.Text.UTF8Encoding(false,true)))
        {
            while(reader.ReadLine() is string line)
            {
                if(line.Length<3 || line[1]!=' ' || (line[0]!='T' && line[0]!='R'))throw new ArgumentException("Malformed saved lifecycle record.");
                frames.Add((line[0]=='T',Convert.FromHexString(line.Substring(2))));
            }
        }
        AL5SavedReadbackEpochKind kind=args[11] switch {
            "startup-unobserved"=>AL5SavedReadbackEpochKind.AfterCleanupStartupUnobserved,
            "declared-startup"=>AL5SavedReadbackEpochKind.AfterDeclaredStartup,
            _=>throw new ArgumentException("Explicit supported startup declaration required; it is not a physical observation.")};
        var epoch=AL5SavedReadbackEpoch.RehearseSavedLifecycle(loader,original,prepared,frames.ToArray(),args[12],kind,
            Convert.FromHexString(args[8]),Convert.FromHexString(args[9]),Convert.FromHexString(args[10]));
        byte[] before=File.ReadAllBytes(args[5]),image=File.ReadAllBytes(args[6]),after=File.ReadAllBytes(args[7]);
        var beforeCounts=Consume(epoch.BeginNextSavedRequest,epoch.ObserveSavedReply,before);
        if(epoch.Phase!=AL5SavedReadbackEpochPhase.FullImage)throw new ArgumentException("Before-bank transcript must cover exactly its own complete campaign.");
        var imageCounts=Consume(epoch.BeginNextSavedRequest,epoch.ObserveSavedReply,image);
        if(epoch.Phase!=AL5SavedReadbackEpochPhase.BanksAfterImage)throw new ArgumentException("Image transcript must cover exactly the complete 1 MiB image.");
        var afterCounts=Consume(epoch.BeginNextSavedRequest,epoch.ObserveSavedReply,after);
        if(epoch.Phase!=AL5SavedReadbackEpochPhase.Complete)throw new ArgumentException("After-bank transcript is incomplete.");
        // Disagreement remains a successful diagnostic export, never a successful
        // preservation check. Agreeing observations still use the unchanged comparator.
        if(epoch.AssessSavedEvidence().BanksAgreeAcrossSavedObservations==true)epoch.VerifySavedComparison();
        var assessment=epoch.AssessSavedEvidence();
        string outcome=assessment.BanksAgreeAcrossSavedObservations!=true?"unstable_saved_observations":
            assessment.StrictSavedComparisonMatched?"strict_saved_comparison_matched":"strict_saved_comparison_failed";
        var report=new {
            schema="al5-saved-readback-epoch-export-v1",outcome,assessment,
            original=Input(args[1],original),prepared=Input(args[2],prepared),loader=Input(args[3],loader),lifecycle=Input(args[4],lifecycle),
            before_transcript=Input(args[5],before),image_transcript=Input(args[6],image),after_transcript=Input(args[7],after),
            before_matched=beforeCounts.matched,before_unrelated=beforeCounts.unrelated,
            image_matched=imageCounts.matched,image_unrelated=imageCounts.unrelated,after_matched=afterCounts.matched,after_unrelated=afterCounts.unrelated,
            changed_persistent_bank_bytes=assessment.ChangedPersistentBankBytes,changed_other_protected_bytes=assessment.ChangedOtherProtectedBytes,
            provenance="caller_supplied_saved_lifecycle_and_correlated_transcripts_not_physical_epoch_proof",
            hardware_access=false,live_upload_enabled=false,live_execution_enabled=false,live_write_enabled=false,ready_to_flash=false
        };
        // No files are emitted until parsing, coverage and diagnosis have finished.
        Directory.CreateDirectory(output);
        Save(Path.Combine(output,"readback.observed.saved.bin"),epoch.CopyObservedImageForDiagnosis());
        Save(Path.Combine(output,"banks.before.saved.bin"),epoch.CopyBeforeBanksForDiagnosis());
        Save(Path.Combine(output,"banks.after.saved.bin"),epoch.CopyAfterBanksForDiagnosis());
        Save(Path.Combine(output,"epoch.json"),JsonSerializer.SerializeToUtf8Bytes(report,new JsonSerializerOptions {WriteIndented=true,Converters={new System.Text.Json.Serialization.JsonStringEnumConverter()}}));
        Console.WriteLine(outcome+"; snapshot coherence, startup history and physical preservation remain unverified.");return 0;
    }
}
