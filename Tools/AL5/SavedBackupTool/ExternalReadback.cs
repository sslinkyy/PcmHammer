using System.Text.Json;
using PcmHacking;

static partial class Program
{
    static string SelectedDumpTarget(string path)
    {
        var f=new FileInfo(path);
        // Historical original sources may be archived or no longer mounted.
        // Preserve their absolute identity without requiring the old file to exist.
        return Path.GetFullPath(f.Exists?(f.ResolveLinkTarget(true)?.FullName??f.FullName):f.FullName);
    }
    static bool SameDumpTarget(string a,string b)=>string.Equals(SelectedDumpTarget(a),SelectedDumpTarget(b),
        OperatingSystem.IsWindows()?StringComparison.OrdinalIgnoreCase:StringComparison.Ordinal);
    static AL5SavedExternalFlashPair ReadExternalPair(string first,string second,string representation)
    {
        if(SameDumpTarget(first,second))throw new ArgumentException("Select distinct raw dump paths; self-comparison is not a repeated read.");
        AL5SavedExternalByteOrder order=representation switch {
            "cpu-bytes"=>AL5SavedExternalByteOrder.CpuBytes,"swap16"=>AL5SavedExternalByteOrder.Swap16,
            _=>throw new ArgumentException("Explicit cpu-bytes or swap16 representation required.")};
        return new AL5SavedExternalFlashPair(ReadFullChip(first),ReadFullChip(second),order);
    }
    static (byte[] Original,byte[] Metadata) LoadExternalOriginal(string source)
    {
        byte[] metadata=File.ReadAllBytes(Path.Combine(source,"backup.json"));
        using var document=JsonDocument.Parse(metadata);var report=document.RootElement;
        if(report.GetProperty("schema").GetString()!="al5-saved-external-chip-backup-v1")throw new ArgumentException("External original importer report required.");
        foreach(string flag in new[]{"chip_identity_verified","physical_data_lane_mapping_verified","pre_entry_physical_acquisition_verified","physical_recovery_verified","hardware_access","live_upload_enabled","live_execution_enabled","live_write_enabled","ready_to_flash"})
            if(report.GetProperty(flag).GetBoolean())throw new ArgumentException("Saved importer evidence must not promote physical/live authority.");
        var pair=ReadExternalPair(Path.Combine(source,"first.raw.saved.bin"),Path.Combine(source,"second.raw.saved.bin"),report.GetProperty("representation").GetString()!);
        byte[] original=ReadFullChip(Path.Combine(source,"original.canonical.saved.bin"));
        if(pair.FirstRawSha256!=report.GetProperty("raw_first").GetProperty("sha256").GetString() ||
            pair.SecondRawSha256!=report.GetProperty("raw_second").GetProperty("sha256").GetString() ||
            Hash(original)!=report.GetProperty("canonical_sha256").GetString() || !pair.CopyCanonical().SequenceEqual(original))
            throw new ArgumentException("External original artifacts no longer match their saved representation/report.");
        byte[] banks=original.AsSpan(0x4000,0x4000).ToArray();
        if(Hash(banks)!=report.GetProperty("original_bank_sha256").GetString() ||
            !ReadSizedFile(Path.Combine(source,"original_banks.saved.bin"),0x4000).SequenceEqual(banks))
            throw new ArgumentException("Original bank artifact differs from the full original.");
        return (original,metadata);
    }
    static (bool Transmitted,byte[] Frame)[] ParseSavedLifecycle(byte[] raw)
    {
        var frames=new List<(bool,byte[])>();using var reader=new StreamReader(new MemoryStream(raw),new System.Text.UTF8Encoding(false,true));
        while(reader.ReadLine() is string line)
        {
            if(line.Length<3 || line[1]!=' ' || (line[0]!='T' && line[0]!='R'))throw new ArgumentException("Malformed saved lifecycle record.");
            frames.Add((line[0]=='T',Convert.FromHexString(line.Substring(2))));
        }
        return frames.ToArray();
    }
    static (string Source,byte[] Original,byte[] Metadata,AL5SavedExternalFlashPair Pair,byte[] History,AL5SavedExternalReadbackEpoch Epoch)
        ExternalReadbackInputs(string originalDirectory,string first,string second,string representation,string epochName,string targetId,string historyPath,string evidenceId)
    {
        if(string.IsNullOrWhiteSpace(evidenceId))throw new ArgumentException("Explicit readback evidence identity required.");
        string source=Path.GetFullPath(originalDirectory);var loaded=LoadExternalOriginal(source);
        using var originalMetadata=JsonDocument.Parse(loaded.Metadata);var originalReport=originalMetadata.RootElement;
        if(!originalReport.TryGetProperty("target_id",out var taggedTarget) || taggedTarget.ValueKind!=JsonValueKind.String ||
            string.IsNullOrWhiteSpace(taggedTarget.GetString()) || taggedTarget.GetString()!=targetId)
            throw new ArgumentException("External readback requires the exact target ID recorded with the original import; target labels are operator declarations.");
        var originalPaths=new List<string>{Path.Combine(source,"first.raw.saved.bin"),Path.Combine(source,"second.raw.saved.bin"),Path.Combine(source,"original.canonical.saved.bin")};
        foreach(string field in new[]{"raw_first","raw_second"})
            originalPaths.Add(originalReport.GetProperty(field).GetProperty("resolved").GetString()!);
        foreach(string selected in new[]{first,second})
            foreach(string name in originalPaths)
                if(SameDumpTarget(selected,name))throw new ArgumentException("Readback cannot reuse an original source or imported artifact path.");
        byte[] history=File.ReadAllBytes(historyPath);
        if(string.IsNullOrWhiteSpace(new System.Text.UTF8Encoding(false,true).GetString(history)))throw new ArgumentException("Explicit operator history, including unknowns, required.");
        var pair=ReadExternalPair(first,second,representation);
        var epoch=epochName switch {"shutdown-declared"=>AL5SavedExternalReadbackEpoch.ShutdownDeclared,
            "power-history-unobserved"=>AL5SavedExternalReadbackEpoch.PowerHistoryUnobserved,
            _=>throw new ArgumentException("Explicit supported power-history declaration required.")};
        return (source,loaded.Original,loaded.Metadata,pair,history,epoch);
    }
    static void ExportExternalReadback(string output,AL5SavedExternalFlashPair pair,byte[] history,object report)
    {
        Directory.CreateDirectory(output);Save(Path.Combine(output,"readback.first.raw.saved.bin"),pair.CopyFirstRaw());Save(Path.Combine(output,"readback.second.raw.saved.bin"),pair.CopySecondRaw());
        Save(Path.Combine(output,"readback.canonical.saved.bin"),pair.CopyCanonical());Save(Path.Combine(output,"readback_banks.saved.bin"),pair.CopyCanonical().AsSpan(0x4000,0x4000).ToArray());
        Save(Path.Combine(output,"operator_history.saved.txt"),history);
        Save(Path.Combine(output,"readback.json"),JsonSerializer.SerializeToUtf8Bytes(report,new JsonSerializerOptions{WriteIndented=true,Converters={new System.Text.Json.Serialization.JsonStringEnumConverter()}}));
    }
    static int ExternalReadback(string[] args)
    {
        if(args.Length!=13)throw new ArgumentException("--external-readback ORIGINAL-import-directory PREPARED-banks.bin LOADER.bin SAVED-lifecycle.txt READBACK-first.bin READBACK-second.bin cpu-bytes|swap16 shutdown-declared|power-history-unobserved TARGET-ID OPERATOR-history.txt EVIDENCE-ID NEW-directory");
        string output=Path.GetFullPath(args[12]);if(Directory.Exists(output)||File.Exists(output))throw new ArgumentException("New output directory required.");
        var loaded=ExternalReadbackInputs(args[1],args[5],args[6],args[7],args[8],args[9],args[10],args[11]);
        byte[] prepared=ReadSizedFile(args[2],0x4000),loader=ReadSizedFile(args[3],1590),lifecycle=File.ReadAllBytes(args[4]);
        var pair=loaded.Pair;
        var assessment=new AL5SavedExternalReadbackReview(loader,loaded.Original,prepared,ParseSavedLifecycle(lifecycle),pair,args[9],args[11],loaded.Epoch);
        var report=new {
            schema="al5-saved-external-readback-v1",outcome=assessment.StrictSavedComparisonMatched?"strict_saved_comparison_matched":"strict_saved_comparison_failed",assessment,
            original_import_directory=loaded.Source,original_metadata=Input(Path.Combine(loaded.Source,"backup.json"),loaded.Metadata),
            prepared=Input(args[2],prepared),loader=Input(args[3],loader),lifecycle=Input(args[4],lifecycle),operator_history=Input(args[10],loaded.History),
            raw_first=Input(args[5],pair.CopyFirstRaw()),raw_second=Input(args[6],pair.CopySecondRaw()),representation=args[7],
            raw_saved_files_match=true,hard_link_identity_verified=false,chip_identity_verified=false,physical_data_lane_mapping_verified=false,
            provenance="external_saved_readback_pair_and_operator_declarations_not_physical_acquisition_proof",
            hardware_access=false,live_upload_enabled=false,live_execution_enabled=false,live_write_enabled=false,ready_to_flash=false
        };
        ExportExternalReadback(output,pair,loaded.History,report);
        Console.WriteLine(report.outcome+"; no reader upload was required by this file workflow. Physical acquisition, target continuity and recovery remain unverified.");return 0;
    }
    static int CaptureExternalReadback(string[] args)
    {
        if(args.Length!=10)throw new ArgumentException("--capture-external-readback ORIGINAL-import-directory READBACK-first.bin READBACK-second.bin cpu-bytes|swap16 shutdown-declared|power-history-unobserved TARGET-ID OPERATOR-history.txt EVIDENCE-ID NEW-directory");
        string output=Path.GetFullPath(args[9]);if(Directory.Exists(output)||File.Exists(output))throw new ArgumentException("New output directory required.");
        var loaded=ExternalReadbackInputs(args[1],args[2],args[3],args[4],args[5],args[6],args[7],args[8]);var pair=loaded.Pair;
        var report=new {
            schema="al5-saved-external-readback-capture-v1",outcome="captured_saved_pair_comparison_unavailable",target_id=args[6],evidence_id=args[8],epoch=loaded.Epoch,
            original_import_directory=loaded.Source,original_metadata=Input(Path.Combine(loaded.Source,"backup.json"),loaded.Metadata),
            operator_history=Input(args[7],loaded.History),raw_first=Input(args[2],pair.CopyFirstRaw()),raw_second=Input(args[3],pair.CopySecondRaw()),representation=args[4],
            observed_image_sha256=pair.CanonicalSha256,raw_saved_files_match=true,readback_all_ff=pair.AllFF,readback_all_zero=pair.AllZero,
            comparison_performed=false,strict_saved_comparison_matched=(bool?)null,
            comparison_unavailable_reason="Capture-only mode; no completed saved lifecycle or prepared reference was supplied.",
            independent_physical_reads_verified=false,physical_power_state_verified=false,hard_link_identity_verified=false,
            operator_target_continuity_verified=false,snapshot_coherence_verified=false,physical_readback_verified=false,preservation_verified=false,recovery_verified=false,
            hardware_access=false,live_upload_enabled=false,live_execution_enabled=false,live_write_enabled=false,ready_to_flash=false
        };
        ExportExternalReadback(output,pair,loaded.History,report);
        Console.WriteLine("Saved external readback pair without a completed lifecycle; comparison remains unavailable and no retry is authorized.");return 0;
    }
}
