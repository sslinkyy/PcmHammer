using System.Security.Cryptography;
using System.Text.Json;
using PcmHacking;

// File-only transcript consumer. No Vehicle, adapter, USB or serial object is constructed.
static partial class Program
{
    static string Hash(byte[] bytes)=>Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    static object Input(string path,byte[] bytes)=>new {selected=path,resolved=Path.GetFullPath(path),bytes=bytes.Length,sha256=Hash(bytes)};
    static (int matched,int unrelated) Consume(AL5SavedBackupPath path,byte[] transcript)=>Consume(path.BeginNextSavedRequest,path.ObserveSavedReply,transcript);
    static (int matched,int unrelated) Consume(Func<byte[]> begin,Func<byte[],AL5ReadOnlyCoreReply> observe,byte[] transcript)
    {
        int matched=0,unrelated=0,lineNumber=0;bool pending=false;
        using var reader=new StreamReader(new MemoryStream(transcript),new System.Text.UTF8Encoding(false,true));
        while(reader.ReadLine() is string line)
        {
            lineNumber++;
            if(line.Length<3 || line[1]!=' ' || (line[0]!='T' && line[0]!='R'))throw new ArgumentException("Invalid transcript record at line "+lineNumber);
            byte[] frame=Convert.FromHexString(line.Substring(2));
            if(line[0]=='T')
            {
                if(pending)throw new InvalidOperationException("An unresolved request owns line "+lineNumber);
                byte[] expected=begin();
                if(!frame.SequenceEqual(expected))throw new ArgumentException("Request differs from the current acquisition at line "+lineNumber);
                pending=true;
            }
            else
            {
                if(!pending)throw new InvalidOperationException("No request owns reply line "+lineNumber);
                var result=observe(frame);
                if(result==AL5ReadOnlyCoreReply.Malformed)throw new ArgumentException("Malformed correlated reply at line "+lineNumber);
                if(result==AL5ReadOnlyCoreReply.Matched){matched++;pending=false;}else unrelated++;
            }
        }
        if(pending)throw new ArgumentException("Transcript ended with an unresolved request.");
        return (matched,unrelated);
    }
    static void Save(string path,byte[] bytes)
    {
        using var stream=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.Read);stream.Write(bytes);stream.Flush(true);
    }
    static int Main(string[] args)
    {
        try{return Run(args);}
        catch(Exception error) when(error is ArgumentException || error is InvalidOperationException || error is IOException ||
            error is FormatException || error is JsonException || error is KeyNotFoundException || error is UnauthorizedAccessException)
        {
            Console.Error.WriteLine("Backup input rejected: "+error.Message);return 1;
        }
    }
    static int Run(string[] args)
    {
        if(args.Length>0 && args[0]=="--readback-epoch")return ReadbackEpoch(args);
        if(args.Length>0 && args[0]=="--external-readback")return ExternalReadback(args);
        if(args.Length>0 && args[0]=="--capture-external-readback")return CaptureExternalReadback(args);
        if(args.Length>0 && args[0]=="--external-chip")return ExternalChip(args);
        if(args.Length>0 && args[0]=="--external-prepared")return ExternalPrepared(args);
        if(args.Length>0 && args[0]=="--startup-bank-review")return StartupBankReview(args);
        if(args.Length>0 && args[0]=="--resident-banks")return ResidentBanks(args);
        if(args.Length!=6)
        {
            Console.Error.WriteLine("Offline only: original-transcript.txt prepared-transcript.txt original-nonce-hex prepared-nonce-hex evidence-id NEW-output-directory");return 2;
        }
        string output=Path.GetFullPath(args[5]);
        if(Directory.Exists(output) || File.Exists(output))throw new ArgumentException("New output directory required; existing evidence is retained.");
        byte[] originalTranscript=File.ReadAllBytes(args[0]),preparedTranscript=File.ReadAllBytes(args[1]);
        var path=new AL5SavedBackupPath(args[4],Convert.FromHexString(args[2]),Convert.FromHexString(args[3]));
        var originalCounts=Consume(path,originalTranscript);
        path.RecordEntryBoundaryForOfflineReview();
        var preparedCounts=Consume(path,preparedTranscript);var reference=path.CopyPreparedReference();
        byte[] original=path.CopyOriginalImage(),originalBanks=reference.CopyOriginal(),prepared=reference.CopyPrepared();
        // All parsing/coverage validation completes before any output file is created.
        Directory.CreateDirectory(output);
        Save(Path.Combine(output,"original.saved.bin"),original);
        Save(Path.Combine(output,"original_banks.saved.bin"),originalBanks);
        Save(Path.Combine(output,"prepared_banks.saved.bin"),prepared);
        var report=new {
            schema="al5-saved-backup-path-v1",path.EvidenceId,phase=path.Phase.ToString(),
            original_transcript=Input(args[0],originalTranscript),prepared_transcript=Input(args[1],preparedTranscript),
            original_nonce_hex=args[2],prepared_nonce_hex=args[3],
            original_bytes=original.Length,original_sha256=Hash(original),original_bank_sha256=reference.OriginalSha256,
            prepared_bank_bytes=prepared.Length,prepared_bank_sha256=reference.PreparedSha256,preparation_changed_bytes=reference.ChangedBytes,
            original_matched_replies=originalCounts.matched,original_unrelated_replies=originalCounts.unrelated,
            prepared_matched_replies=preparedCounts.matched,prepared_unrelated_replies=preparedCounts.unrelated,
            provenance="caller_supplied_saved_correlated_responses_not_physical_acquisition_proof",
            hardware_access=false,pre_entry_physical_acquisition_verified=false,physical_address_mapping_verified=false,
            live_upload_enabled=false,live_execution_enabled=false,live_write_enabled=false,ready_to_flash=false
        };
        Save(Path.Combine(output,"backup.json"),JsonSerializer.SerializeToUtf8Bytes(report,new JsonSerializerOptions{WriteIndented=true}));
        Console.WriteLine("Exported complete saved original and prepared bank epochs. No live operations; physical acquisition remains unqualified.");return 0;
    }

    static byte[] ReadFullChip(string path)
        =>ReadSizedFile(path,0x100000);
    static byte[] ReadSizedFile(string path,int count)
    {
        using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(stream.Length!=count)throw new ArgumentException("Exact "+count+" saved bytes required; no padding, truncation or short-image substitution.");
        var bytes=new byte[count];stream.ReadExactly(bytes);
        if(stream.ReadByte()!=-1)throw new ArgumentException("Chip file changed size during import.");
        return bytes;
    }

    static int StartupBankReview(string[] args)
    {
        if(args.Length!=8)throw new ArgumentException("--startup-bank-review original-full.bin prepared-banks.bin readback-full.bin journal-report.json case-name evidence-id NEW-output-directory");
        string output=Path.GetFullPath(args[7]);
        if(Directory.Exists(output)||File.Exists(output))throw new ArgumentException("New output directory required.");
        byte[] original=ReadFullChip(args[1]),prepared=ReadSizedFile(args[2],0x4000),readback=ReadFullChip(args[3]),metadata=File.ReadAllBytes(args[4]);
        var security=new AL5SavedSecurityExchange(original); // Saved validation only; no session or key sender.
        using var document=JsonDocument.Parse(metadata);var root=document.RootElement;
        if(root.GetProperty("schema").GetString()!="al5-native-journal-restart-v1" || root.GetProperty("reference_sha256").GetString()!=Hash(original))
            throw new ArgumentException("Journal prediction must name the exact saved original.");
        foreach(string flag in new[]{"hardware_access","physical_reset_verified","physical_journal_transition_verified","host_verification_window_proven","live_upload_enabled","live_execution_enabled","live_write_enabled","ready_to_flash"})
            if(root.GetProperty(flag).GetBoolean())throw new ArgumentException("Prediction cannot promote physical/live authority.");
        var matches=root.GetProperty("cases").EnumerateArray().Where(row=>row.GetProperty("case").GetString()==args[5]).ToArray();
        if(matches.Length!=1)throw new ArgumentException("One exact selected journal case required.");
        var row=matches[0].GetProperty("observed");string bankHash=Hash(prepared);
        byte[] overlaid=(byte[])original.Clone();prepared.CopyTo(overlaid,0x4000);
        if(row.GetProperty("selected_reference_sha256").GetString()!=Hash(original) ||
            row.GetProperty("flash_image_sha256").GetString()!=Hash(overlaid) ||
            row.GetProperty("saved_bank_overlay_sha256").GetString()!=bankHash || row.GetProperty("bank_comparison").GetProperty("original_sha256").GetString()!=bankHash ||
            row.GetProperty("stop").GetProperty("reason").GetString()!="after_native_startup_handshake")
            throw new ArgumentException("Selected bounded prediction must own this prepared-bank epoch.");
        var operations=new List<AL5SavedBankProgram>();
        foreach(var operation in row.GetProperty("synthetic_bank_programs").EnumerateArray())
        {
            if(operation.GetProperty("implementation_executed").GetBoolean())throw new ArgumentException("Only declared host-modeled bank operations supported.");
            byte[] before=Convert.FromHexString(operation.GetProperty("before").GetString()!),after=Convert.FromHexString(operation.GetProperty("after").GetString()!);
            if(operation.GetProperty("bytes").GetInt32()!=after.Length)throw new ArgumentException("Saved operation length differs.");
            operations.Add(new AL5SavedBankProgram(operation.GetProperty("caller_return").GetInt32(),operation.GetProperty("destination").GetInt32(),before,after));
        }
        var review=new AL5SavedBankTransitionReview(args[6],Hash(original),prepared,operations.ToArray());
        if(review.PredictedBanksSha256!=row.GetProperty("bank_comparison").GetProperty("final_sha256").GetString())throw new ArgumentException("Ordered operations differ from the declared final-bank digest.");
        var assessment=review.CompareSavedBanks(readback.AsSpan(0x4000,0x4000).ToArray());
        var report=new {schema="al5-saved-startup-bank-diagnosis-v1",evidence_id=review.EvidenceId,selected_case=args[5],
            original=Input(args[1],original),prepared=Input(args[2],prepared),readback=Input(args[3],readback),native_prediction=Input(args[4],metadata),
            review.OriginalSha256,review.PreparedBanksSha256,review.PredictedBanksSha256,review.OperationCount,
            assessment.ChangedFromPreparedBytes,assessment.DifferencesFromPrediction,assessment.MatchesSavedPrediction,
            changed_addresses=assessment.CopyChangedAddresses(),prediction_mismatch_addresses=assessment.CopyPredictionMismatchAddresses(),
            comparison_scope="all_16384_bank_bytes_only_not_other_flash_regions",preservation_verified=false,physical_transition_verified=false,
            snapshot_coherence_verified=false,hardware_access=false,live_upload_enabled=false,live_execution_enabled=false,live_write_enabled=false,ready_to_flash=false};
        Directory.CreateDirectory(output);Save(Path.Combine(output,"predicted_banks.offline.bin"),review.CopyPredictedBanks());
        Save(Path.Combine(output,"review.json"),JsonSerializer.SerializeToUtf8Bytes(report,new JsonSerializerOptions{WriteIndented=true}));
        Console.WriteLine("Saved bank diagnosis: "+assessment.DifferencesFromPrediction+" bytes differ from the exact prediction. This does not authorize preservation acceptance or live operations.");return 0;
    }

    static int ExternalChip(string[] args)
    {
        if(args.Length!=6 && (args.Length!=8 || args[6]!="--target-id"))throw new ArgumentException("--external-chip first-raw.bin second-raw.bin cpu-bytes|swap16 evidence-id NEW-output-directory [--target-id TARGET-ID]");
        string? targetId=args.Length==8?args[7]:null;
        if(targetId!=null && string.IsNullOrWhiteSpace(targetId))throw new ArgumentException("Nonblank explicit target identity required.");
        if(args[3]!="cpu-bytes" && args[3]!="swap16")throw new ArgumentException("Explicit byte representation required; no automatic word swap.");
        if(string.IsNullOrWhiteSpace(args[4]))throw new ArgumentException("Explicit evidence identity required.");
        string output=Path.GetFullPath(args[5]);
        if(Directory.Exists(output)||File.Exists(output))throw new ArgumentException("New output directory required.");
        var pair=ReadExternalPair(args[1],args[2],args[3]);
        byte[] first=pair.CopyFirstRaw(),second=pair.CopySecondRaw(),canonical=pair.CopyCanonical();
        if(pair.AllFF || pair.AllZero)throw new ArgumentException("Blank or zero-filled input is not an AL5 original.");
        byte[] calibration=canonical.AsSpan(AL5CalibrationInspection.StartAddress,AL5CalibrationInspection.Length).ToArray();
        var profile=AL5CalibrationWriteProfile.InspectSavedReference(canonical,calibration);
        if(!profile.SavedBytesMatchProfile)throw new ArgumentException("Selected representation does not match the supported AL5 boot/OS/calibration profile; no automatic reinterpretation.");
        byte[] banks=canonical.AsSpan(0x4000,0x4000).ToArray();
        var report=new {
            schema="al5-saved-external-chip-backup-v1",evidence_id=args[4],target_id=targetId,raw_first=Input(args[1],first),raw_second=Input(args[2],second),
            representation=args[3],explicit_adjacent_pair_conversion=args[3]=="swap16",raw_saved_files_match=true,
            canonical_bytes=canonical.Length,canonical_sha256=Hash(canonical),original_bank_sha256=Hash(banks),saved_profile=profile,
            acquisition_epoch="caller_supplied_external_dump_epoch_not_physically_verified",provenance="saved_files_only_not_hardware_read_or_recovery_proof",
            distinct_selected_paths_do_not_prove_independent_reads=true,hard_link_identity_verified=false,
            chip_identity_verified=false,physical_data_lane_mapping_verified=false,pre_entry_physical_acquisition_verified=false,
            physical_recovery_verified=false,hardware_access=false,live_upload_enabled=false,live_execution_enabled=false,live_write_enabled=false,ready_to_flash=false
        };
        Directory.CreateDirectory(output);
        Save(Path.Combine(output,"first.raw.saved.bin"),first);Save(Path.Combine(output,"second.raw.saved.bin"),second);
        Save(Path.Combine(output,"original.canonical.saved.bin"),canonical);Save(Path.Combine(output,"original_banks.saved.bin"),banks);
        Save(Path.Combine(output,"backup.json"),JsonSerializer.SerializeToUtf8Bytes(report,new JsonSerializerOptions{WriteIndented=true}));
        Console.WriteLine("Imported two matching full-chip saved files with explicit byte representation; originals retained. No hardware or recovery qualification inferred.");return 0;
    }

    static int ExternalPrepared(string[] args)
    {
        if(args.Length!=7 || args[5]!="--entry-boundary-recorded")
            throw new ArgumentException("--external-prepared external-backup-directory prepared-transcript.txt prepared-nonce-hex evidence-id --entry-boundary-recorded NEW-output-directory");
        if(string.IsNullOrWhiteSpace(args[4]))throw new ArgumentException("Explicit evidence identity required.");
        string output=Path.GetFullPath(args[6]);
        if(Directory.Exists(output)||File.Exists(output))throw new ArgumentException("New output directory required.");
        string source=Path.GetFullPath(args[1]);var loaded=LoadExternalOriginal(source);byte[] metadata=loaded.Metadata,original=loaded.Original;
        var security=new AL5SavedSecurityExchange(original); // Pure saved-profile validation; never sends a key.
        byte[] originalBanks=original.AsSpan(0x4000,0x4000).ToArray();
        byte[] transcript=File.ReadAllBytes(args[2]);
        var campaign=AL5SavedBackupPath.FromSavedExternalOriginal(args[4],original,Convert.FromHexString(args[3]));
        campaign.RecordEntryBoundaryForOfflineReview();var counts=Consume(campaign,transcript);
        var reference=campaign.CopyPreparedReference();byte[] prepared=reference.CopyPrepared();
        var result=new {
            schema="al5-external-original-prepared-backup-v1",evidence_id=args[4],external_original_directory=source,
            external_metadata=Input(Path.Combine(source,"backup.json"),metadata),prepared_transcript=Input(args[2],transcript),prepared_nonce_hex=args[3],
            original_bytes=original.Length,original_sha256=Hash(original),original_bank_sha256=reference.OriginalSha256,
            prepared_bank_bytes=prepared.Length,prepared_bank_sha256=reference.PreparedSha256,preparation_changed_bytes=reference.ChangedBytes,
            prepared_matched_replies=counts.matched,prepared_unrelated_replies=counts.unrelated,
            changed_bank_bytes_scope="all_external_original_to_prepared_changes_not_programming_entry_only",
            saved_security_state=security.State.ToString(),entry_boundary="explicit_caller_record_not_physical_proof",
            original_source_kind=campaign.OriginalSourceKind,
            provenance="external_saved_original_plus_separately_correlated_saved_prepared_epoch",
            physical_security_verified=false,pre_entry_physical_acquisition_verified=false,physical_address_mapping_verified=false,
            snapshot_coherence_verified=false,physical_recovery_verified=false,hardware_access=false,
            live_upload_enabled=false,live_execution_enabled=false,live_write_enabled=false,ready_to_flash=false
        };
        Directory.CreateDirectory(output);Save(Path.Combine(output,"original.saved.bin"),original);
        Save(Path.Combine(output,"original_banks.saved.bin"),originalBanks);Save(Path.Combine(output,"prepared_banks.saved.bin"),prepared);
        Save(Path.Combine(output,"backup.json"),JsonSerializer.SerializeToUtf8Bytes(result,new JsonSerializerOptions{WriteIndented=true}));
        Console.WriteLine("Joined an owned external saved original with complete correlated prepared banks; no physical security, acquisition or live authority inferred.");return 0;
    }

    static int ResidentBanks(string[] args)
    {
        if(args.Length!=5)throw new ArgumentException("--resident-banks pinned-sps-os.bin frames.jsonl evidence-id NEW-output-directory");
        if(string.IsNullOrWhiteSpace(args[3]))throw new ArgumentException("Explicit evidence identity required.");
        string output=Path.GetFullPath(args[4]);
        if(Directory.Exists(output) || File.Exists(output))throw new ArgumentException("New output directory required.");
        byte[] os=File.ReadAllBytes(args[1]),raw=File.ReadAllBytes(args[2]);
        var campaign=new AL5SavedPersistentBankCampaign(os);
        using(var reader=new StreamReader(new MemoryStream(raw),new System.Text.UTF8Encoding(false,true)))
        {
            while(reader.ReadLine() is string line)
            {
                using var document=JsonDocument.Parse(line);var row=document.RootElement;
                if(row.GetProperty("address").GetInt32()!=AL5SavedPersistentBankCampaign.StartAddress+campaign.BytesObserved)
                    throw new ArgumentException("Resident bank records must follow the explicit saved interval.");
                var request=Convert.FromHexString(row.GetProperty("vpw_request_hex").GetString()!);
                if(!campaign.BeginNextSavedVpwRequest().SequenceEqual(request))throw new ArgumentException("Resident request differs from the next saved bank request.");
                var kind=campaign.ObserveSavedVpwReply(Convert.FromHexString(row.GetProperty("vpw_reply_hex").GetString()!),out _);
                if(kind!=AL5SavedReplyKind.MatchingLow16Echo)throw new ArgumentException("Resident record did not supply the expected low-16 echo.");
            }
        }
        byte[] banks=campaign.CopyCompleteSavedBanks();
        var report=new {
            schema="al5-saved-resident-bank-backup-v1",evidence_id=args[3],
            os=Input(args[1],os),transcript=Input(args[2],raw),start_address="0x4000",bytes=banks.Length,
            bank_sha256=Hash(banks),requests=campaign.BytesObserved/4,
            acquisition_epoch="caller_claimed_pre_entry_not_physically_verified",
            complete_full_original_image=false,physical_readback_verified=false,pre_entry_acquisition_proven=false,
            freshness_proven=false,full_address_identity_proven=false,hardware_access=false,
            live_read_enabled=false,live_upload_enabled=false,live_execution_enabled=false,live_write_enabled=false,ready_to_flash=false,
            limit="Only low-16 response correlation; a stale same-echo reply cannot be identified by this wire format. This bank file is not a complete independent original backup."
        };
        Directory.CreateDirectory(output);
        Save(Path.Combine(output,"preentry_banks.saved.bin"),banks);
        Save(Path.Combine(output,"backup.json"),JsonSerializer.SerializeToUtf8Bytes(report,new JsonSerializerOptions{WriteIndented=true}));
        Console.WriteLine("Exported 16384 saved resident bank bytes; physical pre-entry acquisition remains unqualified.");return 0;
    }
}
