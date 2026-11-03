using System.Security.Cryptography;
using System.Text.Json;
using PcmHacking;

// File-only transcript consumer. No Vehicle, adapter, USB or serial object is constructed.
static class Program
{
    static string Hash(byte[] bytes)=>Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    static object Input(string path,byte[] bytes)=>new {selected=path,resolved=Path.GetFullPath(path),bytes=bytes.Length,sha256=Hash(bytes)};
    static (int matched,int unrelated) Consume(AL5SavedBackupPath path,byte[] transcript)
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
                byte[] expected=path.BeginNextSavedRequest();
                if(!frame.SequenceEqual(expected))throw new ArgumentException("Request differs from the current acquisition at line "+lineNumber);
                pending=true;
            }
            else
            {
                if(!pending)throw new InvalidOperationException("No request owns reply line "+lineNumber);
                var result=path.ObserveSavedReply(frame);
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
}
