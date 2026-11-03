using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using PcmHacking;

static class WriteCandidateTool
{
    static string Hash(byte[] bytes)=>Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    static object Input(string path,byte[] bytes)=>new { selected=path,resolved=Path.GetFullPath(path),bytes=bytes.Length,sha256=Hash(bytes) };
    static void Save(string path,object value)
    {
        using var stream=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.Read);
        JsonSerializer.Serialize(stream,value,new JsonSerializerOptions { WriteIndented=true });stream.Flush(true);
    }
    static void SaveBytes(string path,byte[] bytes)
    {
        using var stream=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.Read);
        stream.Write(bytes);stream.Flush(true);
    }
    static StreamWriter NewWriter(string path)=>new StreamWriter(new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.Read));
    static int Main(string[] args)
    {
        if(args.Length!=4 && args.Length!=5)
        {
            Console.Error.WriteLine("Offline only: loader.bin calibration.bin full-reference.bin NEW-output-directory [saved-control-template.txt]");
            return 2;
        }
        string output=Path.GetFullPath(args[3]);
        if(Directory.Exists(output) || File.Exists(output))throw new ArgumentException("Choose a new output directory; existing evidence is retained.");
        byte[] loader=File.ReadAllBytes(args[0]),calibration=File.ReadAllBytes(args[1]),baseline=File.ReadAllBytes(args[2]);
        var candidate=new AL5CalibrationWriteCandidate(loader,calibration,baseline);
        byte[] expected=candidate.CopyExpectedSavedImage();
        Directory.CreateDirectory(output);
        try
        {
            SaveBytes(Path.Combine(output,"expected.offline.bin"),expected);
            SaveBytes(Path.Combine(output,"baseline.reference.bin"),baseline);
            SaveBytes(Path.Combine(output,"calibration.reference.bin"),calibration);
            SaveBytes(Path.Combine(output,"loader.reference.bin"),loader);
            using(var requests=NewWriter(Path.Combine(output,"programming_requests.jsonl")))
                for(int i=0;i<candidate.ConstructedProgrammingRequests;i++)
                {
                    byte[] request=candidate.CopyConstructedProgrammingRequest(i);
                    requests.WriteLine(JsonSerializer.Serialize(new { index=i, vpw_request_hex=Convert.ToHexString(request).ToLowerInvariant(),sha256=Hash(request) }));
                }
            object? template=null;
            if(args.Length==5)
            {
                byte[] raw=File.ReadAllBytes(args[4]);template=Input(args[4],raw);
                SaveBytes(Path.Combine(output,"saved_control_template.txt"),raw);
                using var transcript=NewWriter(Path.Combine(output,"rehearsal.jsonl"));
                foreach(string line in File.ReadAllLines(args[4]))
                {
                    if(line.Length<3 || (line[0]!='T' && line[0]!='R') || line[1]!=' ')throw new ArgumentException("Unexpected template record.");
                    bool tx=line[0]=='T';byte[] message=Convert.FromHexString(line.Substring(2));
                    bool replaced=false;
                    if(tx && message.Length>12 && message[3]==0x36 && message[4]==0)
                    {
                        int address=(message[7]<<16)|(message[8]<<8)|message[9];
                        if(address<0x8000 || (address-0x8000)%512!=0)throw new ArgumentException("Unaligned template block.");
                        message=candidate.CopyConstructedProgrammingRequest(2+(address-0x8000)/512);replaced=true;
                    }
                    else if(tx && message.Length==1602 && message[3]==0x36 && message[4]==0x80)
                    {message=candidate.CopyConstructedProgrammingRequest(0);replaced=true;}
                    var before=candidate.NextOfflineAction();candidate.ObserveSavedFrame(tx,message);
                    transcript.WriteLine(JsonSerializer.Serialize(new { transmitted=tx,constructed_payload=replaced,
                        action_before=before.Kind.ToString(),message_hex=Convert.ToHexString(message).ToLowerInvariant(),state_after=candidate.State.ToString() }));
                }
                if(candidate.State!=AL5CapturedWriteState.AwaitingSavedVerification || candidate.PositiveProgramReplies!=192)
                    throw new InvalidOperationException("Control/reply template did not complete the offline programming lifecycle.");
            }
            int changed=baseline.Zip(expected,(a,b)=>a==b?0:1).Sum();
            Save(Path.Combine(output,"candidate.json"),new {
                schema="al5-calibration-write-candidate-v1",profile=AL5CalibrationWriteCandidate.Profile,
                loader=Input(args[0],loader),calibration=Input(args[1],calibration),baseline=Input(args[2],baseline),
                baseline_provenance="caller_supplied_saved_reference_not_physically_qualified",control_template=template,
                saved_profile=AL5CalibrationWriteProfile.InspectSavedReference(baseline,calibration),
                template_semantics="Saved control/reply observations with constructed payload substitution; not a successful custom flash.",
                candidate.BaselineSha256,candidate.PreEraseSectorSha256,
                constructed_programming_requests=candidate.ConstructedProgrammingRequests,program_blocks=192,
                erase_sector_starts=new[]{"0x8000","0x10000"},finalization_marker="0x1FFFE:4AFC",
                expected_sha256=Hash(expected),expected_changed_bytes=changed,
                state=candidate.State.ToString(),candidate.PositiveProgramReplies,candidate.ChecksumErrors,candidate.RepeatsWithoutReply,
                independent_full_readback_supplied=false,complete_saved_comparison=candidate.CompleteSavedComparison,
                hardware_access=false,live_upload_enabled=false,live_execution_enabled=false,live_write_enabled=false,
                automatic_retry_enabled=false,ready_to_flash=false,
                remaining_gates=new[]{"Fresh controller/profile and security qualification", "Original pre-entry persistent-bank acquisition",
                    "Physical entry, transport and watchdog qualification", "Independent full preservation readback", "Demonstrated recovery on the spare"}
            });
            Console.WriteLine("Prepared 195 offline requests, complete reference and expected image. State: "+candidate.State+". No adapter linked; no live writes enabled.");
            return 0;
        }
        catch(Exception error)
        {
            try{Save(Path.Combine(output,"failure.json"),new { complete=false,error=error.Message,hardware_access=false,live_write_enabled=false });}
            catch(IOException){ /* Preserve an existing failure record and propagate the original error. */ }
            throw;
        }
    }
}
