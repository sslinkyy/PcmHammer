using PcmHacking;
using System.Text.Json;

static class Program
{
    static void Check(bool condition,string reason){if(!condition)throw new Exception(reason);}
    static void Blocked(AL5SavedPersistentBankCampaign c)=>Check(!c.PreEntryAcquisitionProven && !c.FreshnessProven &&
        !c.FullAddressIdentityProven && !c.LiveReadEnabled && !c.LiveUploadEnabled && !c.LiveExecutionEnabled && !c.LiveWriteEnabled,"No physical freshness or live authority");
    static void Reject(Action action)
    {
        try{action();}catch(ArgumentException){return;}catch(InvalidOperationException){return;}
        throw new Exception("Expected rejection");
    }
    static int Main(string[] args)
    {
        if(args.Length!=2)throw new ArgumentException("Pinned SPS OS and native freshness report required; file-only tests.");
        byte[] os=File.ReadAllBytes(args[0]);using var doc=JsonDocument.Parse(File.ReadAllBytes(args[1]));var root=doc.RootElement;
        Check(root.GetProperty("schema").GetString()=="al5-native-resident-reply-freshness-v1","Exact native producer schema");
        foreach(string flag in new[]{"hardware_access","session_boundary_proven","physical_status_semantics_verified","live_read_enabled","live_upload_enabled","live_execution_enabled","live_write_enabled"})
            Check(!root.GetProperty(flag).GetBoolean(),"Producer must retain false physical/live gates");
        var rows=root.GetProperty("cases").EnumerateArray().ToDictionary(row=>row.GetProperty("case").GetString()!+ (row.TryGetProperty("pattern",out var pattern)?pattern.GetInt32().ToString():""));
        Check(rows.Count==12,"Complete native state corpus");
        foreach((string name,int mask,int tracked,string pending) in new[]{("requeue",0,0,"10"),("retire",0x40,0,"00"),
            ("retain_tracking",0x80,75,"00"),("discard_and_requeue",0xC0,0,"10"),("class_a0",0x10,75,"00"),
            ("nonempty_tx",0x20,75,"00"),("empty_rx_retains_tracking",0x40,75,"00")})
        {
            var row=rows[name];var after=row.GetProperty("after");
            Check(after.GetProperty("events").EnumerateArray().Last().GetInt32()==mask,"Native mask derivation");
            Check(after.GetProperty("tracked_index").GetInt32()==tracked && after.GetProperty("pending").GetString()==pending,"Native tracking/pending result");
            Check(after.GetProperty("banks_unchanged").GetBoolean(),"Banks remain unchanged");
        }
        var reset=rows["native_interface_reset_requeues_reply"];var resetAfter=reset.GetProperty("after");
        Check(resetAfter.GetProperty("tx_count").GetInt32()==0 && resetAfter.GetProperty("ring").GetString()==new string('0',108) && resetAfter.GetProperty("pending").GetString()=="10","Empty staging/ring do not prevent requeue");
        var init=rows["interface_initializer_retains_old_tracking"];
        Check(init.GetProperty("after").GetProperty("tracked_index").GetInt32()==75 &&
            init.GetProperty("after").GetProperty("body").GetString()==init.GetProperty("before").GetProperty("body").GetString(),"Interface initialization alone retains old response state");
        foreach(int pattern in new[]{0xA5,0x5A})
        {
            var row=rows["application_crt_clears_response_state_before_main"+pattern];var cleared=row.GetProperty("cleared");
            Check(cleared.GetProperty("body").GetString()=="000000000000" && cleared.GetProperty("tracked_index").GetInt32()==0 && cleared.GetProperty("pending").GetString()=="00","CRT clears saved state");
            Check(!row.GetProperty("application_main_executed").GetBoolean() && !row.GetProperty("physical_reset_verified").GetBoolean(),"CRT slice is not a full physical cold start");
        }
        var witness=rows["retired_tracking_does_not_fence_later_aliased_request"];
        byte[] first=Convert.FromHexString(witness.GetProperty("original_submission_hex").GetString()!);
        byte[] alias=Convert.FromHexString(witness.GetProperty("aliased_submission_hex").GetString()!);
        Check(first.AsSpan(0,6).SequenceEqual(alias.AsSpan(0,6)) && !first.SequenceEqual(alias),"Actual native same-echo/different-body witness");
        var c=new AL5SavedPersistentBankCampaign(os);c.BeginNextSavedVpwRequest();
        Check(c.ObserveSavedVpwReply(first,out _)==AL5SavedReplyKind.MatchingLow16Echo && c.BytesObserved==4,"Original reply supplies one dword");
        c.BeginNextSavedVpwRequest();
        Check(c.ObserveSavedVpwReply(alias,out _)==AL5SavedReplyKind.Unrelated && c.HasPendingRequest && c.BytesObserved==4,"Aliased earlier echo cannot consume next dword");
        c.TimeoutOrCancel();Reject(()=>c.BeginNextSavedVpwRequest());Reject(()=>c.CopyCompleteSavedBanks());Blocked(c);
        c=new AL5SavedPersistentBankCampaign(os);c.BeginNextSavedVpwRequest();
        Check(c.ObserveSavedVpwReply(alias,out _)==AL5SavedReplyKind.MatchingLow16Echo && c.BytesObserved==4,"A new host campaign cannot distinguish the native same-echo alias");
        Blocked(c);Reject(()=>c.CopyCompleteSavedBanks());
        Console.WriteLine("PASS 12 native state outcomes and production host duplicate/alias/stop guards; no physical freshness or live authority.");return 0;
    }
}
