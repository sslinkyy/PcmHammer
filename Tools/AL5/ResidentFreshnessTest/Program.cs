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
        if(args.Length<2 || args.Length>5)throw new ArgumentException("Pinned SPS OS and native freshness report [receiver-init report [startup-scheduling report [saved-candidate directory]]] required; file-only tests.");
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
        CheckQueuedDelivery(os,alias).GetAwaiter().GetResult();
        if(args.Length>=3)CheckReceiverInitialization(os,args[2]);
        if(args.Length>=4)CheckStartupScheduling(os,args[3]);
        if(args.Length==5)CheckJournalReadbackEpoch(args[3],args[4]);
        Console.WriteLine("PASS 12 native state outcomes and production host duplicate/alias/stop guards; no physical freshness or live authority.");return 0;
    }

    static void CheckJournalReadbackEpoch(string startupPath,string directory)
    {
        using var doc=JsonDocument.Parse(File.ReadAllBytes(startupPath));var row=doc.RootElement.GetProperty("cases").EnumerateArray().Single();
        byte[] loader=File.ReadAllBytes(Path.Combine(directory,"loader.reference.bin"));
        byte[] calibration=File.ReadAllBytes(Path.Combine(directory,"calibration.reference.bin"));
        byte[] original=File.ReadAllBytes(Path.Combine(directory,"baseline.reference.bin"));
        var frames=File.ReadAllLines(Path.Combine(directory,"rehearsal.jsonl"));
        AL5CalibrationWriteCandidate Rehearse()
        {
            var candidate=new AL5CalibrationWriteCandidate(loader,calibration,original);
            foreach(string frame in frames)
            {
                using var record=JsonDocument.Parse(frame);var value=record.RootElement;
                candidate.ObserveSavedFrame(value.GetProperty("transmitted").GetBoolean(),Convert.FromHexString(value.GetProperty("message_hex").GetString()!));
            }
            Check(candidate.State==AL5CapturedWriteState.AwaitingSavedVerification,"Saved lifecycle reaches its existing cleanup/verification boundary");
            return candidate;
        }
        var control=Rehearse();control.VerifySavedFullReadback(control.CopyExpectedSavedImage());
        Check(control.CompleteSavedComparison && !control.PhysicalReadbackVerified && !control.ReadyToFlash,"Predicted control is a saved comparison, not independent physical readback");
        var changed=Rehearse();var readback=changed.CopyExpectedSavedImage();
        foreach(var operation in row.GetProperty("synthetic_bank_programs").EnumerateArray())
        {
            int address=operation.GetProperty("destination").GetInt32();byte[] before=Convert.FromHexString(operation.GetProperty("before").GetString()!);
            byte[] after=Convert.FromHexString(operation.GetProperty("after").GetString()!);
            Check(!operation.GetProperty("implementation_executed").GetBoolean() && before.Length==after.Length &&
                readback.AsSpan(address,before.Length).SequenceEqual(before),"Native journal request applies to the owned historical bank state");
            after.CopyTo(readback,address);
        }
        var assessment=changed.VerifySavedFullReadback(readback);
        Check(assessment.ExactSavedImageMatch && !changed.CompleteSavedComparison && changed.ChangedPersistentBankBytes==8 && changed.ChangedOtherProtectedBytes==0,
            "Native ordinary journal changes keep full preservation verification failed despite exact programmed-sector comparison");
        Check(changed.State==AL5CapturedWriteState.Stopped && !changed.LiveWriteEnabled && !changed.PhysicalReadbackVerified && !changed.ReadyToFlash,"Journal evidence cannot silently whitelist bank changes or enable writes");
        Console.WriteLine("PASS native startup journal applied to the saved writer lifecycle: programmed sectors match, eight bank changes still fail complete preservation verification.");
    }

    static async Task CheckQueuedDelivery(byte[] os,byte[] nativeAlias)
    {
        static byte[] Dvi(byte command,byte[] payload)
        {
            var bytes=new byte[payload.Length+3];bytes[0]=command;bytes[1]=(byte)payload.Length;payload.CopyTo(bytes,2);
            bytes[^1]=(byte)~(bytes.Take(bytes.Length-1).Sum(b=>(int)b)&255);return bytes;
        }
        using var port=new DeferredFramePort();using var device=new OBDXProDevice(port,new Tests.TestLogger());
        port.Enqueue(Dvi(8,nativeAlias));port.Enqueue(Dvi(0x20,new byte[]{0}));
        Check(await device.SendMessage(new Message(Convert.FromHexString("6D18F02300400001"))),"Scripted adapter accepts one request");
        Check(device.ReceivedMessageCount==1,"Production GT parser queued the earlier bus frame before adapter acknowledgement");
        device.ClearMessageQueue();
        Check(device.ReceivedMessageCount==0 && port.Discards==1,"Host queue and local port discard completed");
        port.ArmUpstream(Dvi(8,nativeAlias));
        var late=await device.ReceiveMessage();
        Check(late.GetBytes().SequenceEqual(nativeAlias),"A separate upstream delivery survives the completed local flush");
        var campaign=new AL5SavedPersistentBankCampaign(os);campaign.BeginNextSavedVpwRequest();
        Check(campaign.ObserveSavedVpwReply(late.GetBytes(),out _)==AL5SavedReplyKind.MatchingLow16Echo && campaign.BytesObserved==4,"A fresh host owner still cannot identify the late native upper-bank alias");
        Check(port.Sends==1,"Queue boundary test sends no automatic retries");Blocked(campaign);
        campaign.TimeoutOrCancel();Reject(()=>campaign.CopyCompleteSavedBanks());
        Console.WriteLine("PASS production GT queue/discard counterexample with scripted upstream delivery; a local flush does not prove end-to-end freshness.");
    }

    static void CheckStartupScheduling(byte[] os,string path)
    {
        using var doc=JsonDocument.Parse(File.ReadAllBytes(path));var root=doc.RootElement;
        Check(root.GetProperty("schema").GetString()=="al5-offline-application-startup-audit-v1","Exact startup producer schema");
        foreach(string flag in new[]{"hardware_access","full_startup_verified","physical_receiver_ready_verified","session_boundary_proven","live_read_enabled","live_upload_enabled","live_execution_enabled","live_write_enabled"})
            Check(!root.GetProperty(flag).GetBoolean(),"Native scheduling model retains false physical/live gates");
        var row=root.GetProperty("cases").EnumerateArray().Single();
        Check(row.GetProperty("stop").GetProperty("reason").GetString()=="after_native_startup_handshake" &&
            row.GetProperty("scheduling_context").GetProperty("handshake").GetInt32()==3,"Native foreground consumed the handshake");
        Check(row.GetProperty("entry_counts").GetProperty("0xa4a38").GetInt32()==80 &&
            row.GetProperty("entry_counts").GetProperty("0x238ac").GetInt32()==80,"Native scheduled dequeue and response selection");
        Check(row.GetProperty("scripted_ticks").GetArrayLength()==320 &&
            row.GetProperty("scripted_ticks").EnumerateArray().All(t=>t.GetProperty("returned").GetBoolean()&&!t.GetProperty("physical_exception_delivered").GetBoolean()),"Scripted timer bodies do not prove real IRQ delivery");
        Check(row.GetProperty("final_state").GetProperty("tracking").GetString()=="0002" &&
            row.GetProperty("final_state").GetProperty("body").GetString()=="000000000000","Empty Mode 23 body does not imply empty response tracking");
        var submission=row.GetProperty("software_submissions").EnumerateArray().Single();
        byte[] frame=Convert.FromHexString(submission.GetProperty("hex").GetString()!);
        Check(submission.GetProperty("response_index").GetInt32()==2 && frame.SequenceEqual(Convert.FromHexString("49FE1806")),"Actual native background submission");
        var campaign=new AL5SavedPersistentBankCampaign(os);campaign.BeginNextSavedVpwRequest();
        Check(campaign.ObserveSavedVpwReply(frame,out _)==AL5SavedReplyKind.Unrelated && campaign.BytesObserved==0 && campaign.HasPendingRequest,"Background startup frame cannot advance bank coverage");
        campaign.TimeoutOrCancel();Reject(()=>campaign.BeginNextSavedVpwRequest());Reject(()=>campaign.CopyCompleteSavedBanks());Blocked(campaign);
        if(row.TryGetProperty("background_completion_probes",out var probes) && probes.GetArrayLength()>0)
        {
            Check(probes.GetArrayLength()==4,"Complete background completion branch corpus");
            foreach(var probe in probes.EnumerateArray())
            {
                Check(probe.GetProperty("returned").GetBoolean() && probe.GetProperty("banks_unchanged_during_probe").GetBoolean() &&
                    !probe.GetProperty("physical_status_semantics_verified").GetBoolean(),"Native background branches remain conditional and non-programming");
                string name=probe.GetProperty("case").GetString()!;
                string tracking=probe.GetProperty("after").GetProperty("tracking").GetString()!;
                Check(tracking==(name=="empty_receive_retains"?"0002":"0000"),"Native background retirement depends on receive context");
                foreach(var repeated in probe.GetProperty("submissions").EnumerateArray())
                {
                    var owner=new AL5SavedPersistentBankCampaign(os);owner.BeginNextSavedVpwRequest();
                    Check(owner.ObserveSavedVpwReply(Convert.FromHexString(repeated.GetProperty("hex").GetString()!),out _)==AL5SavedReplyKind.Unrelated && owner.BytesObserved==0 && owner.HasPendingRequest,"Requeued native background response does not become bank data");
                    owner.TimeoutOrCancel();Blocked(owner);
                }
            }
        }
        Console.WriteLine("PASS native startup scheduling witness through production host: background response cannot advance bank coverage; physical freshness remains false.");
    }

    static void CheckReceiverInitialization(byte[] os,string path)
    {
        using var doc=JsonDocument.Parse(File.ReadAllBytes(path));var root=doc.RootElement;
        Check(root.GetProperty("schema").GetString()=="al5-offline-resident-receiver-init-v1","Exact receiver producer schema");
        foreach(string flag in new[]{"hardware_access","physical_receiver_ready_verified","session_boundary_proven","live_read_enabled","live_upload_enabled","live_execution_enabled","live_write_enabled"})
            Check(!root.GetProperty(flag).GetBoolean(),"Receiver model cannot grant physical/live authority");
        var rows=root.GetProperty("cases").EnumerateArray().ToArray();Check(rows.Length==11,"Complete receiver case corpus");
        foreach(var row in rows.Where(r=>r.GetProperty("case").GetString()=="native_irq_guard"))
        {
            var initial=row.GetProperty("initialization");var state=initial.GetProperty("after");
            Check(state.GetProperty("body").GetString()=="000000000000" && state.GetProperty("tracked_index").GetInt32()==0 && initial.GetProperty("mode23_eligible").GetBoolean(),"Native init retains CRT clearing and admits Mode 23 selection");
            bool consumer=!row.GetProperty("blocked").GetBoolean() && (row.GetProperty("status").GetInt32()==0x40 ||
                (row.GetProperty("status").GetInt32()==0x60 && row.GetProperty("allow60").GetBoolean()));
            Check((row.GetProperty("consumer_entries").GetInt32()>0)==consumer,"Native IRQ guards decide consumer entry");
            Check(row.GetProperty("after").GetProperty("rx_length").GetInt32()==(consumer&&!row.GetProperty("alternate").GetBoolean()?1:0),"Only selected accumulation path takes the byte");
        }
        var initOnly=rows.Single(r=>r.GetProperty("case").GetString()=="communication_init_alone_retains_old_tracking");
        Check(initOnly.GetProperty("after").GetProperty("tracked_index").GetInt32()==75,"Warm communication init is not a freshness fence");
        var joined=rows.Single(r=>r.GetProperty("case").GetString()=="initialized_guarded_receive_to_native_scheduler");
        Check(joined.GetProperty("scheduled").GetProperty("tracked_index").GetInt32()==75 && joined.GetProperty("scheduled").GetProperty("pending").GetString()=="00","Native complete scheduler submitted and tracks reply");
        foreach(var row in rows.Where(r=>r.GetProperty("case").GetString()=="next_read_scheduler_interleaving"))
        {
            bool early=row.GetProperty("early_scheduler").GetBoolean();
            Check(row.GetProperty("native_timer_calls").GetInt32()==(early?100:0) && !row.GetProperty("physical_tick_duration_verified").GetBoolean(),"Native countdown invocation count is not physical timing");
            var c=new AL5SavedPersistentBankCampaign(os);
            Check(c.BeginNextSavedVpwRequest().SequenceEqual(Convert.FromHexString("6d18f02300400001")),"First bank request");
            Check(c.ObserveSavedVpwReply(Convert.FromHexString(row.GetProperty("first_submission_hex").GetString()!),out _)==AL5SavedReplyKind.MatchingLow16Echo && c.BytesObserved==4,"First native dword consumed");
            Check(c.BeginNextSavedVpwRequest().SequenceEqual(Convert.FromHexString("6d18f02300400401")),"Next bank request");
            string duplicate=row.GetProperty("duplicate_submission_hex").GetString()!;
            if(early)
                Check(c.ObserveSavedVpwReply(Convert.FromHexString(duplicate),out _)==AL5SavedReplyKind.Unrelated && c.HasPendingRequest && c.BytesObserved==4,"Native duplicate leaves next request pending");
            else Check(duplicate=="","No early scheduler duplicate in this interleaving");
            Check(c.ObserveSavedVpwReply(Convert.FromHexString(row.GetProperty("next_submission_hex").GetString()!),out _)==AL5SavedReplyKind.MatchingLow16Echo && c.BytesObserved==8,"Actual next native reply satisfies pending request");
            Reject(()=>c.CopyCompleteSavedBanks());c.TimeoutOrCancel();Reject(()=>c.BeginNextSavedVpwRequest());Blocked(c);
        }
        var restored=rows.Single(r=>r.GetProperty("case").GetString()=="persistent_context_restore_preserves_response_clear");
        Check(restored.GetProperty("bytes_restored").GetInt32()==0x9F2 && restored.GetProperty("destination_end_exclusive").GetInt32()==0xFF8B32 &&
            restored.GetProperty("native_crc").GetInt32()==restored.GetProperty("stored_crc").GetInt32(),"Native restored context is bounded and passes CRC");
        Check(restored.GetProperty("restored").GetProperty("body").GetString()=="000000000000" && restored.GetProperty("restored").GetProperty("tracked_index").GetInt32()==0,"Persistent context does not restore the old reply");
        Console.WriteLine("PASS 11 native receiver/init/scheduler/restore outcomes and both actual host reply interleavings; live operations disabled.");
    }
}
