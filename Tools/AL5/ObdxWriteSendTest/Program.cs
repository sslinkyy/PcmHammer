using System.Security.Cryptography;
using System.Text.Json;
using PcmHacking;
using Tests;

// This port has no serial/native binding. Opening/resetting/discarding is an error.
sealed class ScriptPort : IPort
{
    readonly Queue<byte> incoming;
    public List<byte[]> Sends { get; }=new();
    public int EmptyReads { get; private set; }
    public bool ThrowAfterNextSubmission { get; set; }
    public ScriptPort(byte[] bytes) { incoming=new Queue<byte>(bytes); }
    public void Enqueue(byte[] bytes){foreach(byte value in bytes)incoming.Enqueue(value);}
    public Task OpenAsync(PortConfiguration configuration)=>throw new Exception("Test must not open a port");
    public Task ChangeBaudRate(int baudRate)=>throw new Exception("Test must not change baud rate");
    public Task DiscardBuffers()=>throw new Exception("Test must preserve queued replies");
    public Task Send(byte[] buffer)
    {
        Sends.Add((byte[])buffer.Clone());
        if(ThrowAfterNextSubmission){ThrowAfterNextSubmission=false;throw new IOException("Scripted failure after submission, not proof of no transmission");}
        return Task.CompletedTask;
    }
    public Task<int> Receive(byte[] buffer,int offset,int count)
    {
        if(incoming.Count<count)throw new Exception("Test driver requested bytes not present");
        for(int i=0;i<count;i++)buffer[offset+i]=incoming.Dequeue();return Task.FromResult(count);
    }
    public Task<int> GetReceiveQueueSize()
    {
        if(incoming.Count==0){EmptyReads++;throw new TimeoutException("Scripted receive timeout, no hardware");}
        return Task.FromResult(incoming.Count);
    }
    public void SetTimeout(int milliseconds){}
    public void Dispose(){}
}

static class Program
{
    static readonly List<object> cases=new();
    static void Check(bool value,string why){if(!value)throw new Exception(why);}
    static byte[] Frame(byte command,params byte[] payload)
    {
        byte[] bytes=new byte[payload.Length+3];bytes[0]=command;bytes[1]=(byte)payload.Length;payload.CopyTo(bytes,2);
        bytes[^1]=(byte)~(bytes.Take(bytes.Length-1).Sum(v=>(int)v)&255);return bytes;
    }
    static byte[] Packet(int length)=>Enumerable.Range(0,length).Select(i=>(byte)(i^(i>>8))).ToArray();
    static void CheckEnvelope(byte[] wire,byte[] payload)
    {
        int prefix=payload.Length>255?3:2;
        Check(wire[0]==(payload.Length>255?0x11:0x10),"DVI transmit command");
        int size=prefix==3?(wire[1]<<8)|wire[2]:wire[1];
        Check(size==payload.Length && wire.Length==payload.Length+prefix+1,"DVI extent");
        Check(wire.Skip(prefix).Take(size).SequenceEqual(payload),"DVI retains payload bytes");
        Check((wire.Sum(v=>(int)v)&255)==255,"DVI checksum");
    }
    static async Task SendCase(string name,byte[] input,bool expected,int size=522,int queued=0,int? timeouts=null)
    {
        using var port=new ScriptPort(input);using var device=new OBDXProDevice(port,new TestLogger());
        var payload=Packet(size);bool result=await device.SendMessage(new Message(payload));
        Check(result==expected,name+": public SendMessage outcome");
        Check(port.Sends.Count==1,name+": no automatic duplicate transmit");CheckEnvelope(port.Sends[0],payload);
        Check(device.ReceivedMessageCount==queued,name+": queued bus replies retained");
        if(timeouts.HasValue)Check(port.EmptyReads==timeouts.Value,name+": bounded timeout attempts");
        for(int i=0;i<queued;i++)
        {
            var reply=await device.ReceiveMessage();
            Check(reply.GetBytes().SequenceEqual(new byte[]{0x6D,0xF0,0x18,0x76,0,0x73}),name+": bus reply bytes exact");
        }
        cases.Add(new { name,passed=true,payload_bytes=size,result,outgoing_packets=port.Sends.Count,retained_bus_replies=queued });
    }
    static bool Data(byte[] message)=>message.Length>12 && message[3]==0x36 && message[4]==0;
    static bool Is(byte[] message,string hex)=>message.SequenceEqual(Convert.FromHexString(hex));
    static async Task IntegratedWriter(byte[] loader,byte[] fullReference,string templatePath,string calibrationPath,
        bool replyBeforeAdapterAck,bool custom=false,AL5OfflineDispatchKind? failAt=null,bool throwAfterSubmission=false,
        string? loaderFailure=null,bool sendIdentityBeforeLoaderFailure=false,
        AL5OfflineWriteBoundary boundary=AL5OfflineWriteBoundary.CompleteOfflineRehearsal)
    {
        var lines=File.ReadAllLines(templatePath);var calibration=File.ReadAllBytes(calibrationPath);
        var reference=(byte[])fullReference.Clone();var captured=new AL5CapturedProgramImage();
        foreach(string line in lines)
        {var message=Convert.FromHexString(line.Substring(2));if(line[0]=='T' && Data(message))captured.Observe(message);}
        captured.CopyCompleteImage().CopyTo(reference,0x8000);
        if(custom)
        {
            calibration[0x100]^=1;
            Convert.FromHexString(AL5CalibrationInspection.Inspect(calibration).ComputedChecksumHex!).CopyTo(calibration,calibration.Length-4);
        }
        var dispatch=new AL5OfflineWriteDispatcher(loader,calibration,reference,3,boundary:boundary);
        using var port=new ScriptPort(Array.Empty<byte>());using var device=new OBDXProDevice(port,new TestLogger());
        var logger=new TestLogger();var protocol=new Protocol();using var vehicle=new Vehicle(device,protocol,logger,new ToolPresentNotifier(device,protocol,logger),"unused-scripted-path");
        var mockFlash=(byte[])reference.Clone();var prefetched=new HashSet<int>();byte[]? pendingData=null;
        int omitted=0,submitted=0,dataSubmitted=0;bool injected=false;
        for(int index=0;index<lines.Length;index++)
        {
            if(dispatch.State==AL5OfflineDispatchState.BoundaryReached)break;
            string line=lines[index];bool tx=line[0]=='T';byte[] message=Convert.FromHexString(line.Substring(2));
            if(!tx)
            {
                if(!prefetched.Contains(index))port.Enqueue(Frame(0x08,message));
                var reply=await vehicle.ReceiveMessage();Check(reply!=null && reply.GetBytes().SequenceEqual(message),"production Vehicle retains exact AL5 reply bytes");
                dispatch.ObserveSavedReply(reply!.GetBytes());
                if(Is(message,"6cf0187600ee"))Array.Fill(mockFlash,(byte)0xFF,0x8000,0x18000);
                if(Is(message,"6df018760073"))
                {
                    Check(pendingData!=null,"mock program acknowledgement owns decoded wire packet");
                    int address=(pendingData![7]<<16)|(pendingData[8]<<8)|pendingData[9];int count=(pendingData[5]<<8)|pendingData[6];
                    pendingData.AsSpan(10,count).CopyTo(mockFlash.AsSpan(address,count));pendingData=null;
                }
                if(Is(message,"6cf018760086")){mockFlash[0x1FFFE]=0x4A;mockFlash[0x1FFFF]=0xFC;}
                continue;
            }
            AL5OfflineWriteDispatch reservation;
            if(Is(message,"6cfef02800") && dispatch.ProtocolState==AL5CapturedWriteState.Programming)
                reservation=dispatch.PrepareSavedProgrammingBroadcast();
            else if(dispatch.State==AL5OfflineDispatchState.AwaitingReply)
            {
                Check(dispatch.ReplyOwnerDispatch!=null,"raw repeat has an owner");
                if(!custom || !Data(message))Check(dispatch.ReplyOwnerDispatch!.CopyRequest().SequenceEqual(message),"omitted raw repeat bytes match owner");
                omitted++;continue; // Explicit derived-scenario omission, never a silent retry rule.
            }
            else if(dispatch.State==AL5OfflineDispatchState.AwaitingSecurityEvidence)reservation=dispatch.PrepareSavedSecurityEvidence(message);
            else if(dispatch.State==AL5OfflineDispatchState.ChecksumRetryReview)reservation=dispatch.PrepareChecksumRetryForOfflineReview();
            else reservation=dispatch.PrepareNextOfflineDispatch();
            byte[] request=reservation.CopyRequest();
            if(!custom || !Data(message))Check(request.SequenceEqual(message),"constructed request matches selected saved scenario");
            else Check(request.Take(10).SequenceEqual(message.Take(10)),"custom request preserves block extent");
            bool fail=failAt==reservation.Kind;
            bool injectLoaderReply=loaderFailure!=null && reservation.Kind==AL5OfflineDispatchKind.Loader;
            if(fail && throwAfterSubmission)port.ThrowAfterNextSubmission=true;
            else
            {
                if(injectLoaderReply)port.Enqueue(Frame(0x08,Convert.FromHexString(loaderFailure!)));
                bool early=replyBeforeAdapterAck && !fail && !injectLoaderReply && index+1<lines.Length && lines[index+1][0]=='R';
                if(early)
                {
                    port.Enqueue(Frame(0x08,Convert.FromHexString(lines[index+1].Substring(2))));prefetched.Add(index+1);
                }
                port.Enqueue(Frame(request.Length>255?(byte)0x21:(byte)0x20,fail?(byte)1:(byte)0));
            }
            bool accepted;
            try{accepted=await vehicle.SendMessage(new Message(request));}
            catch(IOException){accepted=false;}
            submitted++;if(Data(request))dataSubmitted++;
            Check(port.Sends.Count==submitted,"Vehicle/OBDX submits each dispatch exactly once");
            CheckEnvelope(port.Sends[^1],request);
            // A false result or exception after a send is always outcome-unknown.
            dispatch.CompleteSavedSend(reservation,accepted?AL5OfflineSendOutcome.AdapterAccepted:AL5OfflineSendOutcome.SubmissionUnknown);
            if(fail)
            {
                Check(!accepted && dispatch.StopReason==AL5OfflineDispatchStop.SendSubmissionUnknown,"real send failure maps to uncertainty, not not-submitted");
                Check(Object.ReferenceEquals(dispatch.PendingDispatch,reservation),"failed send reservation retained");
                if(failAt==AL5OfflineDispatchKind.Loader || failAt==AL5OfflineDispatchKind.Erase)Check(dataSubmitted==0,"loader/erase failure prevents data sends");
                injected=true;break;
            }
            Check(accepted,"scripted adapter accepts prepared request");
            if(injectLoaderReply)
            {
                Check(device.ReceivedMessageCount==1,"loader error before adapter ACK retained in production queue");
                var loaderOwner=dispatch.LastLoaderDispatch;
                if(sendIdentityBeforeLoaderFailure)
                {
                    var identity=dispatch.PrepareNextOfflineDispatch();byte[] query=identity.CopyRequest();port.Enqueue(Frame(0x20,0));
                    Check(await vehicle.SendMessage(new Message(query)),"identity query can be submitted while loader error remains queued");
                    submitted++;CheckEnvelope(port.Sends[^1],query);dispatch.CompleteSavedSend(identity,AL5OfflineSendOutcome.AdapterAccepted);
                }
                var queued=await vehicle.ReceiveMessage();Check(queued!=null && queued.GetBytes().SequenceEqual(Convert.FromHexString(loaderFailure!)),"queued loader error bytes exact");
                dispatch.ObserveSavedReply(queued!.GetBytes());
                var expectedStop=loaderFailure=="6cf018768077"?AL5OfflineDispatchStop.LoaderChecksumRejected:
                    loaderFailure=="6cf018760073"?AL5OfflineDispatchStop.UnqualifiedLoaderReply:AL5OfflineDispatchStop.LoaderRejected;
                Check(dispatch.StopReason==expectedStop && Object.ReferenceEquals(loaderOwner,dispatch.LastLoaderDispatch),"loader failure retains loader provenance instead of becoming data ACK");
                Check(dataSubmitted==0 && dispatch.PositiveProgramReplies==0,"loader failure prevents programming");injected=true;break;
            }
            if(Data(request))
            {
                // Reconstruct the mock readback from bytes actually serialized through OBDX.
                byte[] wire=port.Sends[^1];int prefix=wire[0]==0x11?3:2;
                pendingData=wire.Skip(prefix).Take(wire.Length-prefix-1).ToArray();
            }
        }
        if(boundary!=AL5OfflineWriteBoundary.CompleteOfflineRehearsal)
        {
            Check(dispatch.State==AL5OfflineDispatchState.BoundaryReached && dataSubmitted==0,"bounded qualification does not submit a data block");
            var requests=port.Sends.Select(w=>w.Skip(w[0]==0x11?3:2).Take(w.Length-(w[0]==0x11?3:2)-1).ToArray()).ToArray();
            if(boundary==AL5OfflineWriteBoundary.BeforeSecurityKey)Check(!requests.Any(m=>m.Length>=5 && m[3]==0x27 && m[4]==2),"default boundary submits no key");
            if(boundary==AL5OfflineWriteBoundary.BeforeProgrammingEntry)Check(!requests.Any(m=>m.Length>=4 && m[3]==0x34),"entry boundary submits no Mode 34");
            if(boundary==AL5OfflineWriteBoundary.BeforeLoaderUpload)Check(!requests.Any(m=>m.Length==1602),"upload boundary submits no loader");
            if(boundary!=AL5OfflineWriteBoundary.AfterEraseBeforeData)Check(!requests.Any(m=>Is(m,"6c18f036ee")),"pre-erase boundary never submits erase");
        }
        else if(failAt.HasValue || loaderFailure!=null)Check(injected && dispatch.State==AL5OfflineDispatchState.Stopped,"failure scenario stopped at selected phase");
        else
        {
            Check(dispatch.State==AL5OfflineDispatchState.AwaitingReadback && dispatch.PositiveProgramReplies==192,"complete writer/Vehicle/OBDX path reaches readback gate");
            Check(mockFlash.AsSpan(0x8000,calibration.Length).SequenceEqual(calibration),"mock array programmed with selected custom/original bytes");
            Check(dispatch.VerifySavedFullReadback(mockFlash).ExactSavedImageMatch && dispatch.CompleteSavedComparison,"wire-derived mock readback preserves all other bytes");
        }
        Check(!dispatch.LiveWriteEnabled && !dispatch.ReplyFreshnessProven && !dispatch.ReadyToFlash,"integration test never confers physical readiness");
        cases.Add(new { name="integrated_AL5_writer_Vehicle_OBDX",passed=true,template=Path.GetFileName(Path.GetDirectoryName(templatePath)),
            reply_before_adapter_ack=replyBeforeAdapterAck,custom_bin=custom,failure_phase=failAt?.ToString(),throw_after_submission=throwAfterSubmission,
            loader_failure_hex=loaderFailure,identity_query_precedes_loader_failure=sendIdentityBeforeLoaderFailure,
            qualification_boundary=boundary.ToString(),
            submitted,omitted_ambiguous_raw_repeats=omitted,program_replies=dispatch.PositiveProgramReplies,
            stop_reason=dispatch.StopReason.ToString(),readback_is_synthetic_model=true });
    }
    static async Task RejectFullAl5FromPcmWriter(byte[] reference)
    {
        var brokenCalibration=(byte[])reference.Clone();brokenCalibration[0x8100]^=1;
        var brokenBoot=(byte[])reference.Clone();brokenBoot[0]^=1;
        var brokenOs=(byte[])reference.Clone();brokenOs[0x20000]^=1;
        foreach(var pair in new[]{("original",reference),("invalid_calibration",brokenCalibration),("known_OS_only",brokenBoot),("known_boot_only",brokenOs)})
        {
            Check(AL5CalibrationWriteProfile.ContainsKnownAl5FlashCode(pair.Item2),"known AL5 code independent of calibration validity");
            using var port=new ScriptPort(Array.Empty<byte>());using var device=new OBDXProDevice(port,new TestLogger());
            var log=new TestLogger();var protocol=new Protocol();using var vehicle=new Vehicle(device,protocol,log,new ToolPresentNotifier(device,protocol,log),"unused-scripted-path");
            int count=0;
            foreach(WriteType type in Enum.GetValues<WriteType>())
                foreach(PcmType forced in Enum.GetValues<PcmType>())
                {
                    var writer=new WriteManager(log,vehicle,type,(_,_)=>Task.CompletedTask,(_,_)=>Task.FromResult(true),CancellationToken.None);
                    Check(!await writer.Write(pair.Item2,forced),"known full AL5 rejected for every forced type/write mode");count++;
                }
            Check(port.Sends.Count==0 && port.EmptyReads==0,"full AL5 gate precedes all device access");
            cases.Add(new { name="full_AL5_gate_"+pair.Item1,passed=true,rejected_combinations=count,hardware_access=false });
        }
    }
    static async Task<int> Main(string[] args)
    {
        if(args.Length<2 || args[0]!="--receipt" || (args.Length!=2 && (args.Length<7 || args[2]!="--al5-writes" || (args.Length-5)%2!=0)))
            throw new ArgumentException("Use --receipt NEW_JSON [--al5-writes LOADER FULL_REFERENCE TEMPLATE CALIBRATION ...]; no hardware mode exists.");
        using var receiptOutput=new FileStream(args[1],FileMode.CreateNew,FileAccess.Write,FileShare.Read);
        foreach(int length in new[]{5,255,256,522,1602})
            await SendCase("positive_extent_"+length,Frame(length>255?(byte)0x21:(byte)0x20,0),true,length);
        await SendCase("nonzero_ack_status",Frame(0x21,1),false);
        await SendCase("adapter_error_frame",Frame(0x7F,0x11,0x01),false);
        await SendCase("unrelated_device_reply",Frame(0x12,0),false);
        await SendCase("zero_payload_ack",Frame(0x21),false);
        await SendCase("extra_payload_ack",Frame(0x21,0,0),false);
        var corrupt=Frame(0x21,0);corrupt[^1]^=1;await SendCase("bad_ack_checksum",corrupt,false);
        await SendCase("ten_timeouts_no_duplicate_submission",Array.Empty<byte>(),false,timeouts:10);
        byte[] bus=Frame(0x08,0x6D,0xF0,0x18,0x76,0,0x73);
        await SendCase("reply_before_adapter_ack",bus.Concat(Frame(0x21,0)).ToArray(),true,queued:1);
        await SendCase("reply_before_adapter_rejection",bus.Concat(Frame(0x21,2)).ToArray(),false,queued:1);
        await SendCase("queued_reply_then_missing_adapter_ack",bus,false,queued:1,timeouts:10);
        await SendCase("64_bus_frames_reach_read_budget",Enumerable.Range(0,64).SelectMany(_=>bus).ToArray(),false,queued:64);
        if(args.Length>2)
        {
            byte[] loader=File.ReadAllBytes(args[3]),reference=File.ReadAllBytes(args[4]);
            await RejectFullAl5FromPcmWriter(reference);
            for(int index=5;index<args.Length;index+=2)
                foreach(bool before in new[]{false,true})await IntegratedWriter(loader,reference,args[index],args[index+1],before);
            foreach(bool before in new[]{false,true})await IntegratedWriter(loader,reference,args[5],args[6],before,true);
            foreach(var phase in new[]{AL5OfflineDispatchKind.Loader,AL5OfflineDispatchKind.Erase,AL5OfflineDispatchKind.Data,AL5OfflineDispatchKind.Finalization})
                foreach(bool exception in new[]{false,true})await IntegratedWriter(loader,reference,args[5],args[6],false,failAt:phase,throwAfterSubmission:exception);
            foreach(string failure in new[]{"6cf018768077","6cf0187f36800636ff9022","6cf018760073"})
                foreach(bool query in new[]{false,true})await IntegratedWriter(loader,reference,args[5],args[6],false,loaderFailure:failure,sendIdentityBeforeLoaderFailure:query);
            foreach(var boundary in new[]{AL5OfflineWriteBoundary.BeforeSecurityKey,AL5OfflineWriteBoundary.BeforeProgrammingEntry,
                AL5OfflineWriteBoundary.BeforeLoaderUpload,AL5OfflineWriteBoundary.BeforeErase,AL5OfflineWriteBoundary.AfterEraseBeforeData})
                await IntegratedWriter(loader,reference,args[5],args[6],true,boundary:boundary);
        }
        var assembly=typeof(OBDXProDevice).Assembly.Location;
        var receipt=new { schema="al5-obdx-send-contract-v1",passed=true,cases,
            library_path=assembly,library_sha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(assembly))).ToLowerInvariant(),
            hardware_access=false,port_opened=false,live_write_enabled=false,
            limits="Scripted byte transport validates host behavior only. False does not prove no physical submission; true is adapter acceptance, not a controller reply." };
        await JsonSerializer.SerializeAsync(receiptOutput,receipt,new JsonSerializerOptions{WriteIndented=true});
        receiptOutput.Flush(true);
        Console.WriteLine($"PASS {cases.Count} production OBDX send-contract cases; one submission each, exact payloads and queued replies. No port opened.");
        return 0;
    }
}
