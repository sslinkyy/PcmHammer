using System.Security.Cryptography;
using System.Text.Json;
using PcmHacking;
using Tests;

record Frame(bool Tx,byte[] Bytes);

sealed class Peer
{
    readonly Queue<Frame> frames;
    byte[]? pending;
    public byte[] Flash { get; }
    public int OmittedNoReplyRepeats { get; private set; }
    public int OmittedProgrammingBroadcasts { get; private set; }
    public int ExpectedChecksumErrors { get; }
    public int FinalizationsSubmitted { get; private set; }
    public Peer(string[] lines,byte[] reference)
    {
        Flash=(byte[])reference.Clone();frames=new();bool programming=false,replied=true;byte[]? last=null;
        foreach(string line in lines)
        {
            var frame=new Frame(line[0]=='T',Convert.FromHexString(line.Substring(2)));
            if(!frame.Tx && Is(frame.Bytes,"6cf0187600ee"))programming=true;
            if(frame.Tx && Is(frame.Bytes,"6c18f036ff"))programming=false;
            if(programming && frame.Tx && Is(frame.Bytes,"6cfef02800")){OmittedProgrammingBroadcasts++;continue;}
            if(frame.Tx && !replied && last!=null && last.SequenceEqual(frame.Bytes)){OmittedNoReplyRepeats++;continue;}
            frames.Enqueue(frame);
            if(frame.Tx){last=frame.Bytes;replied=false;}else replied=true;
            if(!frame.Tx && Is(frame.Bytes,"6df018760077"))ExpectedChecksumErrors++;
        }
    }
    static bool Is(byte[] a,string hex)=>a.SequenceEqual(Convert.FromHexString(hex));
    public List<byte[]> Submit(byte[] request)
    {
        if(Is(request,"6c18f036ff"))FinalizationsSubmitted++;
        if(frames.Count==0 || !frames.Peek().Tx || !frames.Dequeue().Bytes.SequenceEqual(request))throw new Exception("Executor send differs from derived saved scenario");
        if(request.Length>12 && request[3]==0x36 && request[4]==0)pending=(byte[])request.Clone();
        var replies=new List<byte[]>();
        while(frames.Count>0 && !frames.Peek().Tx)
        {
            byte[] reply=frames.Dequeue().Bytes;replies.Add(reply);
            if(Is(reply,"6cf0187600ee"))Array.Fill(Flash,(byte)0xFF,0x8000,0x18000);
            if(Is(reply,"6df018760073"))
            {
                if(pending==null)throw new Exception("No mock block owns program reply");
                int address=(pending[7]<<16)|(pending[8]<<8)|pending[9],count=(pending[5]<<8)|pending[6];
                pending.AsSpan(10,count).CopyTo(Flash.AsSpan(address,count));pending=null;
            }
            if(Is(reply,"6cf018760086")){Flash[0x1FFFE]=0x4A;Flash[0x1FFFF]=0xFC;}
        }
        return replies;
    }
}

sealed class ScriptPort : IPort
{
    readonly Queue<byte> input=new();readonly Peer peer;readonly bool early;
    public int Sends { get; private set; }
    public ScriptPort(Peer peer,bool early){this.peer=peer;this.early=early;}
    static byte[] Dvi(byte command,byte[] payload)
    {
        var bytes=new byte[payload.Length+3];bytes[0]=command;bytes[1]=(byte)payload.Length;payload.CopyTo(bytes,2);
        bytes[^1]=(byte)~(bytes.Take(bytes.Length-1).Sum(b=>(int)b)&255);return bytes;
    }
    void Add(byte[] bytes){foreach(byte b in bytes)input.Enqueue(b);}
    public Task Send(byte[] wire)
    {
        int prefix=wire[0]==0x11?3:2;int size=prefix==3?(wire[1]<<8)|wire[2]:wire[1];
        if(wire.Length!=prefix+size+1 || (wire.Sum(b=>(int)b)&255)!=255)throw new Exception("Malformed production DVI send");
        var responses=peer.Submit(wire.AsSpan(prefix,size).ToArray());Sends++;
        if(early)foreach(var response in responses)Add(Dvi(8,response));
        Add(Dvi(prefix==3?(byte)0x21:(byte)0x20,new byte[]{0}));
        if(!early)foreach(var response in responses)Add(Dvi(8,response));
        return Task.CompletedTask;
    }
    public Task<int> GetReceiveQueueSize()=>input.Count==0?Task.FromException<int>(new TimeoutException("Scripted silence")):Task.FromResult(input.Count);
    public Task<int> Receive(byte[] bytes,int offset,int count){for(int i=0;i<count;i++)bytes[offset+i]=input.Dequeue();return Task.FromResult(count);}
    public Task OpenAsync(PortConfiguration configuration)=>throw new Exception("No port open allowed");
    public Task ChangeBaudRate(int rate)=>throw new Exception("No baud change allowed");
    public Task DiscardBuffers()=>throw new Exception("No queue discard allowed");
    public void SetTimeout(int milliseconds){}
    public void Dispose(){}
}

sealed class Clock : IAL5WriteExecutionClock { public TimeSpan Now;public TimeSpan Elapsed=>Now; }
sealed class BadWaiter : IAL5WriteExecutionWaiter
{
    public bool Throw;
    public Task<AL5WriteWaitOutcome> WaitAsync(Task operation,TimeSpan remaining,CancellationToken token)
        =>Throw?Task.FromException<AL5WriteWaitOutcome>(new IOException("Scripted wait failure")):Task.FromResult((AL5WriteWaitOutcome)99);
}
sealed class MemoryIo : AL5WriteExecutionIo
{
    readonly Peer peer;readonly Queue<byte[]> replies=new();
    public string Mode="normal";public int Sends,Receives;public Action? OnSend,OnReceive;
    public readonly TaskCompletionSource<AL5OfflineSendOutcome> SendCompletion=new(TaskCreationOptions.RunContinuationsAsynchronously);
    public readonly TaskCompletionSource<byte[]?> ReceiveCompletion=new(TaskCreationOptions.RunContinuationsAsynchronously);
    public MemoryIo(Peer peer){this.peer=peer;}
    public override Task<AL5OfflineSendOutcome> SendAsync(byte[] request)
    {
        Sends++;OnSend?.Invoke();
        if(Mode=="hold_send")return SendCompletion.Task;
        if(Mode=="sync_send_fault")throw new IOException("Scripted synchronous send fault");
        foreach(var reply in peer.Submit(request))replies.Enqueue(reply);
        if(Mode=="async_send_fault")return Task.FromException<AL5OfflineSendOutcome>(new IOException("Scripted post-submission fault"));
        if(Mode=="unknown_send")return Task.FromResult(AL5OfflineSendOutcome.SubmissionUnknown);
        if(Mode=="invalid_send")return Task.FromResult((AL5OfflineSendOutcome)99);
        return Task.FromResult(AL5OfflineSendOutcome.AdapterAccepted);
    }
    public override Task<byte[]?> ReceiveAsync()
    {
        Receives++;OnReceive?.Invoke();
        if(Mode=="hold_receive")return ReceiveCompletion.Task;
        if(Mode=="sync_receive_fault")throw new IOException("Scripted synchronous receive fault");
        if(Mode=="async_receive_fault")return Task.FromException<byte[]?>(new IOException("Scripted asynchronous receive fault"));
        if(Mode=="empty_receive")return Task.FromResult<byte[]?>(null);
        return Task.FromResult<byte[]?>(replies.Count==0?null:replies.Dequeue());
    }
}

static partial class Program
{
    static byte[] loader=Array.Empty<byte>(),original=Array.Empty<byte>(),calibration=Array.Empty<byte>();static string[] lines=Array.Empty<string>();
    static readonly List<object> results=new();
    static void Check(bool value,string why){if(!value)throw new Exception(why);}
    static void Reject(Action action){try{action();}catch(ArgumentException){return;}catch(InvalidOperationException){return;}throw new Exception("Expected rejection");}
    static async Task RejectAsync(Func<Task> action){try{await action();}catch(ArgumentException){return;}catch(InvalidOperationException){return;}throw new Exception("Expected asynchronous rejection");}
    static AL5OfflineWriteTimeBudget Budgets(int send=1000,int reply=1000,int total=60000)=>new(TimeSpan.FromMilliseconds(send),TimeSpan.FromMilliseconds(reply),TimeSpan.FromMilliseconds(reply),TimeSpan.FromMilliseconds(reply),TimeSpan.FromMilliseconds(reply),TimeSpan.FromMilliseconds(total));
    static AL5WriteExecutionSession Session(AL5WriteExecutionIo io,IAL5WriteExecutionClock? clock=null,
        AL5OfflineWriteBoundary boundary=AL5OfflineWriteBoundary.CompleteOfflineRehearsal,AL5OfflineWriteTimeBudget? budgets=null,int retryBudget=3)
        =>new(loader,calibration,original,retryBudget,budgets??Budgets(),boundary,io,clock??new AL5StopwatchExecutionClock(),new AL5TaskWriteExecutionWaiter());
    static async Task<AL5WriteExecutionReport> Drive(AL5WriteExecutionSession session,Peer peer)
    {
        var report=await session.RunUntilReviewAsync(CancellationToken.None);int reviewed=0;
        while(report.Outcome==AL5WriteExecutionOutcome.SecurityReviewRequired || report.Outcome==AL5WriteExecutionOutcome.ChecksumReviewRequired || report.Outcome==AL5WriteExecutionOutcome.PreparationBackupReviewRequired)
        {
            Check(reviewed++<peer.ExpectedChecksumErrors+3,"review budget derives from saved errors plus key/preparation reviews");
            report=report.Outcome==AL5WriteExecutionOutcome.PreparationBackupReviewRequired?
                await session.RecordSavedPreparedBanksAsync(peer.Flash.AsSpan(0x4000,0x4000).ToArray(),CancellationToken.None):report.Outcome==AL5WriteExecutionOutcome.SecurityReviewRequired?
                await session.SubmitSavedSecurityEvidenceAsync(Convert.FromHexString("6c18f02702bc08"),CancellationToken.None):
                await session.ReviewChecksumRetryAsync(CancellationToken.None);
        }
        return report;
    }
    static async Task VehicleCase(bool early,AL5OfflineWriteBoundary boundary,string source)
    {
        var peer=new Peer(lines,original);using var port=new ScriptPort(peer,early);var log=new TestLogger();using var device=new OBDXProDevice(port,log);
        var protocol=new Protocol();using var vehicle=new Vehicle(device,protocol,log,new ToolPresentNotifier(device,protocol,log),"unused-model-directory");
        var session=Session(new AL5VehicleWriteExecutionIo(vehicle),boundary:boundary);var report=await Drive(session,peer);
        if(boundary==AL5OfflineWriteBoundary.CompleteOfflineRehearsal)
        {
            Check(report.Outcome==AL5WriteExecutionOutcome.ReadbackRequired && report.AcknowledgedBlocks==192,"async binding reaches independent readback gate");
            Reject(()=>session.VerifySavedReadback(calibration));
            var matched=session.VerifySavedReadback(peer.Flash);Check(matched.Outcome==AL5WriteExecutionOutcome.SavedComparisonMatched,"wire-derived synthetic readback exact");
        }
        else
        {
            Check(report.Outcome==AL5WriteExecutionOutcome.BoundaryReached && report.AcknowledgedBlocks==(boundary==AL5OfflineWriteBoundary.BeforeFinalization?192:0),"bounded executor retains the selected acknowledged-block progress");
            if(boundary==AL5OfflineWriteBoundary.BeforeFinalization)
            {
                Check(peer.FinalizationsSubmitted==0,"finalization/reset-bound request is not submitted");
                int sends=port.Sends;await session.RunUntilReviewAsync(CancellationToken.None);Check(port.Sends==sends,"terminal pre-finalization boundary cannot resume a send");
                Reject(()=>session.VerifySavedReadback(peer.Flash));
            }
        }
        Check(!report.PhysicalResetVerified && !report.PostFinalizationReadbackWindowVerified && !report.PhysicalDeadlinesQualified,"Saved progress cannot qualify physical reset, readback timing or deadlines");
        Check(report.SavedFinalizationReplyObserved==(boundary==AL5OfflineWriteBoundary.CompleteOfflineRehearsal) && report.SavedCleanupObserved==(boundary==AL5OfflineWriteBoundary.CompleteOfflineRehearsal),"Separate saved finalization and cleanup evidence survives async reporting");
        Check(port.Sends==report.SendCalls && !report.ReadyToFlash && !report.LiveWriteEnabled,"one call per owned dispatch; no live readiness");
        results.Add(new { name="production_Vehicle_binding",passed=true,source,early,boundary=boundary.ToString(),report.SendCalls,report.AcknowledgedBlocks,report.SavedFinalizationReplyObserved,report.SavedCleanupObserved,
            report.PhysicalResetVerified,report.PostFinalizationReadbackWindowVerified,report.PhysicalDeadlinesQualified,
            peer.OmittedNoReplyRepeats,peer.OmittedProgrammingBroadcasts,readback_is_synthetic=true });
    }
    static async Task FaultCases()
    {
        foreach(string mode in new[]{"sync_send_fault","async_send_fault","unknown_send","invalid_send","sync_receive_fault","async_receive_fault","empty_receive"})
        {
            var io=new MemoryIo(new Peer(lines,original)){Mode=mode};var session=Session(io);var report=await session.RunUntilReviewAsync(CancellationToken.None);
            Check(report.Outcome==AL5WriteExecutionOutcome.Stopped && io.Sends==1,"failure stops before another send");
            Check(report.StopReason==(mode.EndsWith("receive_fault")?AL5OfflineDispatchStop.ReceiveFault:mode=="empty_receive"?AL5OfflineDispatchStop.Timeout:AL5OfflineDispatchStop.SendSubmissionUnknown),"failure reason retained");
            Check(mode.Contains("send")?session.PendingDispatch!=null:session.ReplyOwner!=null,"unresolved operation metadata retained");
            results.Add(new { name=mode,passed=true,report.StopReason });
        }
        foreach(bool receive in new[]{false,true})
            foreach(bool cancel in new[]{false,true})
            {
                var io=new MemoryIo(new Peer(lines,original)){Mode=receive?"hold_receive":"hold_send"};var session=Session(io,budgets:Budgets(cancel?1000:20,cancel?1000:20,5000));
                using var cancellation=new CancellationTokenSource();var run=session.RunUntilReviewAsync(cancellation.Token);
                if(cancel)cancellation.Cancel();
                var report=await run;
                Check(report.Outcome==AL5WriteExecutionOutcome.Stopped && report.TransportCallOutstanding,"wait stop retains in-flight transport ownership");
                Check(report.StopReason==(cancel?AL5OfflineDispatchStop.Cancelled:AL5OfflineDispatchStop.Timeout),"timeout and cancellation distinct");
                if(receive)io.ReceiveCompletion.SetResult(Convert.FromHexString("6cf0187c550a0012"));
                else io.SendCompletion.SetException(new IOException("Late fault remains observable"));
                await session.ObserveOutstandingTransportCompletionAsync();
                var stopped=await session.RunUntilReviewAsync(CancellationToken.None);
                Check(stopped.Outcome==AL5WriteExecutionOutcome.Stopped && !stopped.TransportCallOutstanding && io.Sends==1,"late completion cannot resume or retransmit");
                Reject(()=>Session(io));Check(!receive || session.ReplyOwner!=null,"late reply owner remains retained");
                results.Add(new { name="owned_pending_call",passed=true,receive,cancel,stopped.StopReason });
            }
        {
            var io=new MemoryIo(new Peer(lines,original)){Mode="hold_send"};var session=Session(io,budgets:Budgets(1000,1000,5000));
            using var cancellation=new CancellationTokenSource();var running=session.RunUntilReviewAsync(cancellation.Token);
            bool rejected=false;try{await session.RunUntilReviewAsync(CancellationToken.None);}catch(InvalidOperationException){rejected=true;}
            Check(rejected,"second execution call cannot share the session");cancellation.Cancel();await running;
            io.SendCompletion.SetResult(AL5OfflineSendOutcome.AdapterAccepted);await session.ObserveOutstandingTransportCompletionAsync();
            results.Add(new { name="overlapping_run_rejected",passed=true });
        }
        {
            var io=new MemoryIo(new Peer(lines,original));using var cancellation=new CancellationTokenSource();cancellation.Cancel();
            var report=await Session(io).RunUntilReviewAsync(cancellation.Token);Check(io.Sends==0 && report.StopReason==AL5OfflineDispatchStop.Cancelled,"pre-cancel sends nothing");
            results.Add(new { name="pre_cancel",passed=true });
        }
    }
    static async Task QualificationChecks()
    {
        var disabled=await AL5CalibrationWriteExecutor.WriteUnchangedCalibrationAsync(null!,null!,null!,null!,null!,CancellationToken.None);
        Check(disabled.Outcome==AL5WriteExecutionOutcome.LiveDisabled && disabled.SendCalls==0 && disabled.ReceiveCalls==0,"public live entry refuses before dependency/input access");
        var manager=new WriteManager(new TestLogger(),null!,WriteType.Calibration,null!,null!,CancellationToken.None);
        disabled=await manager.WriteAL5UnchangedCalibrationAsync(null!,null!,null!,null!);
        Check(disabled.Outcome==AL5WriteExecutionOutcome.LiveDisabled && disabled.SendCalls==0 && disabled.ReceiveCalls==0,"WriteManager uses the same unconditional AL5 live gate");
        var changed=(byte[])calibration.Clone();changed[0x100]^=1;
        Convert.FromHexString(AL5CalibrationInspection.Inspect(changed).ComputedChecksumHex!).CopyTo(changed,changed.Length-4);
        var unused=new MemoryIo(new Peer(lines,original));Reject(()=>new AL5WriteExecutionSession(loader,changed,original,3,Budgets(),AL5OfflineWriteBoundary.CompleteOfflineRehearsal,unused,new Clock(),new AL5TaskWriteExecutionWaiter()));
        Check(unused.Sends==0 && unused.Receives==0,"checksum-correct custom calibration cannot enter first-write executor");
        var clock=new Clock{Now=TimeSpan.FromSeconds(100)};var peer=new Peer(lines,original);var io=new MemoryIo(peer);
        io.OnSend=()=>clock.Now+=TimeSpan.FromMilliseconds(20);io.OnReceive=()=>clock.Now+=TimeSpan.FromMilliseconds(5);
        var timed=Session(io,clock,budgets:Budgets(30,10,10000));var report=await Drive(timed,peer);
        Check(report.Outcome==AL5WriteExecutionOutcome.ReadbackRequired,"reply deadline begins at actual send completion; clock origin is session-relative");
        var corrupt=(byte[])peer.Flash.Clone();corrupt[0x6000]^=1;
        Check(timed.VerifySavedReadback(corrupt).StopReason==AL5OfflineDispatchStop.VerificationFailed,"preservation mismatch cannot pass unchanged write");
        clock=new Clock();io=new MemoryIo(new Peer(lines,original));io.OnSend=()=>clock.Now=TimeSpan.FromTicks(-1);
        report=await Session(io,clock).RunUntilReviewAsync(CancellationToken.None);
        Check(report.StopReason==AL5OfflineDispatchStop.InvalidClock && io.Sends==1,"regressing clock stops without another send");
        results.Add(new { name="qualification_and_clock_guards",passed=true });
    }
    static async Task PreparationEpochs()
    {
        foreach(bool corruptAfterWrite in new[]{false,true})
        {
            var peer=new Peer(lines,original);var io=new MemoryIo(peer);var session=Session(io);
            var report=await session.RunUntilReviewAsync(CancellationToken.None);
            Check(report.Outcome==AL5WriteExecutionOutcome.SecurityReviewRequired,"no key default");
            report=await session.SubmitSavedSecurityEvidenceAsync(Convert.FromHexString("6c18f02702bc08"),CancellationToken.None);
            Check(report.Outcome==AL5WriteExecutionOutcome.PreparationBackupReviewRequired && report.AcknowledgedBlocks==0,"no erase before prepared backup review");
            int sends=io.Sends;string? originalHash=report.OriginalReferenceSha256;
            report=await session.RunUntilReviewAsync(CancellationToken.None);Check(io.Sends==sends,"plain resume cannot bypass backup gate");
            await RejectAsync(()=>session.RecordSavedPreparedBanksAsync(new byte[10],CancellationToken.None));Check(io.Sends==sends,"partial prepared banks rejected before erase");
            // Explicit model-only preparation change; it is not physical storage evidence.
            peer.Flash[0x6000]^=1;byte[] prepared=peer.Flash.AsSpan(0x4000,0x4000).ToArray();string hash=Convert.ToHexString(SHA256.HashData(prepared)).ToLowerInvariant();
            report=await session.RecordSavedPreparedBanksAsync(prepared,CancellationToken.None);prepared[0]^=1;
            while(report.Outcome==AL5WriteExecutionOutcome.ChecksumReviewRequired)report=await session.ReviewChecksumRetryAsync(CancellationToken.None);
            Check(report.Outcome==AL5WriteExecutionOutcome.ReadbackRequired,"unchanged qualification reaches saved readback");
            Check(report.OriginalReferenceSha256==originalHash && report.PreparedBanksSha256==hash && report.SavedPreparationChangedBytes==1,"original and prepared epochs remain distinct and immutable");
            await RejectAsync(()=>session.RecordSavedPreparedBanksAsync(new byte[0x4000],CancellationToken.None));
            if(corruptAfterWrite)peer.Flash[0x6001]^=1;
            report=session.VerifySavedReadback(peer.Flash);
            Check(report.Outcome==(corruptAfterWrite?AL5WriteExecutionOutcome.Stopped:AL5WriteExecutionOutcome.SavedComparisonMatched),"prepared-bank preservation comparison detects later changes");
            Check(!report.PhysicalBackupVerified && !report.RecoveryVerified && !report.ReadyToFlash,"saved comparison is not physical qualification");
            results.Add(new { name="original_and_prepared_epochs",passed=true,corruptAfterWrite,report.SavedPreparationChangedBytes });
        }
    }
    static async Task CompletionRaces()
    {
        {
            var clock=new Clock();var io=new MemoryIo(new Peer(lines,original));io.OnSend=()=>clock.Now+=TimeSpan.FromMilliseconds(40);
            var session=Session(io,clock,budgets:Budgets(30,100,5000));var report=await session.RunUntilReviewAsync(CancellationToken.None);
            Check(report.StopReason==AL5OfflineDispatchStop.Timeout && session.PendingDispatch!=null && !report.TransportCallOutstanding,"completed late send is not applied past its deadline");
            Check(io.Sends==1 && io.Receives==0,"late send completion causes no follow-up");results.Add(new { name="completed_after_deadline",passed=true });
        }
        foreach(bool receive in new[]{false,true})
        {
            using var cancel=new CancellationTokenSource();var io=new MemoryIo(new Peer(lines,original));
            if(receive)io.OnReceive=()=>cancel.Cancel();else io.OnSend=()=>cancel.Cancel();
            var session=Session(io);var report=await session.RunUntilReviewAsync(cancel.Token);
            Check(report.StopReason==AL5OfflineDispatchStop.Cancelled && session.ReplyOwner!=null,"racing successful operation retains unresolved reply ownership");
            Check(io.Sends==1 && io.Receives==(receive?1:0),"racing cancel prevents the next command");
            results.Add(new { name="completed_operation_cancel_race",passed=true,receive });
        }
        foreach(bool throws in new[]{false,true})
        {
            var io=new MemoryIo(new Peer(lines,original)){Mode="hold_send"};var session=new AL5WriteExecutionSession(loader,calibration,original,3,Budgets(),
                AL5OfflineWriteBoundary.CompleteOfflineRehearsal,io,new Clock(),new BadWaiter{Throw=throws});
            var report=await session.RunUntilReviewAsync(CancellationToken.None);
            Check(report.StopReason==AL5OfflineDispatchStop.ExecutionWaitFault && report.TransportCallOutstanding,"wait failure retains ownership");
            io.SendCompletion.SetResult(AL5OfflineSendOutcome.AdapterAccepted);await session.ObserveOutstandingTransportCompletionAsync();
            Check(session.Snapshot().StopReason==AL5OfflineDispatchStop.ExecutionWaitFault && io.Sends==1,"settled wait failure never resumes");
            results.Add(new { name="wait_contract_failure",passed=true,throws });
        }
    }
    static async Task Main(string[] args)
    {
        string? journalReport=null;
        if(args.Length>3 && args[2]=="--journal-report")
        {journalReport=args[3];args=args.Take(2).Concat(args.Skip(4)).ToArray();}
        if(args.Length<6 || args[0]!="--receipt" || (args.Length-4)%2!=0)throw new ArgumentException("--receipt NEW_JSON LOADER FULL_REFERENCE TEMPLATE CALIBRATION ...; scripted I/O only.");
        using var receipt=new FileStream(args[1],FileMode.CreateNew,FileAccess.Write,FileShare.Read);
        loader=File.ReadAllBytes(args[2]);var baseline=File.ReadAllBytes(args[3]);
        for(int index=4;index<args.Length;index+=2)
        {
            lines=File.ReadAllLines(args[index]);calibration=File.ReadAllBytes(args[index+1]);original=(byte[])baseline.Clone();
            var image=new AL5CapturedProgramImage();foreach(string line in lines){var m=Convert.FromHexString(line.Substring(2));if(line[0]=='T' && m.Length>12 && m[3]==0x36 && m[4]==0)image.Observe(m);}
            image.CopyCompleteImage().CopyTo(original,0x8000);
            foreach(bool early in new[]{false,true})await VehicleCase(early,AL5OfflineWriteBoundary.CompleteOfflineRehearsal,Path.GetFileName(Path.GetDirectoryName(args[index]))!);
            if(index==4)
            {
                foreach(var boundary in new[]{AL5OfflineWriteBoundary.BeforeSecurityKey,AL5OfflineWriteBoundary.BeforeProgrammingEntry,AL5OfflineWriteBoundary.BeforeLoaderUpload,AL5OfflineWriteBoundary.BeforeErase,AL5OfflineWriteBoundary.AfterEraseBeforeData,AL5OfflineWriteBoundary.BeforeFinalization})
                    await VehicleCase(true,boundary,"first_saved_template");
                await VehicleCase(false,AL5OfflineWriteBoundary.BeforeFinalization,"first_saved_template");
                await FaultCases();await QualificationChecks();await PreparationEpochs();await CompletionRaces();await SecurityAndBackupCases();await FinalizerTimingCases();
                if(journalReport!=null)JournalCases(journalReport,baseline);
            }
        }
        var library=typeof(AL5CalibrationWriteExecutor).Assembly.Location;
        await JsonSerializer.SerializeAsync(receipt,new { schema="al5-execution-binding-tests-v1",passed=true,hardware_access=false,live_write_enabled=false,
            library_sha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(library))).ToLowerInvariant(),cases=results,
            limits="Saved stimuli and modeled flash only. Public live entry is unconditionally disabled; no physical programming/recovery was tested." },new JsonSerializerOptions{WriteIndented=true});
        receipt.Flush(true);Console.WriteLine($"PASS {results.Count} asynchronous execution-binding cases; public live entry blocked, scripted port only.");
    }
}
