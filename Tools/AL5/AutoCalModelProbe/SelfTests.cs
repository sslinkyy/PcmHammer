// SPDX-License-Identifier: GPL-3.0-only
using System.Text;
using System.Text.Json;
using PcmHacking;

namespace AutoCalModelProbe;

internal static class SelfTests
{
    private static readonly byte[] Reply = Convert.FromHexString("015201820000000000000500414356320026b419");
    private static int assertions;
    private static void Require(bool value, string message)
    {
        assertions++;
        if (!value) throw new Exception(message);
    }
    private static void Reject<T>(Action action, string message) where T : Exception
    {
        assertions++;
        try { action(); }
        catch (T) { return; }
        throw new Exception(message);
    }

    private sealed class Fake : IModelDevice, IRetainedResources
    {
        internal List<string> Calls = [];
        internal Queue<byte[]> Chunks = new(new[] { Reply.ToArray() });
        internal Queue<CountResult> Queues = new(new[] { new CountResult(0, 0), new CountResult(0, 0) });
        internal CountResult Written = new(0, 14);
        internal OpenResult Opened = new(0, true);
        internal uint TimeoutStatus, CloseStatus, ReadStatus;
        internal uint? ReportedRead;
        internal Action<string>? Before;
        internal List<Identity> Identities = [new(0, 0, 0, FixedModel.DeviceType,
            FixedModel.Identifier, 35, Convert.ToHexString(Encoding.ASCII.GetBytes(FixedModel.Serial)),
            "", true, "", false)];
        public bool OwnsHandle { get; private set; }
        public bool OwnsLibraryOrPin { get; private set; } = true;
        public int CloseAttempts { get; private set; }
        internal int ReleaseAttempts;
        internal int FailedReleases;
        internal bool ThrowRelease;
        private void Step(string name) { Calls.Add(name); Before?.Invoke(name); }
        public Enumeration Enumerate() { Step("enumerate"); return new(0, (uint)Identities.Count, Identities); }
        public OpenResult OpenExactSerial()
        {
            Step("open");
            if (Opened.Status == 0 && Opened.HandleReturned) OwnsHandle = true;
            return Opened;
        }
        public uint SetFixedTimeouts() { Step("timeouts"); return TimeoutStatus; }
        public CountResult GetQueueStatus() { Step("queue"); return Queues.Dequeue(); }
        public CountResult WriteFixedModelQuery() { Step("write"); return Written; }
        public ReadResult Read(int count)
        {
            Step("read");
            byte[] data = Chunks.Count == 0 ? [] : Chunks.Dequeue();
            return new(ReadStatus, ReportedRead ?? (uint)data.Length, data);
        }
        public uint CloseOwnedHandle()
        {
            CloseAttempts++;
            Step("close");
            if (CloseStatus == 0) OwnsHandle = false;
            return CloseStatus;
        }
        public bool TryReleaseLibrary(out string? error)
        {
            ReleaseAttempts++;
            if (OwnsHandle) throw new Exception("Test forbids unload while device handle is owned.");
            if (ThrowRelease) { ThrowRelease = false; throw new IOException("synthetic release exception"); }
            if (ReleaseAttempts <= FailedReleases) { error = "synthetic release failure"; return false; }
            OwnsLibraryOrPin = false;
            error = null;
            return true;
        }
    }

    private static ModelResult Run(Fake fake, Action<ProbeEvent>? emit = null,
        Func<double>? seconds = null, CancellationToken cancellation = default)
        => ModelQuery.Run(fake, new ProbeBudget(seconds ?? (() => 0), cancellation), emit ?? (_ => { }));

    internal static int Run()
    {
        CheckCli();
        CheckSuccessAndPartialReads();
        CheckWritesAndIdentityGates();
        CheckReplyFailures();
        CheckCancellationAndDeadline();
        CheckTelemetryAndCleanup();
        CheckEvidenceFiles();
        Console.WriteLine($"AutoCal fixed-model offline checks passed: {assertions} assertions. No DLL loads or device calls.");
        return 0;
    }

    private static void CheckCli()
    {
        Require(Program.Parse([]).Mode == "plan", "Default must be offline plan");
        Require(Program.Parse(["--plan"]).Mode == "plan", "Explicit offline plan");
        Require(Program.Parse(["--self-test"]).Mode == "self-test", "Explicit offline tests");
        Require(Program.Parse(["--query-model", "--obd-disconnected", "--receipt", "new.json"]).Mode == "query-model", "Only explicit disconnected fixed query");
        foreach (string[] bad in new[] { new[] { "--query-model" }, new[] { "--query-model", "--receipt", "x" },
            new[] { "--plan", "--query-model" }, new[] { "--send", "0154" },
            new[] { "--query-model", "--obd-disconnected", "--receipt", "x", "--reset" } })
            Reject<ArgumentException>(() => Program.Parse(bad), "Reject unreviewed CLI surface");
        Require(Convert.ToHexString(FixedModel.Query()) == "0154018207000000000000008177", "Fixed literal request");
        byte[] query = FixedModel.Query(); query[0] = 99;
        Require(FixedModel.Query()[0] == 1, "Request bytes cannot be changed by a caller");
    }

    private static void CheckSuccessAndPartialReads()
    {
        Fake fake = new();
        ModelResult result = Run(fake);
        Require(result.Successful && result.ModelVerified && result.OwnedHandleClosed, "Successful fixed query");
        Require(string.Join(',', fake.Calls) == "enumerate,open,timeouts,queue,write,read,queue,close", "Exact permitted call order");
        Require(result.ApplicationWriteAttempts == 1 && result.ReadCalls == 1, "One write and one complete read");
        Require(result.ReceivedHex == Convert.ToHexString(Reply), "Exact D2XX bytes retained");
        fake = new();
        fake.Chunks = new Queue<byte[]>(new[] { Reply[..1], Reply[1..10], Array.Empty<byte>(), Reply[10..] });
        result = Run(fake);
        Require(result.Successful && result.ReadCalls == 4, "Partial and empty reads assemble within fixed bound");
        fake = new();
        fake.Chunks = new Queue<byte[]>(new[] { Convert.FromHexString("0152018200000100000005004143563200224819") });
        Require(Run(fake).Successful, "Observed metadata variation accepted");
        fake = new();
        byte[] unknownTail = Reply.ToArray(); unknownTail[^1] = 0xA5;
        fake.Chunks = new Queue<byte[]>(new[] { unknownTail });
        Require(Run(fake).Successful, "Unknown RX tail retained without invented ACK semantics");
    }

    private static void CheckWritesAndIdentityGates()
    {
        foreach (CountResult written in new[] { new CountResult(0, 0), new CountResult(0, 7), new CountResult(5, 14), new CountResult(0, 15) })
        {
            Fake fake = new() { Written = written };
            ModelResult result = Run(fake);
            Require(!result.Successful && result.ApplicationWriteAttempts == 1 && !fake.Calls.Contains("read"), "Partial/error write never retried or followed by read");
            Require(fake.CloseAttempts == 1 && !fake.OwnsHandle, "Failed write still closes exactly once");
        }
        foreach (CountResult before in new[] { new CountResult(0, 1), new CountResult(5, 0) })
        {
            Fake fake = new() { Queues = new Queue<CountResult>(new[] { before }) };
            Require(Run(fake).ApplicationWriteAttempts == 0 && fake.CloseAttempts == 1, "Nonempty/failed queue prevents send");
        }
        Identity good = new Fake().Identities[0];
        foreach (Identity bad in new[] { good with { Flags = 1 }, good with { Identifier = 0 },
            good with { Type = 3 }, good with { Status = 1 }, good with { SerialHex = "41" }, good with { SerialTerminated = false } })
        {
            Fake fake = new() { Identities = [bad] };
            Require(!Run(fake).Successful && fake.Calls.SequenceEqual(new[] { "enumerate" }), "Unknown/busy identity prevents open");
        }
        foreach (List<Identity> identities in new[] { new List<Identity>(), new List<Identity> { good, good } })
        {
            Fake fake = new() { Identities = identities };
            Require(Run(fake).ApplicationWriteAttempts == 0 && !fake.Calls.Contains("open"), "Missing/duplicate identity rejected");
        }
        foreach (OpenResult opened in new[] { new OpenResult(5, false), new OpenResult(0, false) })
        {
            Fake fake = new() { Opened = opened };
            Require(!Run(fake).Successful && fake.CloseAttempts == 0, "Failed/null open is never closed as owned");
        }
        Fake timeout = new() { TimeoutStatus = 5 };
        Require(Run(timeout).ApplicationWriteAttempts == 0 && timeout.CloseAttempts == 1, "Timeout setter failure prevents query");
    }

    private static void CheckReplyFailures()
    {
        Fake fake = new() { Chunks = new Queue<byte[]>(new[] { Reply[..3] }) };
        ModelResult partial = Run(fake);
        Require(partial.ReadCalls == 8 && partial.ReceivedHex == Convert.ToHexString(Reply[..3]), "Incomplete read bounded and preserved");
        Require(!partial.Successful && partial.OwnedHandleClosed, "Incomplete response closes");
        foreach (int offset in new[] { 0, 2, 10, 12, 17 })
        {
            byte[] bad = Reply.ToArray(); bad[offset] ^= 1;
            fake = new() { Chunks = new Queue<byte[]>(new[] { bad }) };
            ModelResult result = Run(fake);
            Require(!result.Successful && result.ReceivedHex == Convert.ToHexString(bad), "Invalid framing/route/model/CRC bytes preserved");
            Require(result.OwnedHandleClosed, "Invalid response closes");
        }
        // Independent Python checksum producer generated these synthetic goldens.
        // Valid CRCs make these distinct route/model checks, not checksum failures.
        foreach ((string literal, string payload) in new[] {
            ("015202820000000000000500414356320065B519", "4143563200"),
            ("015201820000000000000500465356320097B419", "4653563200") })
        {
            byte[] validCrcWrongIdentity = Convert.FromHexString(literal);
            AutoCalHostFrame frame = AutoCalHostFrame.ParseLongHeader(AutoCalHostDirection.DeviceToHost, validCrcWrongIdentity);
            Require(frame.CrcMatches, "Wrong route/model golden has independently valid outer CRC");
            fake = new() { Chunks = new Queue<byte[]>(new[] { validCrcWrongIdentity }) };
            ModelResult result = Run(fake);
            Require(!result.Successful && !result.ModelVerified, "Valid CRC cannot authorize wrong route or model");
            Require(result.ReceivedHex == literal && Convert.ToHexString(frame.Payload) == payload,
                "Rejected valid-CRC response retains its exact bytes and payload");
            Require(result.OwnedHandleClosed && result.ReadCalls == 1, "Identity rejection closes without query retry");
        }
        fake = new() { ReadStatus = 5, Chunks = new Queue<byte[]>(new[] { Reply[..4] }) };
        Require(Run(fake).ReceivedHex == Convert.ToHexString(Reply[..4]) && fake.CloseAttempts == 1, "Failed read retains partial bytes");
        fake = new() { ReportedRead = 21 };
        Require(!Run(fake).Successful && fake.CloseAttempts == 1, "Invalid native read count rejected");
        fake = new() { Queues = new Queue<CountResult>(new[] { new CountResult(0, 0), new CountResult(0, 2) }) };
        Require(!Run(fake).Successful && fake.Calls.Count(item => item == "read") == 1, "Extra queue bytes fail without draining");
    }

    private static void CheckCancellationAndDeadline()
    {
        foreach (string delayed in new[] { "open", "queue" })
        {
            double now = 0;
            Fake fake = new() { Before = stage => { if (stage == delayed) now = 21; } };
            ModelResult result = Run(fake, seconds: () => now);
            Require(result.ApplicationWriteAttempts == 0 && fake.CloseAttempts == 1, "Late native result cannot trigger a new query");
        }
        using CancellationTokenSource cancellation = new();
        Fake canceled = new() { Before = stage => { if (stage == "queue") cancellation.Cancel(); } };
        ModelResult canceledResult = Run(canceled, cancellation: cancellation.Token);
        Require(canceledResult.ApplicationWriteAttempts == 0 && canceled.CloseAttempts == 1, "Cancellation prevents send and allows cleanup");
        using CancellationTokenSource preCanceled = new(); preCanceled.Cancel();
        Fake unopened = new();
        Require(!Run(unopened, cancellation: preCanceled.Token).Successful && unopened.Calls.Count == 0, "Pre-cancellation performs no native work");
    }

    private static void CheckTelemetryAndCleanup()
    {
        foreach (string failingStage in new[] { "open_result", "close_started", "close_result" })
        {
            Fake fake = new();
            ModelResult result = Run(fake, item => { if (item.Stage == failingStage) throw new IOException("synthetic telemetry failure"); });
            Require(!fake.OwnsHandle && fake.CloseAttempts == 1, "Telemetry cannot skip owned close");
            Require(!result.Successful && result.TelemetryErrors.Count == 1, "Telemetry failure remains visible");
            if (failingStage == "open_result") Require(result.ApplicationWriteAttempts == 0, "No query after open telemetry failure");
        }
        Fake failedClose = new() { CloseStatus = 5 };
        ModelResult pending = Run(failedClose);
        Require(pending.CleanupPending && failedClose.OwnsHandle && failedClose.OwnsLibraryOrPin, "Failed close retains all ownership");
        Require(failedClose.CloseAttempts == 1 && failedClose.ReleaseAttempts == 0, "No automatic close retry or unload");
        int inputs = 0, eofs = 0;
        Program.RetainAndClean(failedClose, _ => throw new IOException("cleanup journal failure"), () =>
        {
            inputs++;
            Require(failedClose.ReleaseAttempts == 0 && failedClose.CloseAttempts == 1, "Cleanup waits without releasing or retrying");
            if (inputs == 1) return "invalid";
            if (inputs == 2) return null;
            failedClose.CloseStatus = 0;
            return "retry-close";
        }, () => eofs++);
        Require(eofs == 1 && failedClose.CloseAttempts == 2 && failedClose.ReleaseAttempts == 1, "Only explicit close command permits retry and release");
        Require(!failedClose.OwnsHandle && !failedClose.OwnsLibraryOrPin, "Manual close releases resources in order");

        foreach (bool throws in new[] { false, true })
        {
            Fake library = new() { FailedReleases = 1, ThrowRelease = throws };
            int count = 0;
            Program.RetainAndClean(library, _ => { }, () =>
            {
                Require(library.ReleaseAttempts == 1, "Library failure does not retry on invalid input");
                return ++count == 1 ? "invalid" : "retry-close";
            });
            Require(library.ReleaseAttempts == 2 && !library.OwnsLibraryOrPin, "Library failure/exception retained until explicit retry");
        }
        Fake exceptional = new() { Before = stage => { if (stage == "timeouts") throw new IOException("synthetic native failure"); } };
        Require(Run(exceptional).OwnedHandleClosed && exceptional.CloseAttempts == 1, "Native exception after open still closes");
    }

    private static void CheckEvidenceFiles()
    {
        string directory = Path.Combine(AppContext.BaseDirectory, "self-test-evidence", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "receipt.json");
        using (EvidenceWriter writer = new(path, new { Offline = true }))
        {
            writer.Append(new ProbeEvent("synthetic", new { Value = 1 }));
            string hash = writer.SealJournal();
            Require(hash == D2xxNative.HashFile(writer.JournalPath), "Sealed journal hashes with Windows sharing rules");
            writer.Finish(new { Successful = true, OfflineSynthetic = true, JournalSha256 = hash });
            Reject<IOException>(() => { using EvidenceWriter duplicate = new(path, new { }); }, "Existing receipt cannot be overwritten");
            Reject<InvalidOperationException>(() => writer.Append(new ProbeEvent("late")), "Sealed journal cannot change");
            Reject<InvalidOperationException>(() => writer.Finish(new { }), "Receipt cannot be rewritten");
        }
        using JsonDocument receipt = JsonDocument.Parse(File.ReadAllText(path));
        Require(receipt.RootElement.GetProperty("OfflineSynthetic").GetBoolean(), "Real receipt path completed offline");
        // Keep these tiny synthetic artifacts for inspection; never erase evidence.
        Console.WriteLine($"Synthetic receipt evidence: {path}");
    }
}
