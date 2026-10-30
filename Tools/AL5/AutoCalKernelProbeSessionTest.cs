// SPDX-License-Identifier: GPL-3.0-only
// Actual Vehicle/Device/Channel with a byte-level fake AutoCal+ECU. No native
// library is linked, no adapter opened, and no hardware operation performed.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using PcmHacking;

internal static class AutoCalKernelProbeSessionTest
{
    static int assertions;
    static readonly List<string> passed = new();
    static readonly List<object> failed = new();
    static byte[] kernel = Array.Empty<byte>();
    static byte[] Hex(string value) => Convert.FromHexString(value);
    static void Require(bool value, string text) { assertions++; if (!value) throw new Exception(text); }
    static async Task Case(string name, Func<Task> action)
    {
        try { await action(); passed.Add(name); }
        catch (Exception e) { failed.Add(new { name, error = e.ToString() }); }
    }
    public static async Task<int> Main(string[] args)
    {
        kernel = File.ReadAllBytes(args.Length == 1 ? args[0] : AutoCalKernelProbePolicy.DefaultKernelPath);
        await Case("production Vehicle RAM upload, exact version and successful exit", Success);
        await Case("incorrect initial identity sends no preparation or cleanup", WrongIdentity);
        await Case("lockout cannot become unlocked or trigger retry", Lockout);
        await Case("rejected key cannot lead to upload or repeat unlock", RejectedKey);
        await Case("already-unlocked zero seed skips the key exchange", UnlockedSeed);
        await Case("bad RAM-copy acknowledgement blocks execute", BadCopyAcknowledgement);
        await Case("wrong running kernel blocks exit and ordinary query", WrongKernel);
        await Case("cancelled execute retains uncertain state without retry or cleanup", CancelledExecute);
        await Case("shared upload retry cannot retransmit an unacknowledged execute", MissingExecuteAcknowledgement);
        await Case("post-exit wrong identity is a failure", WrongFinalIdentity);
        await Case("stale correlated bytes remain visible across queue-clear request", StaleCopyAcknowledgement);
        await Case("pending startup bytes are preserved and block all VPW", PendingStartup);
        await Case("repeated session cannot replay setup or upload", Repeat);
        await Case("copy-only observation stops after267 RAM bytes without executing", CopyOnly);
        await Case("copy-only malformed response performs no cleanup or execute", CopyOnlyFailure);
        await Case("copy-only cancellation retains uncertain RAM submission", CopyOnlyCancellation);
        Console.WriteLine(JsonSerializer.Serialize(new { assertions, passed, failed,
            adapterOpened = false, liveWriteEnabled = false, hardwareQualified = false,
            scope = "Production Vehicle + AutoCalDevice/Channel under the bounded policy, scripted byte transport only" }));
        return failed.Count == 0 ? 0 : 1;
    }

    static async Task<(Fake adapter, AutoCalDevice device, AutoCalKernelProbePolicy policy, AutoCalKernelProbeSession session)> Fixture(string failure = "", CancellationTokenSource? cancel = null, bool copyOnly = false)
    {
        var adapter = new Fake(kernel, failure, cancel);
        var token = cancel?.Token ?? CancellationToken.None;
        var device = new AutoCalDevice(new AutoCalChannel(adapter), new Log(), token, AutoCalSetupProfile.RecordedOrdinaryIdentification);
        Require(await device.Initialize(), "ordinary host setup accepted by fake adapter");
        var policy = new AutoCalKernelProbePolicy(kernel);
        var session = new AutoCalKernelProbeSession(device, new Log(), policy, token, copyOnly);
        return (adapter, device, policy, session);
    }
    static void Ownership(Fake fake, AutoCalDevice device)
    {
        Require(fake.DisposeCalls == 0 && !device.Channel.IsTransportDisposed, "session leaves transport ownership with caller");
        Require(fake.Commands.All(f => f.Command == 0x8A00 || f.Command == 0x8201 || f.Command == 0x8604 || f.Command == 0x8800), "no adapter cleanup/reset or extra host command");
        Require(fake.Vpw.All(v => v.Length < 4 || (v[3] != 0x04 && v[3] != 0x14 && v[3] != 0x35 && v[3] != 0xA0 && v[3] != 0xA1)), "no DTC clear, memory read or speed command");
        Require(!fake.Vpw.Any(v => v.Length >= 5 && v[3] == 0x3D && v[4] != 0), "only kernel-version3D00, no erase/flashID/CRC");
        device.Dispose();
        Require(fake.DisposeCalls == 1, "caller alone disposes the transport");
    }
    static bool Has(Fake fake, string hex) => fake.Vpw.Any(v => v.SequenceEqual(Hex(hex)));
    static async Task Success()
    {
        var f = await Fixture();
        var result = await f.session.RunAsync();
        Require(result.Success, result.Error ?? "expected successful scripted probe");
        Require(result.Stage == AutoCalKernelProbeStage.Complete && result.InitialIdentityVerified && result.KernelVersionVerified && result.ExitAcknowledged && result.PostExitIdentityVerified, "all physical-exchange conditions represented separately");
        Require(result.KernelVersion == 0x6AB178EC36UL && !result.BenchPowerCycleRequired && result.RamExecuteSubmitted, "exact version and successful return");
        var uploads = f.adapter.Vpw.Where(v => v[3] == 0x36).ToArray();
        Require(uploads.Length == 2 && uploads[0].Length == 279 && uploads[1].Length == 1772, "two expected descending RAM chunks");
        Require(uploads[0].SequenceEqual(Block(kernel, 1760, 267, 0xFF97E0, 0)) && uploads[1].SequenceEqual(Block(kernel, 0, 1760, 0xFF9100, 0x80)), "all RAM payload bytes/address/checksum match independent wire construction");
        Require(f.adapter.Vpw.Count(v => v.SequenceEqual(Hex("6C10F03C0A"))) == 2, "one initial and one post-exit OSID only");
        Require(result.RetainedQueueClearRequests == 3 && f.policy.RamExecuteAttempts == 1 && f.policy.RamCopyAttempts == 1, "generic queue clears retain bytes and upload is never replayed");
        Require(f.policy.KeyAttempts == 1 && Has(f.adapter, "6C10F027027C21"), "captured43B1 seed maps to the fixed54-algorithm7C21 key");
        Ownership(f.adapter, f.device);
    }
    static async Task WrongIdentity()
    {
        var f = await Fixture("identity"); var result = await f.session.RunAsync();
        Require(!result.Success && !result.InitialIdentityVerified && !result.BenchPowerCycleRequired && result.Stage == AutoCalKernelProbeStage.InitialIdentity, "identity failure before preparation");
        Require(f.adapter.Vpw.Count == 1, "only ordinary OSID was submitted"); Ownership(f.adapter, f.device);
    }
    static async Task Lockout()
    {
        var f = await Fixture("lockout"); var result = await f.session.RunAsync();
        Require(!result.Success && result.Stage == AutoCalKernelProbeStage.Unlock && result.BenchPowerCycleRequired, "lockout fails the probe");
        Require(f.policy.SeedAttempts == 1 && f.policy.KeyAttempts == 0 && !Has(f.adapter, "6C10F020") && !f.adapter.Vpw.Any(x => x[3] == 0x34), "no seed retry, key, upload or cleanup after lockout"); Ownership(f.adapter, f.device);
    }
    static async Task BadCopyAcknowledgement()
    {
        var f = await Fixture("copy"); var result = await f.session.RunAsync();
        Require(!result.Success && result.Stage == AutoCalKernelProbeStage.RamUpload && !result.RamExecuteSubmitted, "copy rejection prevents execute");
        Require(f.policy.RamCopyAttempts == 1 && f.policy.RamExecuteAttempts == 0 && !Has(f.adapter, "6C10F020"), "no repeated copy and no reset"); Ownership(f.adapter, f.device);
    }
    static async Task RejectedKey()
    {
        var f = await Fixture("key"); var result = await f.session.RunAsync();
        Require(!result.Success && result.Stage == AutoCalKernelProbeStage.Unlock && f.policy.KeyAttempts == 1, "rejected key is terminal");
        Require(f.policy.SeedAttempts == 1 && !f.adapter.Vpw.Any(v => v[3] == 0x34) && !Has(f.adapter, "6C10F020"), "no repeat key/seed, permission or reset"); Ownership(f.adapter, f.device);
    }
    static async Task UnlockedSeed()
    {
        var f = await Fixture("unlocked-copy"); var result = await f.session.RunAsync();
        Require(!result.Success && result.Stage == AutoCalKernelProbeStage.RamUpload && f.policy.KeyAttempts == 0 && f.policy.RamCopyAttempts == 1, "zero seed reaches RAM upload without a key attempt");
        Require(!f.adapter.Vpw.Any(v => v.Length >= 5 && v[3] == 0x27 && v[4] == 2), "already unlocked path sends no key"); Ownership(f.adapter, f.device);
    }
    static async Task WrongKernel()
    {
        var f = await Fixture("version"); var result = await f.session.RunAsync();
        Require(!result.Success && !result.KernelVersionVerified && result.RamExecuteSubmitted && result.BenchPowerCycleRequired, "version mismatch remains uncertain execution");
        Require(!Has(f.adapter, "6C10F020") && f.adapter.Vpw.Count(v => v.SequenceEqual(Hex("6C10F03D00"))) == 1, "no version retry or exit after mismatch"); Ownership(f.adapter, f.device);
    }
    static async Task CancelledExecute()
    {
        using var cancel = new CancellationTokenSource();
        var f = await Fixture("cancel-execute", cancel); var result = await f.session.RunAsync();
        Require(!result.Success && result.Cancelled && result.RamExecuteSubmitted && result.BenchPowerCycleRequired, "cancellation conservatively retains submitted execution");
        Require(f.policy.RamExecuteAttempts == 1 && !Has(f.adapter, "6C10F03D00") && !Has(f.adapter, "6C10F020"), "no retry/query/reset after cancellation"); Ownership(f.adapter, f.device);
    }
    static async Task WrongFinalIdentity()
    {
        var f = await Fixture("final-identity"); var result = await f.session.RunAsync();
        Require(!result.Success && result.KernelVersionVerified && result.ExitAcknowledged && !result.PostExitIdentityVerified, "exit ACK cannot stand in for ordinary OS identity");
        Require(f.adapter.Vpw.Count(v => v.SequenceEqual(Hex("6C10F03C0A"))) == 2 && f.adapter.Vpw.Count(v => v.SequenceEqual(Hex("6C10F020"))) == 1, "no fallback OS or repeat reset"); Ownership(f.adapter, f.device);
    }
    static async Task MissingExecuteAcknowledgement()
    {
        var f = await Fixture("missing-execute-ack"); var result = await f.session.RunAsync();
        Require(!result.Success && result.Stage == AutoCalKernelProbeStage.RamUpload && result.RamExecuteSubmitted && result.BenchPowerCycleRequired, "unacknowledged execute remains uncertain");
        Require(f.adapter.Vpw.Count(v => v.Length >= 5 && v[3] == 0x36 && v[4] == 0x80) == 1 && f.policy.RamExecuteAttempts == 1, "production retry loop is blocked before second native submission");
        Require(!Has(f.adapter, "6C10F020") && !Has(f.adapter, "6C10F03D00"), "no guessed version query or cleanup after missing upload ACK"); Ownership(f.adapter, f.device);
    }
    static async Task StaleCopyAcknowledgement()
    {
        var f = await Fixture("stale-copy"); var result = await f.session.RunAsync();
        Require(!result.Success && result.Stage == AutoCalKernelProbeStage.RamUpload && f.policy.LastReceive!.SequenceEqual(Hex("6CF010768078")), "retained stale copy ACK is rejected by expected submode");
        Require(f.policy.RamExecuteAttempts == 0 && f.adapter.PendingByteCount > 0, "no execute and remaining bytes are retained"); Ownership(f.adapter, f.device);
    }
    static async Task PendingStartup()
    {
        var f = await Fixture(); f.adapter.Enqueue(Packet(0x10, Hex("6CF01060")));
        int pending = f.adapter.PendingByteCount; var result = await f.session.RunAsync();
        Require(!result.Success && f.adapter.Vpw.Count == 0 && f.adapter.PendingByteCount == pending, "start refuses pending bytes without purge or transmission"); Ownership(f.adapter, f.device);
    }
    static async Task Repeat()
    {
        var f = await Fixture("identity"); await f.session.RunAsync(); int sent = f.adapter.Commands.Count;
        try { await f.session.RunAsync(); throw new Exception("second run was accepted"); }
        catch (InvalidOperationException) { assertions++; }
        Require(f.adapter.Commands.Count == sent, "second run performs no I/O"); Ownership(f.adapter, f.device);
    }
    static void CopyOnlyBoundary(Fake adapter, AutoCalKernelProbeResult result)
    {
        Require(result.ObservationOnly && !result.RamCopyBytesVerified && !result.RamExecuteSubmitted && !result.KernelVersionVerified && !result.ExitAcknowledged && !result.PostExitIdentityVerified,
            "copy observation makes no execution, content, exit or return-to-OS claim");
        Require(adapter.Vpw.Count(v => v[3] == 0x36) == 1 && adapter.Vpw.Single(v => v[3] == 0x36).SequenceEqual(Block(kernel, 1760, 267, 0xFF97E0, 0)),
            "only the pinned267-byte high RAM fragment was submitted");
        Require(!Has(adapter, "6C10F03D00") && !Has(adapter, "6C10F020") && adapter.Vpw.Count(v => v.SequenceEqual(Hex("6C10F03C0A"))) == 1,
            "no execute/version/exit/postidentity after copy");
    }
    static async Task CopyOnly()
    {
        var f = await Fixture(copyOnly: true); var result = await f.session.RunAsync();
        Require(result.Success && result.Stage == AutoCalKernelProbeStage.RamCopyObserved && result.RamCopyReplyObserved && result.BenchPowerCycleRequired,
            "completed observation still requires a physical bench power cycle");
        Require(f.policy.RamCopyAcknowledgement!.SequenceEqual(Hex("6CF010760078")) && f.policy.CurrentPhase == "RamExecute" && f.policy.RamExecuteAttempts == 0,
            "opaque copy suffix is retained and execute remains unattempted");
        CopyOnlyBoundary(f.adapter, result); Ownership(f.adapter, f.device);
    }
    static async Task CopyOnlyFailure()
    {
        var f = await Fixture("copy", copyOnly: true); var result = await f.session.RunAsync();
        Require(!result.Success && !result.RamCopyReplyObserved && result.BenchPowerCycleRequired && result.Stage == AutoCalKernelProbeStage.RamUpload,
            "malformed copy response terminates observation without success");
        CopyOnlyBoundary(f.adapter, result); Ownership(f.adapter, f.device);
    }
    static async Task CopyOnlyCancellation()
    {
        using var cancel = new CancellationTokenSource();
        var f = await Fixture("cancel-copy", cancel, copyOnly: true); var result = await f.session.RunAsync();
        Require(!result.Success && result.Cancelled && !result.RamCopyReplyObserved && result.BenchPowerCycleRequired,
            "cancelled RAM-copy submission stays uncertain and requires power cycle");
        CopyOnlyBoundary(f.adapter, result); Ownership(f.adapter, f.device);
    }

    // Independent wire constructors for the fake's fixed responses/expected RAM
    // chunks. Production Frame/Protocol encoders are deliberately not called.
    static byte[] Block(byte[] source, int offset, int length, int address, byte mode)
    {
        byte[] value = new byte[length + 12];
        byte[] prefix = { 0x6D, 0x10, 0xF0, 0x36, mode, (byte)(length >> 8), (byte)length, (byte)(address >> 16), (byte)(address >> 8), (byte)address };
        prefix.CopyTo(value, 0); Array.Copy(source, offset, value, 10, length);
        int sum = value.Skip(4).Take(length + 6).Sum(x => (int)x);
        value[^2] = (byte)(sum >> 8); value[^1] = (byte)sum; return value;
    }
    static byte[] Packet(uint field, byte[] payload)
    {
        byte[] bytes = new byte[payload.Length + 15]; bytes[0] = 1; bytes[1] = 0x52;
        for (int n = 0; n < 4; n++) bytes[n + 2] = (byte)(field >> (n * 8));
        bytes[10] = (byte)payload.Length; bytes[11] = (byte)(payload.Length >> 8); payload.CopyTo(bytes, 12);
        ushort crc = 0;
        for (int n = 0; n < bytes.Length - 3; n++)
        { crc ^= bytes[n]; for (int b = 0; b < 8; b++) crc = (ushort)((crc & 1) == 0 ? crc >> 1 : (crc >> 1) ^ 0xA001); }
        bytes[^3] = (byte)crc; bytes[^2] = (byte)(crc >> 8); bytes[^1] = 0x19; return bytes;
    }
    sealed class Fake : IAutoCalByteTransport
    {
        readonly Queue<byte> input = new(); readonly List<byte> output = new(); readonly byte[] image; readonly string failure; readonly CancellationTokenSource? cancel;
        int identityCount;
        public int DisposeCalls; public List<(ushort Command, byte[] Payload)> Commands = new(); public List<byte[]> Vpw = new();
        public int PendingByteCount => input.Count;
        public Fake(byte[] kernel, string failure, CancellationTokenSource? cancel) { image = kernel; this.failure = failure; this.cancel = cancel; }
        public void Enqueue(byte[] bytes) { foreach (byte b in bytes) input.Enqueue(b); }
        public Task<int> Read(byte[] buffer, int offset, int count, int timeoutMs, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); int n = Math.Min(count, Math.Min(97, input.Count));
            for (int i = 0; i < n; i++) buffer[offset + i] = input.Dequeue(); return Task.FromResult(n);
        }
        public Task<int> Write(byte[] buffer, int offset, int count, int timeoutMs, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); int n = Math.Min(113, count); output.AddRange(buffer.Skip(offset).Take(n));
            if (output.Count >= 12)
            {
                int total = 14 + output[10] + (output[11] << 8);
                if (output.Count > total) throw new Exception("Fake received overlapping commands");
                if (output.Count == total)
                {
                    byte[] raw = output.ToArray(); output.Clear();
                    if (raw[0] != 1 || raw[1] != 0x54 || raw[4] != 7) throw new Exception("Unexpected host header");
                    ushort command = (ushort)(raw[2] | raw[3] << 8); byte[] payload = raw.Skip(12).Take(total - 14).ToArray();
                    Commands.Add((command, payload));
                    if (command == 0x8A00)
                    {
                        if (raw[6] != 0x10 || raw[7] != 0 || raw[8] != 0 || raw[9] != 0) throw new Exception("Unexpected VPW metadata");
                        Vpw.Add(payload); Respond(payload);
                    }
                    else
                    {
                        var expected = new[] { (0x8201, ""), (0x8604, "00"), (0x8800, "0000"), (0x8604, "000000000000") };
                        int index = Commands.Count - 1;
                        if (index >= expected.Length || command != expected[index].Item1 || !payload.SequenceEqual(Hex(expected[index].Item2))) throw new Exception("Unexpected setup or cleanup command");
                        Enqueue(Packet(command, command == 0x8201 ? Hex("4143563200") : Array.Empty<byte>()));
                    }
                }
            }
            return Task.FromResult(n);
        }
        void Respond(byte[] bytes)
        {
            string text = Convert.ToHexString(bytes); byte[]? reply;
            switch (text)
            {
                case "6C10F03C0A":
                    identityCount++; reply = Hex(failure == "identity" || failure == "final-identity" && identityCount == 2 ? "6CF0107C0A00E7C435" : "6CF0107C0A00E7C434444E"); break;
                case "6CFEF02800": reply = Hex("6CF0106800"); break;
                case "8CFEF03F": reply = null; break;
                // Seed/key pair is pinned from the independently captured GT
                // read, not calculated with the production key generator here.
                case "6C10F02701": reply = Hex(failure == "lockout" ? "6CF010670137" : failure == "unlocked-copy" ? "6CF01067010000" : "6CF010670143B1"); break;
                case "6C10F027027C21": reply = Hex(failure == "key" ? "6CF010670235" : "6CF010670234"); break;
                case "6C10F0340007EBFF9100":
                    reply = Hex("6CF010740044");
                    if (failure == "stale-copy") { Enqueue(Packet(0x10, reply)); Enqueue(Packet(0x10, Hex("6CF010768078"))); return; }
                    break;
                case "6C10F03D00": reply = Hex(failure == "version" ? "6CF0107D006AB178EC37" : "6CF0107D006AB178EC36"); break;
                case "6C10F020": reply = Hex("6CF01060"); break;
                default:
                    if (bytes.SequenceEqual(Block(image, 1760, 267, 0xFF97E0, 0)))
                    {
                        if (failure == "cancel-copy") { cancel!.Cancel(); return; }
                        reply = Hex(failure == "copy" || failure == "unlocked-copy" ? "6CF010768078" : "6CF010760078");
                    }
                    else if (bytes.SequenceEqual(Block(image, 0, 1760, 0xFF9100, 0x80)))
                    {
                        if (failure == "cancel-execute") { cancel!.Cancel(); return; }
                        if (failure == "missing-execute-ack")
                        {
                            // Exhaust WaitForSuccess with unrelated actual
                            // frames, then observe its attempted resend at the
                            // policy boundary without waiting on fake timeouts.
                            for (int i = 0; i < 5; i++) Enqueue(Packet(0x10, Hex("6CF0116800")));
                            return;
                        }
                        reply = Hex("6CF010768078");
                    }
                    else throw new Exception("Unexpected VPW payload: " + text.Substring(0, Math.Min(text.Length, 40)));
                    break;
            }
            if (reply != null) Enqueue(Packet(0x10, reply));
        }
        public void Dispose() { DisposeCalls++; }
    }
    sealed class Log : ILogger
    {
        public void AddUserMessage(string message) { } public void AddDebugMessage(string message) { }
        public void StatusUpdateActivity(string activity) { } public void StatusUpdateTimeRemaining(string remaining) { }
        public void StatusUpdatePercentDone(string percent) { } public void StatusUpdateRetryCount(string retries) { }
        public void StatusUpdateProgressBar(double completed, bool visible) { } public void StatusUpdateKbps(string kbps) { } public void StatusUpdateReset() { }
    }
}
