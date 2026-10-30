// SPDX-License-Identifier: GPL-3.0-only
// Actual Vehicle/Device/Channel with a byte-level fake AutoCal+ECU. No native
// library is linked, no adapter opened, and no hardware operation performed.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
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
    static byte[] baseline = Array.Empty<byte>();
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
        baseline = File.ReadAllBytes(AutoCalKernelProbePolicy.DefaultBaselinePath);
        Require(baseline.Length == 524288 && Convert.ToHexString(SHA256.HashData(baseline)).Equals(AutoCalKernelProbePolicy.ExpectedBaselineSha256, StringComparison.OrdinalIgnoreCase),
            "private GT readback fixture matches its pinned size and digest");
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
        await Case("unknown Copy suffix cannot authorize Execute", UnknownCopyBlocksExecute);
        await Case("copy-only retains unknown suffix as observation without qualification", UnknownCopyObservation);
        await Case("unknown Execute suffix cannot authorize kernel query", UnknownExecuteStops);
        await Case("full read returns exact GT baseline with seven independent CRC replies", FullReadSuccess);
        await Case("full read rejects bad block checksum without exit or reupload", FullReadCorruptBlock);
        await Case("full read rejects a different checksum-valid image before CRC or exit", FullReadDifferentBaseline);
        await Case("full read CRC mismatch prevents exit and successful image", FullReadCrcMismatch);
        await Case("full read wrong flash identity stops before data transfer", FullReadWrongIdentity);
        await Case("full read cancellation during data stops further traffic", FullReadCancellation);
        await Case("full read cancellation on final CRC cannot succeed or exit", FullReadFinalCrcCancellation);
        await Case("short read returns only the pinned 64-byte prefix without CRC", ShortReadSuccess);
        await Case("short read checksum failure blocks exit and replay", () => ShortReadFailure("short-corrupt"));
        await Case("short read different valid prefix blocks exit and replay", () => ShortReadFailure("short-different"));
        await Case("short read missing matching payload cannot retransmit or exit", () => ShortReadFailure("short-missing"));
        await Case("short read cancellation retains uncertain controller state", ShortReadCancellation);
        await Case("short read mode mismatch and copy combination rejected before traffic", ShortReadModeBinding);
        await Case("recorded preparation and restore occur at exact prefix-session boundaries", RecordedSetupSuccess);
        await Case("partial recorded configuration blocks all further VPW and requires power cycle", () => RecordedSetupFailure("config-partial"));
        await Case("recorded preparation command error blocks suppression", () => RecordedSetupFailure("config-error"));
        await Case("recorded restore failure blocks flash ID and read", () => RecordedSetupFailure("restore-error"));
        await Case("wrong kernel prevents recorded restoration and prefix read", () => RecordedSetupFailure("version"));
        await Case("recorded preparation cancellation blocks continuation", () => RecordedSetupCancellation("config-cancel"));
        await Case("recorded restore cancellation blocks continuation", () => RecordedSetupCancellation("restore-cancel"));
        await Case("recorded setup is restricted to short read before any I/O", RecordedSetupModeBinding);
        await Case("payload parser selects exact submode and checks original wire bytes", ExplicitReadReplySubmode);
        await Case("zero-submode kernel returns scoped prefix with exact changed RAM upload", ZeroSubmodeSuccess);
        await Case("zero-submode kernel rejects a normal-one reply without exit", () => ZeroSubmodeFailure("short-wrong-submode"));
        await Case("zero-submode kernel rejects checksum corruption without exit", () => ZeroSubmodeFailure("short-corrupt"));
        await Case("acknowledged prefix receives exact75 then raw00 data before explicit exit", AcknowledgedReadSuccess);
        await Case("acknowledged prefix cannot accept data without the required75", () => AcknowledgedReadFailure("ack-missing"));
        await Case("acknowledged prefix preserves and rejects a wrong75", () => AcknowledgedReadFailure("ack-wrong"));
        await Case("acknowledged prefix rejects a repeated75 before data", () => AcknowledgedReadFailure("ack-duplicate"));
        await Case("acknowledged prefix rejects75 before the read request", () => AcknowledgedReadFailure("ack-early"));
        await Case("acknowledged prefix retains trailing75 bytes and blocks exit", () => AcknowledgedReadFailure("ack-trailing"));
        await Case("acknowledgement survives a later payload checksum failure", () => AcknowledgedReadFailure("short-corrupt"));
        await Case("ordinary zero-submode mode cannot silently admit75", UnexpectedAcknowledgement);
        Console.WriteLine(JsonSerializer.Serialize(new { assertions, passed, failed,
            adapterOpened = false, liveWriteEnabled = false, hardwareQualified = false,
            scope = "Production Vehicle + AutoCalDevice/Channel under the bounded policy, scripted byte transport only" }));
        return failed.Count == 0 ? 0 : 1;
    }

    static async Task<(Fake adapter, AutoCalDevice device, AutoCalKernelProbePolicy policy, AutoCalKernelProbeSession session)> Fixture(string failure = "", CancellationTokenSource? cancel = null, bool copyOnly = false, bool fullRead = false, bool shortRead = false, bool recordedReadSetup = false, bool useZeroSubmodeKernel = false, bool prependReadAcknowledgement = false)
    {
        var adapter = new Fake(IndependentKernel(useZeroSubmodeKernel, prependReadAcknowledgement), failure, cancel, fullRead, shortRead, recordedReadSetup, useZeroSubmodeKernel, prependReadAcknowledgement);
        var token = cancel?.Token ?? CancellationToken.None;
        var device = new AutoCalDevice(new AutoCalChannel(adapter), new Log(), token, AutoCalSetupProfile.RecordedOrdinaryIdentification);
        Require(await device.Initialize(), "ordinary host setup accepted by fake adapter");
        var policy = new AutoCalKernelProbePolicy(kernel, fullRead, shortRead, useZeroSubmodeKernel, prependReadAcknowledgement);
        var session = new AutoCalKernelProbeSession(device, new Log(), policy, token, copyOnly, fullRead, shortRead, recordedReadSetup);
        return (adapter, device, policy, session);
    }
    static byte[] IndependentKernel(bool zeroSubmode, bool prependReadAcknowledgement = false)
    {
        byte[] value = (byte[])kernel.Clone();
        if (zeroSubmode)
        {
            if (!value.AsSpan(0x7AA, 10).SequenceEqual(Hex("6DF01036010000000000")))
                throw new Exception("Private kernel fixture differs from the independently pinned reply-template bytes.");
            value[0x7AE] = 0;
        }
        if (prependReadAcknowledgement)
        {
            if (!zeroSubmode || !value.AsSpan(0x90, 4).SequenceEqual(Hex("67000448"))
                || !value.AsSpan(0x794, 22).SequenceEqual(System.Text.Encoding.ASCII.GetBytes("(c)2026 pcmhacking.net")))
                throw new Exception("Private kernel differs from the independently reviewed dispatch and metadata bytes.");
            // Independent exact fixture: dispatch to the22-byte metadata stub,
            // emit the six-byte ACK, then branch to unchanged Mode35 parsing.
            value[0x92] = 7; value[0x93] = 2;
            Hex("41FA000C70066100FE4C6000FD3A6DF0107501544E71").CopyTo(value, 0x794);
        }
        return value;
    }
    static void Ownership(Fake fake, AutoCalDevice device)
    {
        Require(fake.DisposeCalls == 0 && !device.Channel.IsTransportDisposed, "session leaves transport ownership with caller");
        Require(fake.Commands.All(f => f.Command == 0x8A00 || f.Command == 0x8201 || f.Command == 0x8604 || f.Command == 0x8800
            || fake.RecordedReadSetup && f.Command == 0x8603), "no adapter cleanup/reset or extra host command");
        Require(fake.Vpw.All(v => v.Length < 4 || (v[3] != 0x04 && v[3] != 0x14 && (v[3] != 0x35 || fake.FullRead || fake.ShortRead) && v[3] != 0xA0 && v[3] != 0xA1)), "no DTC clear, unrequested memory read or speed command");
        Require(!fake.Vpw.Any(v => v.Length >= 5 && v[3] == 0x3D && v[4] > (fake.FullRead ? 2 : fake.ShortRead ? 1 : 0)), "only mode-permitted kernel information/CRC queries, no erase");
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
        Require(result.EffectiveKernelSha256 == AutoCalKernelProbePolicy.ExpectedKernelSha256 && !result.UsesZeroSubmodeKernel && result.ReadReplySubmode == 1,
            "ordinary kernel provenance and expected reply submode remain unchanged");
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
    static async Task UnknownCopyBlocksExecute()
    {
        var f = await Fixture("copy-unknown"); var result = await f.session.RunAsync();
        Require(!result.Success && result.RamCopyReplyObserved && !result.RamCopyBytesVerified && !result.RamExecuteSubmitted && result.BenchPowerCycleRequired,
            "unobserved Copy suffix remains a raw observation and prevents execution");
        Require(f.policy.RamCopyAcknowledgement!.SequenceEqual(Hex("6CF010760000")) && f.policy.RamExecuteAttempts == 0,
            "unknown Copy reply is preserved and Execute is rejected before submission");
        Require(f.adapter.Vpw.Count(v => v[3] == 0x36) == 1 && !Has(f.adapter, "6C10F03D00") && !Has(f.adapter, "6C10F020"),
            "no second upload or subsequent kernel operation"); Ownership(f.adapter, f.device);
    }
    static async Task UnknownCopyObservation()
    {
        var f = await Fixture("copy-unknown", copyOnly: true); var result = await f.session.RunAsync();
        Require(result.Success && result.ObservationOnly && result.RamCopyReplyObserved && result.BenchPowerCycleRequired,
            "copy-only can complete observation of an unknown suffix");
        Require(f.policy.RamCopyAcknowledgement!.SequenceEqual(Hex("6CF010760000")), "unknown suffix preserved verbatim");
        CopyOnlyBoundary(f.adapter, result); Ownership(f.adapter, f.device);
    }
    static async Task UnknownExecuteStops()
    {
        var f = await Fixture("execute-unknown"); var result = await f.session.RunAsync();
        Require(!result.Success && result.RamExecuteSubmitted && !result.KernelVersionVerified && result.BenchPowerCycleRequired,
            "unknown Execute suffix retains uncertain execution and fails closed");
        Require(f.policy.LastReceive!.SequenceEqual(Hex("6CF010768000")) && !Has(f.adapter, "6C10F03D00") && !Has(f.adapter, "6C10F020"),
            "raw Execute reply preserved with no kernel query or reset"); Ownership(f.adapter, f.device);
    }
    static void FullReadUploadBoundary(Fake adapter)
    {
        byte[][] uploads = adapter.Vpw.Where(v => v[3] == 0x36).ToArray();
        Require(uploads.Length == 2 && uploads[0].SequenceEqual(Block(kernel, 1760, 267, 0xFF97E0, 0)) && uploads[1].SequenceEqual(Block(kernel, 0, 1760, 0xFF9100, 0x80)),
            "only the initial two pinned RAM uploads, never a flash write or reupload");
        Require(adapter.Vpw.Count(v => v[3] == 0x34) == 1, "one initial upload-permission request");
    }
    static void FullReadFailureBoundary(Fake adapter, AutoCalKernelProbeResult result)
    {
        Require(!result.Success && result.Stage == AutoCalKernelProbeStage.FullRead && result.KernelVersionVerified && result.BenchPowerCycleRequired,
            "read failure retains known running-kernel state and requires recovery by caller");
        Require(!result.ReadbackCrcVerified && !result.BaselineMatched && result.ReadbackBytes == null && !result.ExitAcknowledged && !result.PostExitIdentityVerified,
            "failed transfer never exposes a successful image or exit claim");
        Require(!Has(adapter, "6C10F020") && adapter.Vpw.Count(v => v.SequenceEqual(Hex("6C10F03C0A"))) == 1,
            "no automatic exit or post-exit identity after read failure");
        FullReadUploadBoundary(adapter);
    }
    static async Task FullReadSuccess()
    {
        var f = await Fixture(fullRead: true); var result = await f.session.RunAsync();
        Require(result.Success, result.Error ?? "expected full-read success");
        Require(result.ReadbackLength == 524288 && result.ReadbackSha256 == AutoCalKernelProbePolicy.ExpectedBaselineSha256
            && result.ReadbackBytes!.SequenceEqual(baseline), "full returned snapshot equals the independently captured GT baseline byte for byte");
        Require(result.ReadbackCrcVerified && result.BaselineMatched && f.policy.IsImageVerified && f.policy.VerifiedCrcRanges == 7,
            "both production reader and policy verified all seven captured controller CRCs");
        Require(result.ReadbackScope == "full-image", "full-image match has explicit coverage scope");
        Require(f.adapter.ReadRequests == 128 && f.adapter.CrcRequests == 7 && f.policy.ReadBlockReplies == 128,
            "exact block coverage and seven CRC exchanges without retries");
        Require(result.ExitAcknowledged && result.PostExitIdentityVerified && !result.BenchPowerCycleRequired,
            "exit and return to ordinary identity only after successful full verification");
        Require(!JsonSerializer.Serialize(result).Contains("ReadbackBytes"), "private firmware bytes are excluded from receipt JSON");
        FullReadUploadBoundary(f.adapter); Ownership(f.adapter, f.device);
    }
    static async Task FullReadCorruptBlock()
    {
        var f = await Fixture("read-corrupt", fullRead: true); var result = await f.session.RunAsync();
        FullReadFailureBoundary(f.adapter, result);
        Require(f.adapter.ReadRequests == 1 && f.adapter.CrcRequests == 0 && f.policy.ReadBlockReplies == 0,
            "checksum failure blocks subsequent read requests and CRCs"); Ownership(f.adapter, f.device);
    }
    static async Task FullReadDifferentBaseline()
    {
        var f = await Fixture("read-different", fullRead: true); var result = await f.session.RunAsync();
        FullReadFailureBoundary(f.adapter, result);
        Require(f.adapter.ReadRequests == 128 && f.adapter.CrcRequests == 0 && f.policy.IsImageReadComplete && !f.policy.BaselineShaMatched,
            "complete checksum-valid but changed image fails baseline pin before CRC or exit"); Ownership(f.adapter, f.device);
    }
    static async Task FullReadCrcMismatch()
    {
        var f = await Fixture("read-crc", fullRead: true); var result = await f.session.RunAsync();
        FullReadFailureBoundary(f.adapter, result);
        Require(f.adapter.ReadRequests == 128 && f.adapter.CrcRequests == 4 && f.policy.VerifiedCrcRanges == 3,
            "first mismatching CRC halts remaining ranges without losing prior coverage"); Ownership(f.adapter, f.device);
    }
    static async Task FullReadWrongIdentity()
    {
        var f = await Fixture("read-flash-id", fullRead: true); var result = await f.session.RunAsync();
        FullReadFailureBoundary(f.adapter, result);
        Require(f.adapter.ReadRequests == 0 && f.adapter.CrcRequests == 0 && !f.policy.IsFlashIdentityVerified,
            "wrong physical flash ID blocks every memory read"); Ownership(f.adapter, f.device);
    }
    static async Task FullReadCancellation()
    {
        using var cancel = new CancellationTokenSource();
        var f = await Fixture("read-cancel", cancel, fullRead: true); var result = await f.session.RunAsync();
        FullReadFailureBoundary(f.adapter, result);
        Require(result.Cancelled && f.adapter.ReadRequests == 64 && f.adapter.CrcRequests == 0,
            "data cancellation stops at submitted block64 and sends no further requests"); Ownership(f.adapter, f.device);
    }
    static async Task FullReadFinalCrcCancellation()
    {
        using var cancel = new CancellationTokenSource();
        var f = await Fixture("read-crc-cancel", cancel, fullRead: true); var result = await f.session.RunAsync();
        FullReadFailureBoundary(f.adapter, result);
        Require(result.Cancelled && f.adapter.ReadRequests == 128 && f.adapter.CrcRequests == 7 && f.policy.VerifiedCrcRanges == 6,
            "cancellation at final CRC prevents a successful result and exit"); Ownership(f.adapter, f.device);
    }

    static async Task ShortReadSuccess()
    {
        var f = await Fixture(shortRead: true); var result = await f.session.RunAsync();
        Require(result.Success, result.Error ?? "expected prefix read success");
        Require(result.ReadbackScope == "baseline-prefix" && result.BaselineMatched && result.ReadbackLength == 64
            && result.ReadbackBytes!.SequenceEqual(baseline.Take(64)) && result.ReadbackSha256 == AutoCalKernelProbePolicy.ExpectedShortReadSha256,
            "only the first64 baseline bytes and their scoped digest are returned");
        Require(!result.ReadbackCrcVerified && f.policy.IsShortReadVerified && !f.policy.IsImageVerified && !f.policy.IsImageReadComplete && !f.policy.BaselineShaMatched,
            "prefix success makes no controller CRC or full-image claim");
        Require(f.adapter.ReadRequests == 1 && f.adapter.CrcRequests == 0 && Has(f.adapter, "6D10F035010040000000"),
            "one exact64-byte request and no range CRC");
        Require(result.ExitAcknowledged && result.PostExitIdentityVerified && !result.BenchPowerCycleRequired,
            "successful prefix permits explicit exit and ordinary identity");
        Require(!JsonSerializer.Serialize(result).Contains("ReadbackBytes"), "private prefix excluded from receipt");
        FullReadUploadBoundary(f.adapter); Ownership(f.adapter, f.device);
    }
    static async Task ShortReadFailure(string failure, CancellationTokenSource? cancel = null)
    {
        var f = await Fixture(failure, cancel, shortRead: true); var result = await f.session.RunAsync();
        Require(!result.Success && result.Stage == AutoCalKernelProbeStage.ShortRead && result.KernelVersionVerified && result.BenchPowerCycleRequired,
            "prefix failure retains running-kernel state and needs caller recovery");
        Require(result.ReadbackScope == "baseline-prefix" && !result.ReadbackCrcVerified && !result.BaselineMatched && result.ReadbackBytes == null,
            "failed prefix never produces readback or image verification claims");
        Require(f.adapter.ReadRequests == 1 && f.adapter.CrcRequests == 0 && !Has(f.adapter, "6C10F020")
            && f.adapter.Vpw.Count(v => v.SequenceEqual(Hex("6C10F03C0A"))) == 1,
            "one read only, no retry, CRC, exit or post-exit query");
        Require(!f.policy.IsShortReadVerified && !f.policy.IsImageVerified, "no verification on failed prefix");
        if (cancel != null) Require(result.Cancelled, "cancellation retained in result");
        if (failure == "short-missing") Require(f.policy.UnrelatedReceiveCount == 6 && f.policy.LastReceive!.SequenceEqual(Hex("6CF0116800")),
            "five unrelated data-window replies plus the earlier suppression reply were retained without replay");
        FullReadUploadBoundary(f.adapter); Ownership(f.adapter, f.device);
    }
    static async Task ShortReadCancellation()
    {
        using var cancel = new CancellationTokenSource();
        await ShortReadFailure("short-cancel", cancel);
    }
    static async Task ShortReadModeBinding()
    {
        var f = await Fixture(shortRead: true);
        int rejected = 0;
        try { _ = new AutoCalKernelProbeSession(f.device, new Log(), f.policy, CancellationToken.None); } catch (ArgumentException) { rejected++; }
        try { _ = new AutoCalKernelProbeSession(f.device, new Log(), f.policy, CancellationToken.None, copyOnly: true, shortRead: true); } catch (ArgumentException) { rejected++; }
        try { _ = new AutoCalKernelProbeSession(f.device, new Log(), f.policy, CancellationToken.None, fullRead: true, shortRead: true); } catch (ArgumentException) { rejected++; }
        Require(rejected == 3 && f.adapter.Vpw.Count == 0, "mode mismatch rejected before any VPW command");
        Ownership(f.adapter, f.device);
    }

    static async Task RecordedSetupSuccess()
    {
        var f = await Fixture(shortRead: true, recordedReadSetup: true); var result = await f.session.RunAsync();
        Require(result.Success, result.Error ?? "expected configured prefix success");
        Require(result.RecordedReadSetupAttempted && result.RecordedReadSetupApplied && result.RecordedOrdinaryConfigurationRestored,
            "preparation attempt acceptance and restoration are distinct observations");
        Require(result.ReadbackScope == "baseline-prefix" && result.ReadbackLength == 64 && result.BaselineMatched
            && !result.ReadbackCrcVerified && !f.policy.IsImageVerified && !result.BenchPowerCycleRequired,
            "recorded setup does not widen verified data or claim controller CRC");
        var commands = f.adapter.Commands;
        Require(commands[4].Command == 0x8A00 && commands[4].Payload.SequenceEqual(Hex("6C10F03C0A"))
            && commands[5].Command == 0x8603 && commands[5].Payload.SequenceEqual(Hex("0100F401"))
            && commands[6].Command == 0x8604 && commands[6].Payload.SequenceEqual(Hex("010010000000"))
            && commands[7].Command == 0x8A00 && commands[7].Payload.SequenceEqual(Hex("6CFEF02800")),
            "exact recorded pair is between initial identity and suppression");
        int version = commands.FindIndex(c => c.Command == 0x8A00 && c.Payload.SequenceEqual(Hex("6C10F03D00")));
        int flash = commands.FindIndex(c => c.Command == 0x8A00 && c.Payload.SequenceEqual(Hex("6C10F03D01")));
        Require(commands[version + 1].Command == 0x8604 && commands[version + 1].Payload.SequenceEqual(new byte[6])
            && flash > version + 1 && f.adapter.ConfigurationCommands == 3,
            "one zero restore after valid kernel version precedes flash identification");
        Require(f.adapter.ReadRequests == 1 && f.adapter.CrcRequests == 0 && result.PostExitIdentityVerified,
            "same one-shot prefix and ordinary exit follow configuration");
        FullReadUploadBoundary(f.adapter); Ownership(f.adapter, f.device);
    }
    static async Task RecordedSetupFailure(string failure, CancellationTokenSource? cancel = null)
    {
        var f = await Fixture(failure, cancel, shortRead: true, recordedReadSetup: true);
        var result = await f.session.RunAsync();
        Require(!result.Success && result.InitialIdentityVerified && result.RecordedReadSetupAttempted && result.BenchPowerCycleRequired,
            "attempted configuration failure conservatively requires caller power cycle");
        Require(!result.RecordedOrdinaryConfigurationRestored && !Has(f.adapter, "6C10F03D01") && f.adapter.ReadRequests == 0
            && f.adapter.CrcRequests == 0 && !Has(f.adapter, "6C10F020"), "failed configuration or prerequisite never sends later read/CRC/exit");
        bool prepareFailure = failure.StartsWith("config-", StringComparison.Ordinal);
        Require(result.RecordedReadSetupApplied == !prepareFailure, "accepted configuration survives later failure without conflating partial setup");
        if (prepareFailure)
        {
            Require(result.Stage == AutoCalKernelProbeStage.RecordedReadPreparation && f.adapter.Vpw.Count == 1
                && !result.RamExecuteSubmitted, "preparation failure sends no suppression, key or kernel");
            Require(f.adapter.ConfigurationCommands == 1, "first configuration complete; second absent or partial without replay");
            if (failure == "config-partial") Require(f.adapter.PartialConfigurationBytes == 7 && f.device.Channel.IsFaulted,
                "partial mode command is retained as uncertain and stops channel");
        }
        else if (failure == "version")
        {
            Require(result.Stage == AutoCalKernelProbeStage.KernelVersion && !result.KernelVersionVerified
                && f.adapter.ConfigurationCommands == 2, "wrong kernel does not authorize zero restoration");
        }
        else Require(result.Stage == AutoCalKernelProbeStage.RecordedOrdinaryRestore && result.KernelVersionVerified
            && f.adapter.ConfigurationCommands == 3, "restoration failure follows known kernel and stops before flash ID");
        if (cancel != null) Require(result.Cancelled, "configuration cancellation remains explicit");
        Ownership(f.adapter, f.device);
    }
    static async Task RecordedSetupCancellation(string failure)
    {
        using var cancel = new CancellationTokenSource(); await RecordedSetupFailure(failure, cancel);
    }
    static async Task RecordedSetupModeBinding()
    {
        var f = await Fixture(); int rejected = 0;
        try { _ = new AutoCalKernelProbeSession(f.device, new Log(), f.policy, CancellationToken.None, recordedReadSetup: true); }
        catch (ArgumentException) { rejected++; }
        var fullPolicy = new AutoCalKernelProbePolicy(kernel, fullRead: true);
        try { _ = new AutoCalKernelProbeSession(f.device, new Log(), fullPolicy, CancellationToken.None, fullRead: true, recordedReadSetup: true); }
        catch (ArgumentException) { rejected++; }
        var zeroPolicy = new AutoCalKernelProbePolicy(kernel, shortRead: true, useZeroSubmodeKernel: true);
        try { _ = new AutoCalKernelProbeSession(f.device, new Log(), zeroPolicy, CancellationToken.None, shortRead: true, recordedReadSetup: true); }
        catch (ArgumentException) { rejected++; }
        Require(rejected == 3 && f.adapter.Vpw.Count == 0, "recorded setup cannot enable ordinary, full-image or zero-submode variant");
        Ownership(f.adapter, f.device);
    }

    static Task ExplicitReadReplySubmode()
    {
        var protocol = new Protocol();
        byte[] normal = Block(baseline, 0, 64, 0, 1); normal[1] = 0xF0; normal[2] = 0x10;
        byte[] zero = Block(baseline, 0, 64, 0, 0); zero[1] = 0xF0; zero[2] = 0x10;
        byte[] before = (byte[])zero.Clone();
        Require(protocol.ParsePayload(new Message(normal), 64, 0).Status == ResponseStatus.Success,
            "legacy three-argument parser still accepts normal submode one");
        Require(protocol.ParsePayload(new Message(zero), 64, 0).Status != ResponseStatus.Success,
            "legacy parser does not silently broaden to submode zero");
        var accepted = protocol.ParsePayload(new Message(zero), 64, 0, 0);
        Require(accepted.Status == ResponseStatus.Success && accepted.Value.SequenceEqual(baseline.Take(64)),
            "explicit zero parses the independently constructed raw zero-submode checksum");
        Require(zero.SequenceEqual(before), "explicit parsing does not normalize or mutate input bytes");
        Require(protocol.ParsePayload(new Message(normal), 64, 0, 0).Status != ResponseStatus.Success
            && protocol.ParsePayload(new Message(zero), 64, 0, 1).Status != ResponseStatus.Success,
            "expected submode is exact in both directions");
        byte[] staleChecksum = (byte[])normal.Clone(); staleChecksum[4] = 0;
        Require(protocol.ParsePayload(new Message(staleChecksum), 64, 0, 0).Status != ResponseStatus.Success,
            "changing submode without recomputing its raw checksum cannot pass");
        byte[] corrupt = (byte[])zero.Clone(); corrupt[^1] ^= 1;
        Require(protocol.ParsePayload(new Message(corrupt), 64, 0, 0).Status != ResponseStatus.Success,
            "independently corrupted zero-submode checksum fails");
        int rejected = 0;
        foreach (byte unsupported in new byte[] { 2, 0x80, 0xFF })
            try { protocol.ParsePayload(new Message(normal), 64, 0, unsupported); }
            catch (ArgumentOutOfRangeException) { rejected++; }
        Require(rejected == 3, "explicit normal mode option admits only zero or one");
        return Task.CompletedTask;
    }

    static void ZeroSubmodeUploadBoundary(Fake adapter)
    {
        byte[] derived = IndependentKernel(true);
        Require(Enumerable.Range(0, kernel.Length).Where(i => derived[i] != kernel[i]).SequenceEqual(new[] { 0x7AE })
            && kernel[0x7AE] == 1 && derived[0x7AE] == 0, "only the pinned response-template byte is changed in the test kernel");
        byte[][] uploads = adapter.Vpw.Where(v => v[3] == 0x36).ToArray();
        Require(uploads.Length == 2 && uploads[0].SequenceEqual(Block(derived, 1760, 267, 0xFF97E0, 0))
            && uploads[1].SequenceEqual(Block(kernel, 0, 1760, 0xFF9100, 0x80)),
            "derived high chunk and checksum match; executable low chunk remains byte-identical");
        Require(adapter.Vpw.Count(v => v[3] == 0x34) == 1 && adapter.ReadRequests == 1 && adapter.CrcRequests == 0
            && adapter.ConfigurationCommands == 0, "one RAM permission and prefix read, with no retry, CRC or configuration change");
    }

    static async Task ZeroSubmodeSuccess()
    {
        var f = await Fixture(shortRead: true, useZeroSubmodeKernel: true); var result = await f.session.RunAsync();
        Require(result.Success, result.Error ?? "expected derived-kernel prefix success");
        Require(result.UsesZeroSubmodeKernel && result.ReadReplySubmode == 0
            && result.EffectiveKernelSha256 == "17a351715bbdd366cf77e33ad5d0b801fa0747f2d31c57478ad3bb409ee58fe3"
            && Convert.ToHexString(SHA256.HashData(kernel)).Equals(AutoCalKernelProbePolicy.ExpectedKernelSha256, StringComparison.OrdinalIgnoreCase),
            "receipt identifies derived kernel without changing original fixture");
        Require(result.ReadbackScope == "baseline-prefix" && result.BaselineMatched && result.ReadbackLength == 64
            && result.ReadbackBytes!.SequenceEqual(baseline.Take(64)) && result.ReadbackSha256 == AutoCalKernelProbePolicy.ExpectedShortReadSha256,
            "exact prefix returned from raw zero-submode response");
        Require(f.policy.IsShortReadVerified && !f.policy.IsImageVerified && !result.ReadbackCrcVerified,
            "zero variant preserves prefix-only scope");
        Require(result.ExitAcknowledged && result.PostExitIdentityVerified && !result.BenchPowerCycleRequired,
            "normal explicit exit follows verified variant prefix");
        ZeroSubmodeUploadBoundary(f.adapter); Ownership(f.adapter, f.device);
    }

    static async Task ZeroSubmodeFailure(string failure)
    {
        var f = await Fixture(failure, shortRead: true, useZeroSubmodeKernel: true); var result = await f.session.RunAsync();
        Require(!result.Success && result.Stage == AutoCalKernelProbeStage.ShortRead && result.KernelVersionVerified
            && result.BenchPowerCycleRequired && result.UsesZeroSubmodeKernel && result.ReadReplySubmode == 0,
            "bad variant reply halts after the known kernel with uncertain controller state retained");
        Require(!result.BaselineMatched && result.ReadbackBytes == null && !f.policy.IsShortReadVerified
            && !result.ExitAcknowledged && !result.PostExitIdentityVerified && !Has(f.adapter, "6C10F020"),
            "no result, automatic exit or cleanup after mismatching raw frame");
        Require(f.policy.LastReceive != null && f.policy.LastReceive.Length == 76,
            "rejected data frame remains available as evidence");
        ZeroSubmodeUploadBoundary(f.adapter); Ownership(f.adapter, f.device);
    }

    static void AcknowledgedUploadBoundary(Fake adapter)
    {
        byte[] derived = IndependentKernel(true, true);
        Require(derived.Length == kernel.Length && Convert.ToHexString(SHA256.HashData(derived)).Equals(
            "eca54a2661baa317c02f96cd19a4e4bdac5a79a4c264f5154662e12e1c519664", StringComparison.OrdinalIgnoreCase),
            "independent acknowledgement fixture has the reviewed exact extent and hash");
        Require(Enumerable.Range(0, kernel.Length).Where(i => derived[i] != kernel[i]).All(i =>
            i == 0x92 || i == 0x93 || i == 0x7AE || i >= 0x794 && i < 0x7AA),
            "fixture changes only dispatch, owned metadata and the retained zero template");
        byte[][] uploads = adapter.Vpw.Where(v => v[3] == 0x36).ToArray();
        Require(uploads.Length == 2 && uploads[0].SequenceEqual(Block(derived, 1760, 267, 0xFF97E0, 0))
            && uploads[1].SequenceEqual(Block(derived, 0, 1760, 0xFF9100, 0x80)),
            "both changed RAM chunks carry exact independent payloads and regenerated checksums");
        Require(adapter.Vpw.Count(v => v[3] == 0x34) == 1 && adapter.CrcRequests == 0 && adapter.ConfigurationCommands == 0
            && !adapter.Vpw.Any(v => v[3] == 0x75), "ACK originates in scripted ECU, never a host transmit or configuration command");
    }

    static async Task AcknowledgedReadSuccess()
    {
        var f = await Fixture(shortRead: true, useZeroSubmodeKernel: true, prependReadAcknowledgement: true);
        var result = await f.session.RunAsync();
        Require(result.Success, result.Error ?? "expected acknowledged prefix success");
        Require(result.PrependReadAcknowledgement && result.ReadAcknowledgementObserved && result.ReadAcknowledgementHex == "6DF010750154"
            && result.UsesZeroSubmodeKernel && result.ReadReplySubmode == 0
            && result.EffectiveKernelSha256 == "eca54a2661baa317c02f96cd19a4e4bdac5a79a4c264f5154662e12e1c519664",
            "result records the exact derived asset and observed raw acknowledgement");
        Require(result.ReadbackScope == "baseline-prefix" && result.BaselineMatched && result.ReadbackLength == 64
            && result.ReadbackBytes!.SequenceEqual(baseline.Take(64)) && !result.ReadbackCrcVerified && !f.policy.IsImageVerified,
            "acknowledged data verifies only the requested prefix");
        Require(result.ExitAcknowledged && result.PostExitIdentityVerified && !result.BenchPowerCycleRequired && f.adapter.ReadRequests == 1,
            "only exact ACK plus data permits one normal explicit exit");
        AcknowledgedUploadBoundary(f.adapter); Ownership(f.adapter, f.device);
    }

    static async Task AcknowledgedReadFailure(string failure)
    {
        var f = await Fixture(failure, shortRead: true, useZeroSubmodeKernel: true, prependReadAcknowledgement: true);
        var result = await f.session.RunAsync();
        Require(!result.Success && result.Stage == AutoCalKernelProbeStage.ShortRead && result.KernelVersionVerified
            && result.BenchPowerCycleRequired && result.PrependReadAcknowledgement,
            "acknowledgement failure retains the uncertain controller state");
        Require(!result.ExitAcknowledged && !result.PostExitIdentityVerified && !Has(f.adapter, "6C10F020")
            && f.adapter.Vpw.Count(v => v.SequenceEqual(Hex("6C10F03C0A"))) == 1,
            "missing, wrong, repeated or early ACK cannot cause exit or post-exit identity");
        bool acceptedAck = failure == "ack-duplicate" || failure == "ack-trailing" || failure == "short-corrupt";
        Require(result.ReadAcknowledgementObserved == acceptedAck && result.ReadAcknowledgementHex == (acceptedAck ? "6DF010750154" : null),
            "accepted acknowledgement is retained even when a later phase fails");
        if (failure == "ack-trailing")
        {
            Require(result.BaselineMatched && result.ReadbackLength == 64 && f.policy.IsShortReadVerified,
                "valid prefix remains a partial observation when pending bytes block exit");
            Require(f.device.ReceivedMessageCount + f.device.Channel.BufferedByteCount + f.device.Channel.PendingByteCount > 0,
                "trailing acknowledgement bytes remain owned and unconsumed");
            Require(result.Error!.Contains("Pending bytes remain"), "failure identifies the sampled buffer boundary");
        }
        else
        {
            Require(!result.BaselineMatched && result.ReadbackBytes == null && !f.policy.IsShortReadVerified,
                "no prefix result is inferred from incomplete or rejected exchange");
            Require(f.policy.LastReceive != null && (failure == "ack-missing" || failure == "short-corrupt"
                ? f.policy.LastReceive.Length == 76 : f.policy.LastReceive[3] == 0x75),
                "rejected original response remains available as evidence");
        }
        Require(f.adapter.ReadRequests == (failure == "ack-early" ? 0 : 1), "no read request retry follows any acknowledgement failure");
        AcknowledgedUploadBoundary(f.adapter); Ownership(f.adapter, f.device);
    }

    static async Task UnexpectedAcknowledgement()
    {
        var f = await Fixture("ack-unexpected", shortRead: true, useZeroSubmodeKernel: true);
        var result = await f.session.RunAsync();
        Require(!result.Success && !result.PrependReadAcknowledgement && !result.ReadAcknowledgementObserved
            && result.ReadAcknowledgementHex == null && !Has(f.adapter, "6C10F020"),
            "an unexpected75 cannot broaden the existing zero-only profile");
        Require(f.policy.LastReceive!.SequenceEqual(Hex("6DF010750154")), "unexpected acknowledgement raw bytes retained");
        ZeroSubmodeUploadBoundary(f.adapter); Ownership(f.adapter, f.device);
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
        bool partialConfiguration;
        public int DisposeCalls, ReadRequests, CrcRequests; public List<(ushort Command, byte[] Payload)> Commands = new(); public List<byte[]> Vpw = new();
        public int ConfigurationCommands, PartialConfigurationBytes;
        public readonly bool FullRead, ShortRead, RecordedReadSetup, ZeroSubmodeKernel, PrependReadAcknowledgement;
        public int PendingByteCount => input.Count;
        public Fake(byte[] kernel, string failure, CancellationTokenSource? cancel, bool fullRead, bool shortRead, bool recordedReadSetup, bool zeroSubmodeKernel, bool prependReadAcknowledgement)
        { image = kernel; this.failure = failure; this.cancel = cancel; FullRead = fullRead; ShortRead = shortRead; RecordedReadSetup = recordedReadSetup; ZeroSubmodeKernel = zeroSubmodeKernel; PrependReadAcknowledgement = prependReadAcknowledgement; }
        public void Enqueue(byte[] bytes) { foreach (byte b in bytes) input.Enqueue(b); }
        public Task<int> Read(byte[] buffer, int offset, int count, int timeoutMs, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); int n = Math.Min(count, Math.Min(97, input.Count));
            for (int i = 0; i < n; i++) buffer[offset + i] = input.Dequeue(); return Task.FromResult(n);
        }
        public Task<int> Write(byte[] buffer, int offset, int count, int timeoutMs, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (partialConfiguration) throw new IOException("Scripted failure after the first seven configuration bytes.");
            int n = Math.Min(113, count);
            if (failure == "config-partial" && offset == 0 && count >= 18 && buffer[2] == 4 && buffer[3] == 0x86 && buffer[12] == 1)
            { n = 7; partialConfiguration = true; PartialConfigurationBytes = n; }
            output.AddRange(buffer.Skip(offset).Take(n));
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
                        int index = Commands.Count - 1;
                        if (index < 4)
                        {
                            var expected = new[] { (0x8201, ""), (0x8604, "00"), (0x8800, "0000"), (0x8604, "000000000000") };
                            if (command != expected[index].Item1 || !payload.SequenceEqual(Hex(expected[index].Item2))) throw new Exception("Unexpected initial setup command");
                            Enqueue(Packet(command, command == 0x8201 ? Hex("4143563200") : Array.Empty<byte>()));
                        }
                        else
                        {
                            var expected = new[] { (0x8603, "0100F401"), (0x8604, "010010000000"), (0x8604, "000000000000") };
                            if (!RecordedReadSetup || ConfigurationCommands >= expected.Length || command != expected[ConfigurationCommands].Item1
                                || !payload.SequenceEqual(Hex(expected[ConfigurationCommands].Item2))) throw new Exception("Unexpected session configuration or cleanup command");
                            if (ConfigurationCommands < 2 && (Vpw.Count != 1 || !Vpw[0].SequenceEqual(Hex("6C10F03C0A"))))
                                throw new Exception("Recorded preparation must immediately follow initial identity.");
                            if (ConfigurationCommands == 2 && !Vpw.Last().SequenceEqual(Hex("6C10F03D00")))
                                throw new Exception("Recorded restoration must immediately follow kernel version.");
                            ConfigurationCommands++;
                            bool error = failure == "config-error" && ConfigurationCommands == 1 || failure == "restore-error" && ConfigurationCommands == 3;
                            if (error) Enqueue(Packet(0xFF00, new byte[] { (byte)command, (byte)(command >> 8), 0, 0 }));
                            else Enqueue(Packet(command, Array.Empty<byte>()));
                            if (failure == "config-cancel" && ConfigurationCommands == 1 || failure == "restore-cancel" && ConfigurationCommands == 3)
                                cancel!.Cancel();
                        }
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
                case "6C10F03D01":
                    if (!FullRead && !ShortRead) throw new Exception("Flash ID requested outside read mode");
                    if (failure == "ack-early") { Enqueue(Packet(0x10, Hex("6DF010750154"))); return; }
                    reply = Hex(failure == "read-flash-id" ? "6CF0107D0100894472" : "6CF0107D0100894471"); break;
                case "6C10F020": reply = Hex("6CF01060"); break;
                default:
                    if (ShortRead && bytes.SequenceEqual(Hex("6D10F035010040000000")))
                    {
                        if (++ReadRequests != 1) throw new Exception("Repeated prefix request");
                        if (failure == "short-cancel") { cancel!.Cancel(); return; }
                        if (failure == "short-missing")
                        {
                            for (int i = 0; i < 5; i++) Enqueue(Packet(0x10, Hex("6CF0116800")));
                            return;
                        }
                        byte[] data = (byte[])baseline.Clone();
                        if (failure == "short-different") data[0] ^= 1;
                        byte submode = ZeroSubmodeKernel ? (byte)0 : (byte)1;
                        if (failure == "short-wrong-submode") submode = submode == 0 ? (byte)1 : (byte)0;
                        reply = Block(data, 0, 64, 0, submode); reply[1] = 0xF0; reply[2] = 0x10;
                        if (failure == "short-corrupt") reply[^1] ^= 1;
                        if (PrependReadAcknowledgement || failure == "ack-unexpected")
                        {
                            if (failure != "ack-missing") Enqueue(Packet(0x10, Hex(failure == "ack-wrong" ? "6DF010750155" : "6DF010750154")));
                            if (failure == "ack-duplicate") Enqueue(Packet(0x10, Hex("6DF010750154")));
                            Enqueue(Packet(0x10, reply));
                            if (failure == "ack-trailing") Enqueue(Packet(0x10, Hex("6DF010750154")));
                            return;
                        }
                    }
                    else if (FullRead && bytes.Length == 10 && bytes.AsSpan(0, 5).SequenceEqual(Hex("6D10F03501")))
                    {
                        int length = bytes[5] << 8 | bytes[6]; int address = bytes[7] << 16 | bytes[8] << 8 | bytes[9];
                        if (length != 4096 || address != ReadRequests * 4096 || address + length > baseline.Length) throw new Exception("Read coverage differs from fixed ascending blocks");
                        ReadRequests++;
                        if (failure == "read-cancel" && ReadRequests == 64) { cancel!.Cancel(); return; }
                        byte[] data = baseline;
                        if (failure == "read-different" && address == 0) { data = (byte[])baseline.Clone(); data[0] ^= 1; }
                        reply = Block(data, address, length, address, 1); reply[1] = 0xF0; reply[2] = 0x10;
                        if (failure == "read-corrupt") reply[^1] ^= 1;
                    }
                    else if (FullRead && bytes.Length == 11 && bytes.AsSpan(0, 5).SequenceEqual(Hex("6C10F03D02")))
                    {
                        // Golden replies from the independent GT full read log
                        // (baseline a3b010af...), not calculated by production Crc.
                        string[] replies = { "6CF0107D02020000060000D6703728", "6CF0107D0202000004000057DBDAAF", "6CF0107D020200000200004E3F92B0",
                            "6CF0107D02018000008000712EFE11", "6CF0107D0200200000600085B5BB36", "6CF0107D020020000040007D830D3E", "6CF0107D02004000000000CED58D53" };
                        if (CrcRequests >= replies.Length) throw new Exception("Unexpected repeated CRC request");
                        reply = Hex(replies[CrcRequests]); byte[] expected = reply.Take(11).ToArray(); expected[1] = 0x10; expected[2] = 0xF0; expected[3] = 0x3D;
                        if (!bytes.SequenceEqual(expected)) throw new Exception("CRC request order or range differs from independent GT log");
                        CrcRequests++;
                        if (failure == "read-crc-cancel" && CrcRequests == 7) { cancel!.Cancel(); return; }
                        if (failure == "read-crc" && CrcRequests == 4) reply[^1] ^= 1;
                    }
                    else if (bytes.SequenceEqual(Block(image, 1760, 267, 0xFF97E0, 0)))
                    {
                        if (failure == "cancel-copy") { cancel!.Cancel(); return; }
                        reply = Hex(failure == "copy" || failure == "unlocked-copy" ? "6CF010768078" : failure == "copy-unknown" ? "6CF010760000" : "6CF010760078");
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
                        reply = Hex(failure == "execute-unknown" ? "6CF010768000" : "6CF010768078");
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
