// SPDX-License-Identifier: GPL-3.0-only
// Pure policy + production Protocol generator. No transport or adapter access.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using PcmHacking;

internal static partial class AutoCalKernelProbePolicyTest
{
    private static byte[] kernel = Array.Empty<byte>();
    private static int assertions;
    private static readonly List<string> passed = new();
    private static readonly List<object> failed = new();
    private static byte[] Hex(string value) => Convert.FromHexString(value);
    private static AutoCalKernelProbePolicy New() => new(kernel);
    private static void Require(bool condition, string reason)
    { assertions++; if (!condition) throw new Exception(reason); }
    private static void Reject(Action action, string reason)
    {
        try { action(); }
        catch (InvalidOperationException) { assertions++; return; }
        catch (InvalidDataException) { assertions++; return; }
        throw new Exception("Expected rejection: " + reason);
    }
    private static void Run(string name, Action action)
    {
        try { action(); passed.Add(name); }
        catch (Exception error) { failed.Add(new { name, error = error.ToString() }); }
    }
    public static int Main(string[] args)
    {
        string path = args.Length == 0 ? AutoCalKernelProbePolicy.DefaultKernelPath : args[0];
        try { kernel = File.ReadAllBytes(path); }
        catch (Exception error) { Console.Error.WriteLine(error); return 2; }
        Run("pinned asset and production upload-plan equivalence", PlanAndPin);
        Run("complete positive-seed session and exact provenance", CompletePositive);
        Run("unknown copy suffix is observable but cannot authorize execution", ZeroSeed);
        Run("wrong identity and malformed security responses fail closed", InvalidIdentitySecurity);
        Run("flash erase/read/copy/speed/DTC and modified RAM bytes refused", ForbiddenRequests);
        Run("uncertain command cannot replay or skip phase", ReplayAndOrdering);
        Run("correlated response validation and unrelated preservation", Responses);
        Run("caller mutation cannot change pin or authorization", DefensiveCopies);
        Run("bounded notification allowance", NotificationBudget);
        Run("host guard binds exact payload metadata and one fresh authorization", HostAuthorization);
        Run("host guard exact setup and completion-gated cleanup", HostSetupCleanup);
        Run("host guard owns partial command without consuming authorization twice", HostPartialWrites);
        Run("copy-only host boundary stops before execute version and cleanup", CopyOnlyBoundary);
        Run("full-read plan matches pinned baseline and actual GT blocks", FullReadSourcePins);
        Run("full-read exact image seven CRC ranges and restoration", FullReadSuccess);
        Run("full-read requests cannot skip replay change length or write flash", FullReadRequestRestrictions);
        Run("full-read rejects malformed blocks before accepting coverage", FullReadMalformedResponses);
        Run("full-read image SHA mismatch cannot reach CRC or exit", FullReadBaselineMismatch);
        Run("full-read CRC response correlation and values are strict", FullReadCrcFailures);
        Run("full-read CRC polls and notifications have derived bounds", FullReadBudgets);
        Run("full-read host guard keeps cleanup behind entire verified read", FullReadHostBoundary);
        Run("short read exact prefix preserves distinct full-image state", ShortReadSuccess);
        Run("short read rejects ambiguous mode alternate reads CRC and replay", ShortReadRequests);
        Run("short read rejects malformed blocks checksum and wrong baseline prefix", ShortReadResponses);
        Run("short read native host guard gates entire fixed prefix exchange", ShortReadHostBoundary);
        Run("recorded read configuration is bound to exact session phases", RecordedReadHostBoundary);
        Run("zero-submode variant changes one pinned data byte without changing input", ZeroSubmodePin);
        Run("zero-submode RAM upload uses exact effective bytes and recalculated checksum", ZeroSubmodeUpload);
        Run("zero-submode reply validates raw checksum exact prefix and explicit exit", ZeroSubmodeReply);
        Run("zero-submode option rejects other modes inputs submodes and extra operations", ZeroSubmodeRestrictions);
        Console.WriteLine(JsonSerializer.Serialize(new { assertions, passed, failed, kernelPath = path,
            kernelSha256 = AutoCalKernelProbePolicy.ExpectedKernelSha256,
            hardwareAccess = false, liveWriteEnabled = false, hardwareQualificationClaimedByThisRun = false,
            scope = "Pinned-file plan and fail-closed VPW policy; production Protocol generation; no native transport" }));
        return failed.Count == 0 ? 0 : 1;
    }
    private static void Tx(AutoCalKernelProbePolicy policy, string hex) => policy.BeforeTransmit(Hex(hex));
    private static void Rx(AutoCalKernelProbePolicy policy, string hex) => policy.ObserveReceive(Hex(hex));
    private static AutoCalKernelProbePolicy Identified()
    {
        var p = New(); Tx(p, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434444E"); return p;
    }
    private static AutoCalKernelProbePolicy Unlocked()
    {
        var p = Identified(); Tx(p, "6C10F02701"); Rx(p, "6CF01067010000"); return p;
    }
    private static AutoCalKernelProbePolicy CopyReady()
    {
        var p = Unlocked(); p.BeforeTransmit(p.UploadPermissionMessage); Rx(p, "6CF010740044"); return p;
    }
    private static AutoCalKernelProbePolicy Executed()
    {
        var p = CopyReady(); p.BeforeTransmit(p.UploadMessages[0]); Rx(p, "6CF010760078");
        p.BeforeTransmit(p.UploadMessages[1]); Rx(p, "6CF010768078"); return p;
    }
    private static AutoCalKernelProbePolicy Verified()
    {
        var p = Executed(); Tx(p, "6C10F03D00"); Rx(p, "6CF0107D006AB178EC36"); return p;
    }
    private static void PlanAndPin()
    {
        var p = New(); var info = new OSIDInfo(15189044); var protocol = new Protocol();
        Require(kernel.Length == 2027 && info.HardwareType == PcmType.E54 && !info.LoaderRequired, "known E54 no-loader asset");
        Require(p.UploadPermissionMessage.SequenceEqual(protocol.CreateUploadRequest(info, 2027).GetBytes()), "uses production upload request");
        byte[][] messages = p.UploadMessages;
        Require(messages.Length == 2 && messages[0].Length == 279 && messages[1].Length == 1772, "observed1772 TX cap yields two packets");
        Require(messages[0].SequenceEqual(protocol.CreateBlockMessage(kernel, 1760, 267, 0xFF97E0, BlockCopyType.Copy).GetBytes()), "high RAM copy generated by production Protocol");
        Require(messages[1].SequenceEqual(protocol.CreateBlockMessage(kernel, 0, 1760, 0xFF9100, BlockCopyType.Execute).GetBytes()), "base RAM execute generated by production Protocol");
        Require(messages[1].Skip(10).Take(1760).Concat(messages[0].Skip(10).Take(267)).SequenceEqual(kernel), "two packet payloads reconstruct exact pinned asset");
        foreach (byte[] packet in messages)
        {
            int n = (packet[5] << 8) | packet[6];
            Require(VpwUtilities.CalcBlockChecksum(packet) == ((packet[n + 10] << 8) | packet[n + 11]), "production checksum matches each exact frame");
        }
        byte[] changed = (byte[])kernel.Clone(); changed[35] ^= 1;
        Reject(() => new AutoCalKernelProbePolicy(changed), "same-length changed kernel");
        Reject(() => new AutoCalKernelProbePolicy(kernel[..^1]), "truncated kernel");
    }
    private static void CompletePositive()
    {
        var p = Identified(); Tx(p, "6CFEF02800"); Tx(p, "8CFEF03F"); Rx(p, "8CF0106800");
        Tx(p, "6C10F02701"); Rx(p, "6CF010670143B1");
        // Actual earlier GT read seed/key pair, checked against production algorithm54.
        Require(KeyAlgorithm.GetKey(54, 0x43B1) == 0x7C21, "pinned actual seed/key vector");
        Tx(p, "6C10F027027C21"); Rx(p, "6CF010670234");
        p.BeforeTransmit(p.UploadPermissionMessage); Rx(p, "6CF010740044");
        p.BeforeTransmit(p.UploadMessages[0]); Rx(p, "6CF010760078");
        p.BeforeTransmit(p.UploadMessages[1]); Rx(p, "6CF010768078");
        Require(!p.IsKernelVerified, "RAM ACK is not execution proof");
        Tx(p, "6C10F03D00"); Rx(p, "6CF0107D006AB178EC36");
        Require(p.IsKernelVerified, "exact version proves expected kernel answered");
        Tx(p, "6C10F020"); Rx(p, "6CF01060");
        Require(p.IsExitConfirmed && !p.IsPostExitIdentityVerified, "exit ACK alone is not restored ROM proof");
        Tx(p, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434A5C7");
        Require(p.IsPostExitIdentityVerified && p.CurrentPhase == "Complete" && p.Failure == null, "complete bounded session");
        Require(p.SeedAttempts == 1 && p.KeyAttempts == 1 && p.RamCopyAttempts == 1 && p.RamExecuteAttempts == 1, "once-only operation attempts");
        Require(p.AuthorizedTransmitCount == 11 && p.LastAuthorizedTransmit!.SequenceEqual(Hex("6C10F03C0A")), "hostguard handoff pin and ordinal");
        Require(p.UnrelatedReceiveCount == 1, "suppression response preserved as unrelated");
        Require(p.PostExitIdentityReply!.SequenceEqual(Hex("6CF0107C0A00E7C434A5C7")), "opaque OS suffix preserved");
        Reject(() => Tx(p, "6C10F020"), "no reset replay after completion");
    }
    private static void ZeroSeed()
    {
        var p = Unlocked(); Require(p.KeyAttempts == 0 && p.CurrentPhase == "UploadPermission", "zero seed skips key");
        p.BeforeTransmit(p.UploadPermissionMessage); Rx(p, "6CF010740044");
        p.BeforeTransmit(p.UploadMessages[0]); Rx(p, "6CF0107600FF");
        Require(p.RamCopyAcknowledgement![5] == 0xFF && !p.IsKernelVerified, "opaque copy suffix retained, not execution status");
        int count = p.AuthorizedTransmitCount;
        Reject(() => p.BeforeTransmit(p.UploadMessages[1]), "unobserved copy suffix cannot authorize execution");
        Require(p.AuthorizedTransmitCount == count && p.RamExecuteAttempts == 0,
            "unqualified Copy reply stops before host Execute authorization");
        foreach (byte suffix in new byte[] { 0, 0xAB, 0xFF })
        {
            var q = CopyReady(); q.BeforeTransmit(q.UploadMessages[0]); Rx(q, "6CF010760078");
            q.BeforeTransmit(q.UploadMessages[1]);
            Reject(() => q.ObserveReceive(new byte[] { 0x6C, 0xF0, 0x10, 0x76, 0x80, suffix }), "unobserved Execute suffix");
            Require(q.RamExecuteAcknowledgement![5] == suffix && !q.IsKernelVerified,
                "failed Execute evidence retained without execution proof");
            Reject(() => Tx(q, "6C10F03D00"), "wrong Execute reply cannot advance to version query");
        }
    }
    private static void InvalidIdentitySecurity()
    {
        foreach (string bad in new[] { "6CF0107C0A00E7C435", "6CF0107C0B00E7C434", "6CF0107C0A00E7C43400", "6CF0107F3C12" })
        { var p = New(); Tx(p, "6C10F03C0A"); Reject(() => Rx(p, bad), bad); Require(p.Failure != null && !p.IsInitialIdentityVerified, "identity rejects fail closed"); }
        foreach (string bad in new[] { "6CF0106701", "6CF010670137", "6CF0106701FFFF", "6CF0106701000000", "6CF01067021234", "6CF0107F2733" })
        { var p = Identified(); Tx(p, "6C10F02701"); Reject(() => Rx(p, bad), bad); }
        var key = Identified(); Tx(key, "6C10F02701"); Rx(key, "6CF010670143B1");
        Reject(() => Tx(key, "6C10F027020000"), "wrong key rejected before transport");
        foreach (string bad in new[] { "6CF010670233", "6CF01067023400", "6CF010670134" })
        { var p = Identified(); Tx(p, "6C10F02701"); Rx(p, "6CF010670143B1"); Tx(p, "6C10F027027C21"); Reject(() => Rx(p, bad), bad); }
    }
    private static void ForbiddenRequests()
    {
        foreach (string request in new[] { "6C10F03D05008000", "6D10F035010010000000", "6CFEF0A0", "6CFEF0A1", "686AF004", "8CFEF014", "6C10F03D01", "6C10F03D02010000000000", "6C10F03D09494D4F42" })
        { var p = Verified(); Reject(() => Tx(p, request), request); Require(p.IsKernelVerified && p.Failure != null, "retain completed proof while refusing disallowed operation"); }
        foreach (int at in new[] { 0, 1, 2, 4, 5, 7, 9, 10, 50, 278 })
        { var p = CopyReady(); byte[] request = p.UploadMessages[0]; request[at] ^= 1; Reject(() => p.BeforeTransmit(request), "changed packet byte" + at); }
        var flash = CopyReady();
        byte[] flashPacket = new Protocol().CreateBlockMessage(kernel, 1760, 267, 0x008000, BlockCopyType.Copy).GetBytes();
        Reject(() => flash.BeforeTransmit(flashPacket), "checksum-valid same bytes at flash address");
    }
    private static void ReplayAndOrdering()
    {
        var initial = New(); Tx(initial, "6C10F03C0A"); Reject(() => Tx(initial, "6C10F03C0A"), "identity retry");
        Require(initial.AuthorizedTransmitCount == 1, "blocked request does not authorize host write");
        var copy = CopyReady(); byte[] message = copy.UploadMessages[0]; copy.BeforeTransmit(message);
        Reject(() => copy.BeforeTransmit(message), "uncertain copy retry");
        Reject(() => Tx(copy, "8CFEF03F"), "no transmissions after policy fault");
        var early = CopyReady(); Reject(() => early.BeforeTransmit(early.UploadMessages[1]), "execute before high RAM copy ACK");
        var execute = CopyReady(); execute.BeforeTransmit(execute.UploadMessages[0]); Rx(execute, "6CF010760078"); execute.BeforeTransmit(execute.UploadMessages[1]);
        Reject(() => execute.BeforeTransmit(execute.UploadMessages[1]), "uncertain execute cannot replay");
        var version = Executed(); Tx(version, "6C10F03D00"); Reject(() => Tx(version, "6C10F03D00"), "bounded version request");
    }
    private static void Responses()
    {
        var p = New(); Tx(p, "6C10F03C0A");
        foreach (string unrelated in new[] { "", "6C", "6CF0187C0A00E7C434", "6CF0106800", "6CF0107F3F12" }) Rx(p, unrelated);
        Require(p.UnrelatedReceiveCount == 5 && !p.IsInitialIdentityVerified, "unrelated traffic cannot establish identity");
        Rx(p, "6CF0107C0A00E7C434"); Require(p.IsInitialIdentityVerified, "valid reply can follow unrelated traffic");
        foreach (string bad in new[] { "6CF010740000", "6CF010740044AA", "6CF0107F3433" })
        { var q = Unlocked(); q.BeforeTransmit(q.UploadPermissionMessage); Reject(() => Rx(q, bad), "permission" + bad); }
        foreach (string bad in new[] { "6CF0107600", "6CF010768078", "6CF010760078AA", "6CF0107F3600" })
        { var q = CopyReady(); q.BeforeTransmit(q.UploadMessages[0]); Reject(() => Rx(q, bad), "copy" + bad); }
        foreach (string bad in new[] { "6CF0107D006AB178EC35", "6CF0107D006AB178EC", "6CF0107D006AB178EC36AA", "6CF0107D016AB178EC36" })
        { var q = Executed(); Tx(q, "6C10F03D00"); Reject(() => Rx(q, bad), "kernel" + bad); Require(!q.IsKernelVerified, "wrong version cannot qualify"); }
        var exit = Verified(); Tx(exit, "6C10F020"); Reject(() => Rx(exit, "6CF0106000"), "exit malformed");
    }
    private static void DefensiveCopies()
    {
        byte[] supplied = (byte[])kernel.Clone(); var p = new AutoCalKernelProbePolicy(supplied); supplied[0] ^= 1;
        p.KernelBytes[0] ^= 1; p.UploadMessages[0][0] ^= 1; p.UploadPermissionMessage[0] ^= 1;
        Require(p.KernelBytes.SequenceEqual(kernel), "caller cannot change pinned kernel");
        byte[] request = Hex("6C10F03C0A"); p.BeforeTransmit(request); request[0] ^= 1;
        p.LastAuthorizedTransmit![0] ^= 1;
        Require(p.LastAuthorizedTransmit!.SequenceEqual(Hex("6C10F03C0A")), "authorization snapshot cannot mutate");
        byte[] reply = Hex("6CF0107C0A00E7C434444E"); p.ObserveReceive(reply); reply[0] ^= 1; p.LastReceive![0] ^= 1;
        Require(p.InitialIdentityReply!.SequenceEqual(Hex("6CF0107C0A00E7C434444E")), "identity evidence defensive copy");
    }
    private static void NotificationBudget()
    {
        var p = Identified();
        for (int i = 0; i < AutoCalKernelProbePolicy.MaximumToolPresentAttempts; i++) Tx(p, "8CFEF03F");
        Require(p.ToolPresentAttempts == 32 && p.AuthorizedTransmitCount == 33, "count notification attempts");
        Reject(() => Tx(p, "8CFEF03F"), "bounded notification flood");
        var early = New(); Reject(() => Tx(early, "8CFEF03F"), "no notifier before identity");
    }

    private static void HostFinish(RequestWriteGuard guard, byte[] frame)
    { guard.BeforeWrite(frame, 0, frame.Length); guard.CompleteWrite(frame.Length); }
    private static KernelRequestGuard HostReady(AutoCalKernelProbePolicy policy, bool copyOnly = false)
    {
        var guard = new KernelRequestGuard(policy, copyOnly);
        foreach (byte[] frame in new ProbeProfile(true).Requests.Take(4)) HostFinish(guard, frame);
        return guard;
    }
    private static void HostTx(AutoCalKernelProbePolicy p, KernelRequestGuard g, byte[] bytes)
    { p.BeforeTransmit(bytes); HostFinish(g, AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, bytes)); }
    private static void HostTx(AutoCalKernelProbePolicy p, KernelRequestGuard g, string hex) => HostTx(p, g, Hex(hex));
    private static void HostComplete(AutoCalKernelProbePolicy p, KernelRequestGuard g, bool forwardFinal = true)
    {
        HostTx(p, g, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434444E");
        HostTx(p, g, "6C10F02701"); Rx(p, "6CF01067010000");
        HostTx(p, g, p.UploadPermissionMessage); Rx(p, "6CF010740044");
        HostTx(p, g, p.UploadMessages[0]); Rx(p, "6CF010760078");
        HostTx(p, g, p.UploadMessages[1]); Rx(p, "6CF010768078");
        HostTx(p, g, "6C10F03D00"); Rx(p, "6CF0107D006AB178EC36");
        HostTx(p, g, "6C10F020"); Rx(p, "6CF01060");
        if (forwardFinal) HostTx(p, g, "6C10F03C0A"); else Tx(p, "6C10F03C0A");
        Rx(p, "6CF0107C0A00E7C434444E");
    }
    private static void HostAuthorization()
    {
        byte[] os = Hex("6C10F03C0A");
        foreach (byte[] frame in new[] {
            AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0, os),
            AutoCalHostFrame.EncodeLongHeader(0x8A00, 8, 0x10, os),
            AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, Hex("6C10F03C0B")),
            AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, Hex("6C10F03D05008000")),
            AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, Array.Empty<byte>()) })
        {
            var p = New(); var g = HostReady(p); p.BeforeTransmit(os);
            Reject(() => HostFinish(g, frame), "changed host metadata/selector/VPW payload");
            Require(g.VpwPayloadCommandsStarted == 0, "denial precedes native command accounting");
        }
        var unauthorized = New(); var ug = HostReady(unauthorized);
        Reject(() => HostFinish(ug, AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, os)), "raw host command has no policy authorization");
        var once = New(); var og = HostReady(once); HostTx(once, og, os);
        Reject(() => HostFinish(og, AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, os)), "completed authorization cannot replay");
        var gap = New(); var gg = HostReady(gap); HostTx(gap, gg, os); Rx(gap, "6CF0107C0A00E7C434");
        Tx(gap, "8CFEF03F"); Tx(gap, "6C10F02701");
        Reject(() => HostFinish(gg, AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, Hex("6C10F02701"))), "cannot skip unconsumed authorization");
        var bad = New(); var bg = HostReady(bad); Tx(bad, "6C10F03C0A");
        Reject(() => Tx(bad, "6CFEF0A1"), "fault policy before native send");
        Reject(() => HostFinish(bg, AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, os)), "faulted policy voids unconsumed command");
    }
    private static void HostSetupCleanup()
    {
        byte[][] frames = new ProbeProfile(true).Requests;
        var early = new KernelRequestGuard(New()); Reject(() => HostFinish(early, frames[1]), "cannot skip model query");
        var incomplete = New(); var ig = HostReady(incomplete);
        Reject(() => HostFinish(ig, frames[5]), "cleanup not allowed before successful kernel+exit+identity");
        var p = New(); var g = HostReady(p); HostComplete(p, g);
        Require(p.IsPostExitIdentityVerified && g.VpwPayloadCommandsCompleted == 8, "all8VPWcommands crossed guard");
        Reject(() => HostFinish(g, frames[6]), "cleanup order is exact");
        foreach (byte[] frame in frames.Skip(5)) HostFinish(g, frame);
        Require(g.CommandsStarted == 15 && g.VpwPayloadCommandsCompleted == 8, "4startup+8VPW+3cleanup complete");
        Reject(() => HostFinish(g, frames[0]), "cannot reopen after cleanup");
        var missing = New(); var mg = HostReady(missing); HostComplete(missing, mg, false);
        Reject(() => HostFinish(mg, frames[5]), "cleanup cannot conceal unsent final OSID authorization");
    }
    private static void HostPartialWrites()
    {
        var p = New(); var g = HostReady(p); Tx(p, "6C10F03C0A");
        byte[] frame = AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, Hex("6C10F03C0A"));
        g.BeforeWrite(frame, 0, frame.Length); g.CompleteWrite(3);
        Require(g.VpwPayloadCommandsStarted == 1 && g.VpwPayloadCommandsCompleted == 0, "partial frame remains one incomplete command");
        Reject(() => g.BeforeWrite(frame, 0, frame.Length), "partial command cannot restart");
        Reject(() => g.BeforeWrite(frame, 4, frame.Length - 4), "cannot skip partial suffix byte");
        byte[] changed = (byte[])frame.Clone(); changed[6] ^= 1;
        Reject(() => g.BeforeWrite(changed, 3, changed.Length - 3), "partial suffix cannot mutate metadata");
        g.BeforeWrite(frame, 3, frame.Length - 3); g.CompleteWrite(frame.Length - 3);
        Require(g.VpwPayloadCommandsCompleted == 1 && p.AuthorizedTransmitCount == 1, "exact suffix consumes no new authorization");
        Reject(() => g.CompleteWrite(1), "late duplicate completion rejected");
    }
    private static void CopyOnlyBoundary()
    {
        foreach (byte suffix in new byte[] { 0, 0x78, 0xFF })
        {
            var p = New(); var g = HostReady(p, true);
            HostTx(p, g, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434444E");
            HostTx(p, g, "6C10F02701"); Rx(p, "6CF01067010000");
            HostTx(p, g, p.UploadPermissionMessage); Rx(p, "6CF010740044");
            HostTx(p, g, p.UploadMessages[0]);
            p.ObserveReceive(new byte[] { 0x6C, 0xF0, 0x10, 0x76, 0x00, suffix });
            Require(g.VpwPayloadCommandsCompleted == 4 && p.RamCopyAttempts == 1 && p.RamExecuteAttempts == 0,
                "only identity/seed/permission/267-byte RAM copy crossed host boundary");
            Require(p.RamCopyAcknowledgement![5] == suffix && !p.IsKernelVerified && !p.IsExitConfirmed,
                "copy reply observed with opaque suffix; no execution or restoration proof");
            if (suffix != 0x78)
            {
                Reject(() => p.BeforeTransmit(p.UploadMessages[1]),
                    "unobserved copy suffix cannot authorize Execute even in full offline policy");
                Reject(() => HostFinish(g, AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, p.UploadMessages[1])),
                    "copy-only host boundary also refuses unqualified Execute");
                Require(g.VpwPayloadCommandsCompleted == 4 && p.RamExecuteAttempts == 0,
                    "unknown suffix observation remains copy-only");
                continue;
            }
            // Even though the offline full-session policy would permit its next
            // exact frame, live copy-only host scope blocks it before native I/O.
            byte[] execute = p.UploadMessages[1]; p.BeforeTransmit(execute);
            Reject(() => HostFinish(g, AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, execute)),
                "copy-only boundary independently rejects authorized Execute");
            p.ObserveReceive(Hex("6CF010768078")); Tx(p, "6C10F03D00");
            Reject(() => HostFinish(g, AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, Hex("6C10F03D00"))),
                "manual offline policy advancement cannot permit live version query");
            Rx(p, "6CF0107D006AB178EC36"); Tx(p, "6C10F020");
            Reject(() => HostFinish(g, AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, Hex("6C10F020"))),
                "copy-only cannot send reset even if policy state advanced");
            Rx(p, "6CF01060"); Tx(p, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434");
            Reject(() => HostFinish(g, new ProbeProfile(true).Requests[5]),
                "copy-only forbids adapter protocol cleanup after fabricated full-policy completion");
            Require(g.VpwPayloadCommandsCompleted == 4 && g.CommandsStarted == 8,
                "all attempted scope escapes stayed before native command accounting");
        }
        var notify = New(); var ng = HostReady(notify, true);
        HostTx(notify, ng, "6C10F03C0A"); Rx(notify, "6CF0107C0A00E7C434");
        HostTx(notify, ng, "6C10F02701"); Rx(notify, "6CF01067010000");
        HostTx(notify, ng, notify.UploadPermissionMessage); Rx(notify, "6CF010740044");
        HostTx(notify, ng, notify.UploadMessages[0]); Rx(notify, "6CF010760078");
        Tx(notify, "8CFEF03F");
        Reject(() => HostFinish(ng, AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, Hex("8CFEF03F"))),
            "even keepalive stops after copy reply observation");
    }

    private static void RecordedReadHostBoundary()
    {
        byte[] interval = AutoCalHostFrame.EncodeLongHeader(0x8603, 7, 0, Hex("0100F401"));
        byte[] mode = AutoCalHostFrame.EncodeLongHeader(0x8604, 7, 0, Hex("010010000000"));
        byte[] zero = new ProbeProfile(true).Requests[5];
        (AutoCalKernelProbePolicy p, KernelRequestGuard g) Begin(bool atKernel = false)
        {
            var p = new AutoCalKernelProbePolicy(kernel, shortRead: true);
            var g = new KernelRequestGuard(p, recordedReadSetup: true);
            foreach (byte[] frame in new ProbeProfile(true).Requests.Take(4)) HostFinish(g, frame);
            HostTx(p, g, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434");
            if (atKernel)
            {
                HostFinish(g, interval); HostFinish(g, mode);
                HostTx(p, g, "6C10F02701"); Rx(p, "6CF01067010000");
                HostTx(p, g, p.UploadPermissionMessage); Rx(p, "6CF010740044");
                HostTx(p, g, p.UploadMessages[0]); Rx(p, "6CF010760078");
                HostTx(p, g, p.UploadMessages[1]); Rx(p, "6CF010768078");
                HostTx(p, g, "6C10F03D00"); Rx(p, "6CF0107D006AB178EC36");
            }
            return (p, g);
        }
        var early = Begin();
        Reject(() => HostTx(early.p, early.g, "6C10F02701"), "cannot skip recorded preparation pair");
        var order = Begin();
        Reject(() => HostFinish(order.g, mode), "cannot reverse recorded pair");
        Reject(() => HostFinish(order.g, zero), "cannot substitute zero for preparation");
        order.g.BeforeWrite(interval, 0, interval.Length); order.g.CompleteWrite(3);
        Reject(() => order.g.BeforeWrite(interval, 0, interval.Length), "configuration partial frame cannot restart");
        order.g.BeforeWrite(interval, 3, interval.Length - 3); order.g.CompleteWrite(interval.Length - 3);
        Reject(() => HostFinish(order.g, interval), "completed interval configuration cannot replay");
        HostFinish(order.g, mode);
        Require(order.g.CommandsStarted == 7, "four setup one identity and two preparation commands");
        var skip = Begin(true);
        Reject(() => HostTx(skip.p, skip.g, "6C10F03D01"), "flash identity cannot skip post-kernel zero configuration");
        var success = Begin(true);
        Reject(() => HostFinish(success.g, mode), "post-kernel configuration cannot repeat active form");
        HostFinish(success.g, zero);
        Reject(() => HostFinish(success.g, zero), "post-kernel configuration cannot replay");
        HostTx(success.p, success.g, "6C10F03D01"); Rx(success.p, "6CF0107D0100894471");
        HostTx(success.p, success.g, ShortRequest); success.p.ObserveReceive(ShortReply());
        HostTx(success.p, success.g, "6C10F020"); Rx(success.p, "6CF01060");
        HostTx(success.p, success.g, "6C10F03C0A"); Rx(success.p, "6CF0107C0A00E7C434");
        foreach (byte[] frame in new ProbeProfile(true).Requests.Skip(5)) HostFinish(success.g, frame);
        Require(success.g.CommandsStarted == 20 && success.g.VpwPayloadCommandsCompleted == 10,
            "only three fixed adapter commands added; VPW unchanged");
        var ordinary = new AutoCalKernelProbePolicy(kernel, shortRead: true); var og = HostReady(ordinary);
        HostTx(ordinary, og, "6C10F03C0A"); Rx(ordinary, "6CF0107C0A00E7C434");
        Reject(() => HostFinish(og, interval), "ordinary profile cannot gain recorded configuration");
        bool rejected = false;
        try { new KernelRequestGuard(New(), recordedReadSetup: true); } catch (ArgumentException) { rejected = true; }
        Require(rejected, "configuration experiment cannot expand kernel-info or copy-only modes");
        rejected = false;
        try { new KernelRequestGuard(new AutoCalKernelProbePolicy(kernel, shortRead: true, useZeroSubmodeKernel: true), recordedReadSetup: true); }
        catch (ArgumentException) { rejected = true; }
        Require(rejected, "configuration and reply-template experiments cannot be combined");
    }
}
