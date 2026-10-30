// SPDX-License-Identifier: GPL-3.0-only
// Linked production fixed profile/guard and production Device/Channel; no native transport.
using PcmHacking;
using System.Text.Json;

internal static class AutoCalProbeProfileTest
{
    private static int assertions;
    private static readonly List<string> passed = new();
    private static readonly List<object> failed = new();
    private static byte[] Hex(string text) => Convert.FromHexString(text);
    private static readonly string[] UsbGolden = {
        "0154018207000000000000008177", "01540486070000000000010000B6B9",
        "0154008807000000000002000000FDD5", "0154038607000000000004000100F4011218",
        "015404860700000000000600010010000000A871", "015404860700000000000600000000000000AD60",
        "0154018B070000000000040000010000D5AB", "0154018B070000000000040001010000D457" };
    private static readonly string[] IdentityGolden = {
        UsbGolden[0], UsbGolden[1], UsbGolden[2], UsbGolden[5],
        "0154008A07001000000005006C10F03C0AEB5F", UsbGolden[5], UsbGolden[6], UsbGolden[7] };
    // Saved receive envelopes from read12 record75 and failed-write record118;
    // fixture replay establishes framing/identity parsing, not live execution.
    private static readonly string[] IdentityReplies = {
        "0152100000001D0000000B006CF0107C0A00E7C434444EF5CF19",
        "0152100000000500000009006CF0107C0A00E7C434196919" };

    public static async Task<int> Main()
    {
        Run("exact closed command profiles", ExactProfiles);
        Run("identity prefix, extent and baseline checks", IdentityParser);
        Run("request guard refuses replay and changed payloads", GuardRejections);
        Run("request guard reconciles only exact partial suffix", PartialAccounting);
        Run("external profile arrays cannot alter allowlist", ProfileMutation);
        await RunAsync("production ordinary setup, one OS query and cleanup", ProductionIdentitySession);
        Console.WriteLine(JsonSerializer.Serialize(new { assertions, passed, failed,
            adapterOpened = false, liveWriteEnabled = false, physicalSpeedMeasured = false,
            scope = "Linked ProbeProfile/ExactRequestGuard plus production AutoCalDevice/AutoCalChannel; saved receive envelopes and scripted bytes only" }));
        return failed.Count == 0 ? 0 : 1;
    }
    private static void Run(string name, Action body)
    {
        try { body(); passed.Add(name); }
        catch (Exception error) { failed.Add(new { name, error = error.ToString() }); }
    }
    private static async Task RunAsync(string name, Func<Task> body)
    {
        try { await body(); passed.Add(name); }
        catch (Exception error) { failed.Add(new { name, error = error.ToString() }); }
    }
    private static void Require(bool value, string description)
    {
        assertions++; if (!value) throw new Exception(description);
    }
    private static void Reject(Action body, string description)
    {
        try { body(); }
        catch (InvalidOperationException) { assertions++; return; }
        throw new Exception("Expected guard rejection: " + description);
    }
    private static void BadIdentity(byte[] bytes, string description)
    {
        try { new ProbeProfile(true).ParseIdentity(bytes); }
        catch (InvalidDataException) { assertions++; return; }
        throw new Exception("Expected identity rejection: " + description);
    }
    private static void Finish(ExactRequestGuard guard, byte[] bytes)
    { guard.BeforeWrite(bytes, 0, bytes.Length); guard.CompleteWrite(bytes.Length); }
    private static ExactRequestGuard AtOsRequest()
    {
        var guard = new ExactRequestGuard(new ProbeProfile(true));
        foreach (string frame in IdentityGolden.Take(4)) Finish(guard, Hex(frame));
        return guard;
    }

    private static void ExactProfiles()
    {
        foreach (bool identity in new[] { false, true })
        {
            var profile = new ProbeProfile(identity);
            string[] golden = identity ? IdentityGolden : UsbGolden;
            Require(profile.Requests.Length == 8, "each fixed profile has8commands");
            for (int i = 0; i < golden.Length; i++)
                Require(profile.Requests[i].SequenceEqual(Hex(golden[i])), "exact full frame at ordinal" + i);
            var guard = new ExactRequestGuard(profile);
            foreach (string frame in golden) Finish(guard, Hex(frame));
            Require(guard.CommandsStarted == 8, "all commands accounted once");
            Require(guard.VpwPayloadCommandsStarted == (identity ? 1 : 0)
                && guard.VpwPayloadCommandsCompleted == (identity ? 1 : 0), "only identity profile admits oneVPWpayload");
            Reject(() => Finish(guard, Hex(golden[0])), "sequence cannot restart after completion");
        }
        var ordinary = new ProbeProfile(true);
        Require(ordinary.Setup == AutoCalSetupProfile.RecordedOrdinaryIdentification, "identity uses recorded ordinary profile");
        Require(ordinary.CreateOsRequest().GetBytes().SequenceEqual(Hex("6C10F03C0A")), "production OS request pinned");
        Reject(() => new ProbeProfile(false).CreateOsRequest(), "USB-only profile cannot create VPW query");
    }

    private static void IdentityParser()
    {
        var profile = new ProbeProfile(true);
        foreach (string payload in new[] { "6CF0107C0A00E7C434", "6CF0107C0A00E7C434444E", "6CF0107C0A00E7C434A5C7" })
            Require(profile.ParseIdentity(Hex(payload)) == 15189044, "9/11byte OS reply with opaque suffix accepted");
        byte[] original = Hex("6CF0107C0A00E7C434444E"), copy = (byte[])original.Clone();
        profile.ParseIdentity(original); Require(copy.SequenceEqual(original), "parser preserves original opaque suffix");
        foreach (string unrelated in new[] { "", "6CF0107C", "6CF0117C0A00E7C434", "6CF1107C0A00E7C434",
            "6CF0107C0B00E7C434", "8CF0107C0A00E7C434", "6CF0106000" })
            Require(profile.ParseIdentity(Hex(unrelated)) == null, "wrong source/destination/block/service does not identify");
        foreach (string invalid in new[] { "6CF0107C0A", "6CF0107C0A00E7C4", "6CF0107C0A00E7C43400",
            "6CF0107C0A00E7C434000000", "6CF0107C0A00E7C435", "6CF0107C0AFFFFFFFF", "6CF0107F3C12" })
            BadIdentity(Hex(invalid), "malformed, changed OS or negative response");
    }

    private static void GuardRejections()
    {
        byte[] os = Hex(IdentityGolden[4]);
        Reject(() => new ExactRequestGuard(new ProbeProfile(true)).BeforeWrite(os, 0, os.Length), "unsolicited8A00before setup");
        var usb = new ExactRequestGuard(new ProbeProfile(false));
        foreach (string f in UsbGolden.Take(4)) Finish(usb, Hex(f));
        Reject(() => usb.BeforeWrite(os, 0, os.Length), "USB-only sequence disallows8A00");
        byte[][] changed = {
            AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, Hex("6C10F03C0B")),
            AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, Hex("6C18F03C0A")),
            AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, Hex("6C10F02701")),
            AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, Hex("6CFEF0A1")),
            AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, Array.Empty<byte>()),
            AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0, Hex("6C10F03C0A")),
            AutoCalHostFrame.EncodeLongHeader(0x8A00, 8, 0x10, Hex("6C10F03C0A")) };
        foreach (byte[] packet in changed)
            Reject(() => AtOsRequest().BeforeWrite(packet, 0, packet.Length), "different valid-CRC command/payload/header");
        var once = AtOsRequest(); Finish(once, os);
        Reject(() => once.BeforeWrite(os, 0, os.Length), "completed OS query cannot repeat");
        var uncertain = AtOsRequest(); uncertain.BeforeWrite(os, 0, os.Length);
        Reject(() => uncertain.BeforeWrite(os, 0, os.Length), "pending write cannot replay");
    }

    private static void PartialAccounting()
    {
        byte[] os = Hex(IdentityGolden[4]);
        var guard = AtOsRequest(); guard.BeforeWrite(os, 0, os.Length); guard.CompleteWrite(3);
        Require(guard.VpwPayloadCommandsStarted == 1 && guard.VpwPayloadCommandsCompleted == 0, "partial write does not claim completion");
        Reject(() => guard.BeforeWrite(os, 0, os.Length), "partial command cannot restart");
        Reject(() => guard.BeforeWrite(os, 4, os.Length - 4), "suffix cannot skip a byte");
        byte[] changed = (byte[])os.Clone(); changed[5] ^= 1;
        Reject(() => guard.BeforeWrite(changed, 3, os.Length - 3), "caller buffer mutation rejected");
        guard.BeforeWrite(os, 3, os.Length - 3); guard.CompleteWrite(os.Length - 3);
        Require(guard.VpwPayloadCommandsStarted == 1 && guard.VpwPayloadCommandsCompleted == 1, "suffix finishes original command once");
        Reject(() => guard.CompleteWrite(1), "completion without pending call rejected");
        foreach (int invalid in new[] { -1, os.Length + 1 })
        {
            var bad = AtOsRequest(); bad.BeforeWrite(os, 0, os.Length);
            Reject(() => bad.CompleteWrite(invalid), "impossible completion count");
            Reject(() => bad.BeforeWrite(os, 0, os.Length), "uncertain invalid completion cannot reopen writes");
        }
    }

    private static void ProfileMutation()
    {
        var profile = new ProbeProfile(true);
        byte[][] exposed = profile.Requests;
        exposed[4][16] = 0x0B;
        exposed[0] = Hex(IdentityGolden[4]);
        Require(profile.Requests[0].SequenceEqual(Hex(IdentityGolden[0]))
            && profile.Requests[4].SequenceEqual(Hex(IdentityGolden[4])), "profile exposes defensive copies");
        var guard = new ExactRequestGuard(profile);
        foreach (string frame in IdentityGolden) Finish(guard, Hex(frame));
        Require(guard.VpwPayloadCommandsCompleted == 1, "guard still pins original allowed request after attempted mutation");
    }

    private static async Task ProductionIdentitySession()
    {
        foreach (string replyFixture in IdentityReplies)
        {
            var profile = new ProbeProfile(true);
            using var transport = new Script(profile, Hex(replyFixture));
            using var device = new AutoCalDevice(new AutoCalChannel(transport), new QuietLog(), default, profile.Setup);
            Require(await device.Initialize(), "production ordinary profile initializes");
            Require(transport.Completed == 4, "ordinary profile uses4startup commands, no8603or pollsetup");
            Require(device.AdapterSetupAccepted && !device.Supports4X && !device.HardwareProgrammingQualified,
                "setup acceptance makes no speed/programming claim");
            Require(await device.SendMessage(profile.CreateOsRequest()), "one fixed OS query submitted");
            int writes = transport.WriteCalls;
            Message message = await device.ReceiveMessage();
            Require(profile.ParseIdentity(message.GetBytes()) == ProbeProfile.ExpectedOperatingSystem,
                "saved9/11byte identity traverses production channel/device");
            Require(transport.WriteCalls == writes, "OS response receive performs no transmit");
            await device.StopRecordedSessionAsync();
            Require(transport.Completed == 8 && transport.Guard.VpwPayloadCommandsCompleted == 1,
                "whole ordinary-profile session emits exact8commands with oneVPWquery");
            Require(transport.PendingByteCount == 0 && !device.AdapterSetupAccepted, "recorded cleanup consumes replies and stops session");
        }
    }

    private sealed class Script : IAutoCalByteTransport
    {
        private readonly Queue<byte> inbound = new();
        private readonly byte[] identityReply;
        private int offset;
        public int Completed, WriteCalls;
        public ExactRequestGuard Guard { get; }
        public Script(ProbeProfile profile, byte[] identityReply) { Guard = new(profile); this.identityReply = identityReply; }
        public int PendingByteCount => inbound.Count;
        public Task<int> Write(byte[] bytes, int at, int count, int timeoutMs, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); WriteCalls++;
            Guard.BeforeWrite(bytes, at, count);
            byte[] golden = Hex(IdentityGolden[Completed]);
            if (!bytes.SequenceEqual(golden) || at != offset || count != golden.Length - offset)
                throw new InvalidOperationException("Production device bytes differ from independent saved/golden sequence.");
            int size = Math.Min(count, 3); offset += size; Guard.CompleteWrite(size);
            if (offset == golden.Length)
            {
                byte[] response = Completed switch {
                    0 => Hex("015201820000000000000500414356320026B419"),
                    2 => Hex("01520088000001000000010000FC8419"),
                    4 => identityReply,
                    6 or 7 => Hex("0152018B000001000000010001C9B719"),
                    _ => Hex("015204860000000000000000FCC919") };
                foreach (byte value in response) inbound.Enqueue(value);
                Completed++; offset = 0;
            }
            return Task.FromResult(size);
        }
        public Task<int> Read(byte[] buffer, int at, int count, int timeoutMs, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); int size = Math.Min(count, Math.Min(2, inbound.Count));
            for (int i = 0; i < size; i++) buffer[at + i] = inbound.Dequeue();
            return Task.FromResult(size);
        }
        public void Dispose() { }
    }
    private sealed class QuietLog : ILogger
    {
        public void AddUserMessage(string message) { }
        public void AddDebugMessage(string message) { }
        public void StatusUpdateActivity(string activity) { }
        public void StatusUpdateTimeRemaining(string remaining) { }
        public void StatusUpdatePercentDone(string percent) { }
        public void StatusUpdateRetryCount(string retries) { }
        public void StatusUpdateProgressBar(double completed, bool visible) { }
        public void StatusUpdateKbps(string kbps) { }
        public void StatusUpdateReset() { }
    }
}
