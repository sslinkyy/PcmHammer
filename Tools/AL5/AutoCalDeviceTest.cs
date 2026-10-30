// SPDX-License-Identifier: GPL-3.0-only
// Production Device + Channel with an in-memory scripted adapter. No native
// library, device enumeration, USB access, or vehicle operation occurs here.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using PcmHacking;

internal static class AutoCalDeviceTest
{
    private static int assertions;
    private static readonly List<string> passed = new List<string>();
    private static readonly List<object> failed = new List<object>();
    private static byte[] Hex(string text) => Convert.FromHexString(text);
    private static readonly byte[] ModelPayload = Hex("4143563200");

    public static async Task<int> Main()
    {
        await Case("exact startup and no type3 protocol select", Startup);
        await Case("wrong model and pending startup refuse setup", StartupRefusals);
        await Case("error-marker status zero halts initialization and receive", ZeroStatusError);
        await Case("96 program payloads and 98 acknowledgements", SyntheticProgramming);
        await Case("receive-only, idle timeout and queued drain", ReceiveAndDrain);
        await Case("delayed setup echo cannot become a bus message", DelayedSetupEcho);
        await Case("receive and broadcast reject oversized payloads", Oversize);
        await Case("4x refused and recorded cleanup stops traffic", SpeedAndStop);
        await Case("dispose request blocks sends while I/O or cleanup remains owned", Disposal);
        await Case("recorded configuration lifecycle sends only the fixed commands once", RecordedConfiguration);
        await Case("recorded configuration requires initialized ordinary profile and empty queues", ConfigurationPreconditions);
        await Case("partial preparation and restore failures stop traffic without replay", ConfigurationFailures);
        await Case("configuration transition blocks interleaved device I/O", ConfigurationExclusion);
        await Case("disposal during preparation preserves ownership and blocks the second command", ConfigurationDisposal);
        await Case("cancellation during preparation halts without replay or implicit cleanup", ConfigurationCancellation);
        Console.WriteLine(JsonSerializer.Serialize(new {
            assertions, passed, failed, syntheticProgramFrames = 96, syntheticAcknowledgements = 98,
            adapterOpened = false, liveWriteEnabled = false, hardwareQualified = false,
            pcmLibraryAssembly = typeof(AutoCalDevice).Assembly.Location,
            scope = "Production AutoCalDevice/AutoCalChannel with scripted bytes only; no ECU behavior or flash recovery established"
        }));
        return failed.Count == 0 ? 0 : 1;
    }

    private static async Task Case(string name, Func<Task> action)
    {
        try { await action(); passed.Add(name); }
        catch (Exception error) { failed.Add(new { name, error = error.ToString() }); }
    }
    private static void Require(bool condition, string description)
    {
        assertions++;
        if (!condition) throw new Exception(description);
    }
    private static void Same(byte[] expected, byte[] actual, string description)
        => Require(expected.SequenceEqual(actual), description);
    private static async Task<T> Throws<T>(Func<Task> action, string description) where T : Exception
    {
        try { await action(); }
        catch (T error) { assertions++; return error; }
        throw new Exception("Expected " + typeof(T).Name + ": " + description);
    }

    // Independent fake-adapter framing, not the production encoder/parser.
    private static byte[] Packet(bool fromAdapter, uint headerField, byte[] payload, uint metadata = 0)
    {
        byte[] result = new byte[payload.Length + (fromAdapter ? 15 : 14)];
        result[0] = 1; result[1] = fromAdapter ? (byte)0x52 : (byte)0x54;
        for (int i = 0; i < 4; i++) result[2 + i] = (byte)(headerField >> (8 * i));
        if (!fromAdapter) result[4] = 7;
        for (int i = 0; i < 4; i++) result[6 + i] = (byte)(metadata >> (8 * i));
        result[10] = (byte)payload.Length; result[11] = (byte)(payload.Length >> 8);
        Array.Copy(payload, 0, result, 12, payload.Length);
        ushort crc = 0;
        for (int i = 0; i < payload.Length + 12; i++)
        {
            crc ^= result[i];
            for (int bit = 0; bit < 8; bit++) crc = (ushort)((crc & 1) == 0 ? crc >> 1 : (crc >> 1) ^ 0xA001);
        }
        result[payload.Length + 12] = (byte)crc;
        result[payload.Length + 13] = (byte)(crc >> 8);
        if (fromAdapter) result[result.Length - 1] = 0x19;
        return result;
    }
    private static byte[] Tx(ushort command, byte[] payload, uint metadata = 0) => Packet(false, command, payload, metadata);
    private static byte[] Rx(uint field, byte[] payload) => Packet(true, field, payload);
    private static byte[] Error(ushort command, ushort status) => Rx(0xFF00,
        new byte[] { (byte)command, (byte)(command >> 8), (byte)status, (byte)(status >> 8) });

    private static Script AdapterWithStartup(byte[]? model = null, bool firstSetupError = false, bool ordinary = false)
    {
        var adapter = new Script();
        adapter.Expect(Tx(0x8201, Array.Empty<byte>()), Rx(0x8201, model ?? ModelPayload));
        if (model != null && !model.SequenceEqual(ModelPayload)) return adapter;
        adapter.Expect(Tx(0x8604, new byte[] { 0 }), firstSetupError ? Error(0x8604, 0) : Rx(0x8604, Array.Empty<byte>()));
        if (firstSetupError) return adapter;
        adapter.Expect(Tx(0x8800, new byte[] { 0, 0 }), Rx(0x8800, Array.Empty<byte>()));
        if (ordinary) adapter.Expect(Tx(0x8604, new byte[6]), Rx(0x8604, Array.Empty<byte>()));
        else
        {
            adapter.Expect(Tx(0x8603, Hex("0100F401")), Rx(0x8603, Array.Empty<byte>()));
            adapter.Expect(Tx(0x8604, Hex("010010000000")), Rx(0x8604, Array.Empty<byte>()));
        }
        return adapter;
    }
    private static AutoCalDevice Device(Script adapter, bool ordinary = false) => new AutoCalDevice(new AutoCalChannel(adapter), new Log(),
        setupProfile: ordinary ? AutoCalSetupProfile.RecordedOrdinaryIdentification : AutoCalSetupProfile.RecordedE54Read);

    private static void ExpectPreparation(Script adapter)
    {
        adapter.Expect(Tx(0x8603, Hex("0100F401")), Rx(0x8603, Array.Empty<byte>()));
        adapter.Expect(Tx(0x8604, Hex("010010000000")), Rx(0x8604, Array.Empty<byte>()));
    }

    private static async Task RecordedConfiguration()
    {
        using var adapter = AdapterWithStartup(ordinary: true); using var device = Device(adapter, ordinary: true);
        adapter.ReadChunk = 1; adapter.WriteChunk = 3;
        Require(await device.Initialize() && adapter.Completed.Count == 4, "ordinary initialization remains the exact four-command sequence");
        Require(!device.RecordedReadPreparationAccepted && !device.RecordedOrdinaryConfigurationRestored, "transitions initially unattempted");
        await Throws<InvalidOperationException>(() => device.RestoreRecordedOrdinaryConfigurationAsync(), "restore before preparation");
        ExpectPreparation(adapter);
        await device.ApplyRecordedReadPreparationAsync();
        Require(device.RecordedReadPreparationAccepted && !device.RecordedOrdinaryConfigurationRestored && device.AdapterSetupAccepted,
            "both preparation replies accepted without claiming restore");
        await Throws<InvalidOperationException>(() => device.ApplyRecordedReadPreparationAsync(), "duplicate preparation");
        Require(adapter.Completed.Count == 6 && adapter.ExpectedRemaining == 0, "exact preparation pair without replay");
        adapter.Expect(Tx(0x8604, new byte[6]), Rx(0x8604, Array.Empty<byte>()));
        await device.RestoreRecordedOrdinaryConfigurationAsync();
        Require(device.RecordedOrdinaryConfigurationRestored && device.AdapterSetupAccepted, "zero-form restore accepted");
        await Throws<InvalidOperationException>(() => device.RestoreRecordedOrdinaryConfigurationAsync(), "duplicate restore");
        Require(adapter.Completed.Count == 7 && adapter.ExpectedRemaining == 0 && adapter.DisposeCalls == 0,
            "exact seven host commands, no bus command or implicit disposal");
        Require(adapter.Completed.All(b => !(b[2] == 0 && b[3] == 0x8A)), "configuration lifecycle submits no VPW payload");
    }

    private static async Task ConfigurationPreconditions()
    {
        using (var adapter = AdapterWithStartup(ordinary: true))
        using (var device = Device(adapter, ordinary: true))
        {
            await Throws<InvalidOperationException>(() => device.ApplyRecordedReadPreparationAsync(), "preparation before initialize");
            await Throws<InvalidOperationException>(() => device.RestoreRecordedOrdinaryConfigurationAsync(), "restore before initialize");
            Require(adapter.WriteCalls == 0, "no startup bypass");
            await device.Initialize();
            byte[] pending = Rx(0x10, Hex("6CF01060")); adapter.Enqueue(pending);
            await Throws<InvalidOperationException>(() => device.ApplyRecordedReadPreparationAsync(), "pending data before configuration");
            Require(adapter.PendingByteCount == pending.Length && adapter.Completed.Count == 4,
                "pending bytes are preserved without setup or drain");
            device.Dispose();
            await Throws<InvalidOperationException>(() => device.ApplyRecordedReadPreparationAsync(), "preparation after dispose");
            await Throws<InvalidOperationException>(() => device.RestoreRecordedOrdinaryConfigurationAsync(), "restore after dispose");
            Require(adapter.Completed.Count == 4, "disposed device emits no configuration");
        }
        using (var adapter = AdapterWithStartup())
        using (var device = Device(adapter))
        {
            await device.Initialize();
            await Throws<InvalidOperationException>(() => device.ApplyRecordedReadPreparationAsync(), "already read-profile device");
            await Throws<InvalidOperationException>(() => device.RestoreRecordedOrdinaryConfigurationAsync(), "wrong profile restore");
            Require(adapter.Completed.Count == 5 && device.AdapterSetupAccepted, "profile rejection leaves existing setup unchanged");
        }
    }

    private static async Task ConfigurationFailures()
    {
        foreach (int failedStep in new[] { 1, 2, 3 })
        {
            using var adapter = AdapterWithStartup(ordinary: true); using var device = Device(adapter, ordinary: true);
            await device.Initialize();
            adapter.Expect(Tx(0x8603, Hex("0100F401")), failedStep == 1 ? Error(0x8603, 0) : Rx(0x8603, Array.Empty<byte>()));
            if (failedStep != 1)
                adapter.Expect(Tx(0x8604, Hex("010010000000")), failedStep == 2 ? Error(0x8604, 0) : Rx(0x8604, Array.Empty<byte>()));
            if (failedStep < 3) await Throws<InvalidOperationException>(() => device.ApplyRecordedReadPreparationAsync(), "error in preparation");
            else
            {
                await device.ApplyRecordedReadPreparationAsync();
                adapter.Expect(Tx(0x8604, new byte[6]), Error(0x8604, 0));
                await Throws<InvalidOperationException>(() => device.RestoreRecordedOrdinaryConfigurationAsync(), "error in restore");
            }
            Require(!device.AdapterSetupAccepted && !device.RecordedOrdinaryConfigurationRestored
                && device.RecordedReadPreparationAccepted == (failedStep == 3), "partial acceptance never becomes a successful transition");
            int writes = adapter.WriteCalls;
            await Throws<InvalidOperationException>(() => device.ApplyRecordedReadPreparationAsync(), "failed preparation cannot retry");
            await Throws<InvalidOperationException>(() => device.RestoreRecordedOrdinaryConfigurationAsync(), "failed transition cannot restore/replay");
            await Throws<InvalidOperationException>(() => device.SendMessage(new Message(Hex("6C10F020"))), "configuration failure blocks VPW");
            await Throws<InvalidOperationException>(() => device.StopRecordedSessionAsync(), "configuration failure blocks protocol cleanup");
            Require(!await device.CheckDeviceConnection() && !await device.Initialize(), "failed transition blocks model query and reinitialization");
            Require(adapter.WriteCalls == writes && adapter.Completed.Count == 4 + failedStep && adapter.ExpectedRemaining == 0
                && adapter.DisposeCalls == 0, "failure stops exact sequence with caller ownership retained");
        }
    }

    private static async Task ConfigurationExclusion()
    {
        using var adapter = AdapterWithStartup(ordinary: true); using var device = Device(adapter, ordinary: true);
        await device.Initialize(); ExpectPreparation(adapter);
        adapter.WriteBarrier = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task preparation = device.ApplyRecordedReadPreparationAsync(); await adapter.WriteStarted.Task;
        int writes = adapter.WriteCalls;
        Require(!device.AdapterSetupAccepted, "transition blocks session traffic while in progress");
        await Throws<InvalidOperationException>(() => device.ApplyRecordedReadPreparationAsync(), "concurrent preparation");
        await Throws<InvalidOperationException>(() => device.RestoreRecordedOrdinaryConfigurationAsync(), "concurrent restore");
        await Throws<InvalidOperationException>(() => device.SendMessage(new Message(Hex("6C10F020"))), "interleaved VPW");
        await Throws<InvalidOperationException>(() => device.ReceiveMessage(), "interleaved VPW receive");
        await Throws<InvalidOperationException>(() => device.StopRecordedSessionAsync(), "interleaved cleanup");
        Require(!await device.CheckDeviceConnection() && !await device.Initialize() && adapter.WriteCalls == writes,
            "model query and initialize cannot interleave the pair");
        adapter.WriteBarrier.SetResult(true); await preparation;
        Require(device.RecordedReadPreparationAccepted && device.AdapterSetupAccepted && adapter.Completed.Count == 6,
            "in-progress rejections did not corrupt the owning transition");
    }

    private static async Task ConfigurationDisposal()
    {
        var adapter = AdapterWithStartup(ordinary: true); var device = Device(adapter, ordinary: true);
        await device.Initialize(); ExpectPreparation(adapter);
        adapter.WriteBarrier = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task preparation = device.ApplyRecordedReadPreparationAsync(); await adapter.WriteStarted.Task;
        device.Dispose();
        Require(!device.AdapterSetupAccepted && adapter.DisposeCalls == 0, "configuration I/O remains owned after dispose request");
        await Throws<InvalidOperationException>(() => device.RestoreRecordedOrdinaryConfigurationAsync(), "restore after in-flight dispose");
        adapter.WriteBarrier.SetResult(true);
        await Throws<Exception>(() => preparation, "disposed preparation cannot complete acceptance");
        await Task.Delay(20);
        Require(!device.RecordedReadPreparationAccepted && !device.RecordedOrdinaryConfigurationRestored
            && adapter.Completed.Count == 5 && adapter.ExpectedRemaining == 1, "second preparation command blocked after disposal");
        Require(device.Channel.IsTransportDisposed && adapter.DisposeCalls == 1, "native ownership released only after active I/O completion");
        int writes = adapter.WriteCalls; device.Dispose();
        Require(adapter.WriteCalls == writes, "repeated disposal sends no cleanup commands");
    }

    private static async Task ConfigurationCancellation()
    {
        using var cancel = new CancellationTokenSource();
        using var adapter = AdapterWithStartup(ordinary: true);
        using var device = new AutoCalDevice(new AutoCalChannel(adapter), new Log(), cancel.Token, AutoCalSetupProfile.RecordedOrdinaryIdentification);
        await device.Initialize(); ExpectPreparation(adapter);
        adapter.WriteBarrier = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task preparation = device.ApplyRecordedReadPreparationAsync(); await adapter.WriteStarted.Task;
        cancel.Cancel();
        await Throws<AutoCalChannelException>(() => preparation, "pending preparation cancellation");
        Require(!device.AdapterSetupAccepted && !device.RecordedReadPreparationAccepted && !device.RecordedOrdinaryConfigurationRestored,
            "cancelled transition never grants acceptance");
        int writes = adapter.WriteCalls;
        await Throws<InvalidOperationException>(() => device.ApplyRecordedReadPreparationAsync(), "cancelled preparation replay");
        await Throws<InvalidOperationException>(() => device.RestoreRecordedOrdinaryConfigurationAsync(), "cancelled restore");
        adapter.WriteBarrier.SetResult(true); await Task.Delay(20);
        Require(adapter.WriteCalls == writes && adapter.Completed.Count == 5 && adapter.ExpectedRemaining == 1 && adapter.DisposeCalls == 0,
            "late first-command completion is retained with no second command or implicit disposal");
    }

    private static async Task Startup()
    {
        using var adapter = AdapterWithStartup();
        adapter.ReadChunk = 1; adapter.WriteChunk = 3;
        using var device = Device(adapter);
        Require(await device.Initialize(), "initialization accepted scripted ordinary setup replies");
        Same(Hex("0154018207000000000000008177"), adapter.Completed[0], "fixed model query golden bytes");
        Require(adapter.Completed.Count == 5 && adapter.ExpectedRemaining == 0, "exactly five startup commands");
        Require(adapter.Completed.Count(f => f[2] == 0 && f[3] == 0x88) == 1, "one connection-time8800 only");
        Require(!adapter.Completed.Any(f => f[2] == 0 && f[3] == 0x88 && f[12] == 1), "type3-only88000100 absent");
        Require(device.AdapterSetupAccepted && !device.HardwareProgrammingQualified, "host acceptance remains distinct from hardware qualification");
        Require(device.MaxKernelSendSize == 1772 && device.MaxFlashWriteSendSize == 1036 && device.MaxReceiveSize == 4108,
            "backend exposes bounded observed extents");
        int writes = adapter.WriteCalls;
        Require(await device.Initialize() && adapter.WriteCalls == writes, "successful initialization is not replayed");
        Require(await device.SetTimeout(TimeoutScenario.ReadCrc) == TimeoutScenario.ReadProperty, "initial timeout can be restored by generic caller");
        Require(await device.SetTimeout(TimeoutScenario.ReadProperty) == TimeoutScenario.ReadCrc, "timeout previous state is retained");
    }

    private static async Task StartupRefusals()
    {
        using (var adapter = AdapterWithStartup(Hex("4143563300")))
        using (var device = Device(adapter))
        {
            Require(!await device.Initialize(), "wrong model refused");
            Require(adapter.Completed.Count == 1 && !device.AdapterSetupAccepted, "wrong model emits no setup");
            await Throws<InvalidOperationException>(() => device.SendMessage(new Message(Hex("6C10F020"))), "wrong model blocks VPW");
            await Throws<InvalidOperationException>(() => device.Initialize(), "failed initialization cannot silently replay");
            Require(adapter.Completed.Count == 1, "no command repeated after failed initialization");
        }
        using (var adapter = AdapterWithStartup())
        using (var device = Device(adapter))
        {
            byte[] pending = Rx(0x8604, Array.Empty<byte>()); adapter.Enqueue(pending);
            await Throws<InvalidOperationException>(() => device.Initialize(), "pending startup bytes");
            Require(adapter.WriteCalls == 0 && adapter.ReadCalls == 0 && adapter.PendingByteCount == pending.Length,
                "pending startup is preserved without queries or silent purge");
        }
    }

    private static async Task ZeroStatusError()
    {
        using (var adapter = AdapterWithStartup(firstSetupError: true))
        using (var device = Device(adapter))
        {
            await Throws<InvalidOperationException>(() => device.Initialize(), "setup error0");
            Require(adapter.Completed.Count == 2 && !device.AdapterSetupAccepted, "error0 prevents further setup");
            Require(!await device.Initialize(), "stopped initialization is not replayed");
            await Throws<InvalidOperationException>(() => device.SendMessage(new Message(Hex("6C10F020"))), "setup error blocks bus send");
        }
        using (var adapter = AdapterWithStartup())
        using (var device = Device(adapter))
        {
            await device.Initialize(); adapter.Enqueue(Error(0x8A00, 0));
            await Throws<InvalidOperationException>(() => device.ReceiveMessage(), "VPW error0");
            Require(!device.AdapterSetupAccepted && device.ReceivedMessageCount == 0, "error0 is not a message or success");
            Require(adapter.Completed.Count == 5, "error handling did not transmit a poll or retry");
        }
    }

    private static async Task SyntheticProgramming()
    {
        using var adapter = AdapterWithStartup();
        adapter.ReadChunk = 7; adapter.WriteChunk = 113;
        using var device = Device(adapter);
        await device.Initialize();
        var protocol = new Protocol();
        int acknowledgements = 0;
        foreach (uint address in new uint[] { 0x8000, 0x10000 })
        {
            Message erase = protocol.CreateFlashEraseBlockRequest(address);
            byte[] ack = Hex("6CF0107D0500");
            adapter.Expect(Tx(0x8A00, erase.GetBytes(), 0x10), Rx(0x10, ack));
            Require(await device.SendMessage(erase), "synthetic erase host submission");
            Same(ack, (await device.ReceiveMessage()).GetBytes(), "synthetic erase ACK unchanged");
            acknowledgements++;
        }
        var image = Enumerable.Range(0, 96 * 1024).Select(i => (byte)((i * 37 + i / 1024) & 255)).ToArray();
        for (int block = 0; block < 96; block++)
        {
            Message message = protocol.CreateBlockMessage(image, block * 1024, 1024, 0x8000 + block * 1024, BlockCopyType.Copy);
            Require(message.Length == 1036, "each synthetic programming request is1036bytes");
            byte[] ack = Hex("6CF010760000");
            adapter.Expect(Tx(0x8A00, message.GetBytes(), 0x10), Rx(block % 2 == 0 ? 0u : 0x10u, ack));
            Require(await device.SendMessage(message), "program host submission completes exact bytes");
            Same(ack, (await device.ReceiveMessage()).GetBytes(), "short program ACK unchanged");
            acknowledgements++;
        }
        Require(acknowledgements == 98, "two erase plus96program acknowledgements");
        Require(adapter.Completed.Count == 103 && adapter.ExpectedRemaining == 0, "5setup+98bus commands, no extras/replays");
        Require(adapter.Completed.Skip(7).All(f => f.Length == 1050 && f[10] == 0x0C && f[11] == 4),
            "all96payloads encoded as1036-byte host payloads");
        Require(adapter.PendingByteCount == 0 && device.ReceivedMessageCount == 0, "all scripted acknowledgements consumed once");
        Require(device.AdapterSetupAccepted && !device.HardwareProgrammingQualified, "fake programming does not qualify hardware");
    }

    private static async Task ReceiveAndDrain()
    {
        using var adapter = AdapterWithStartup(); using var device = Device(adapter);
        await device.Initialize(); int writes = adapter.WriteCalls;
        byte[] broadcast = Hex("6CF01060"); adapter.Enqueue(Rx(0x10, broadcast));
        Require(await device.IsCommandBroadcasting(0x60), "broadcast command recognized");
        Same(broadcast, (await device.ReceiveMessage()).GetBytes(), "broadcast remains available in device queue");
        adapter.Enqueue(Rx(0, Array.Empty<byte>()));
        Require(await device.ReceiveMessage() == null, "empty ordinary VPW reply is not a bus message");
        await device.SetTimeout(TimeoutScenario.Minimum);
        Require(await device.ReceiveMessage() == null && device.AdapterSetupAccepted, "empty idle timeout permits subsequent receive");
        adapter.Enqueue(Rx(0, broadcast).Concat(Rx(0x10, Hex("6CF010760000"))).ToArray());
        device.ClearMessageQueue();
        Require(adapter.PendingByteCount == 0 && device.Channel.LastDrainReplies.Count == 2, "drain retains both complete raw records");
        Require(adapter.WriteCalls == writes, "receive, timeout, broadcast and drain never send an empty8A00 poll");
    }

    private static async Task DelayedSetupEcho()
    {
        using var adapter = AdapterWithStartup(); using var device = Device(adapter);
        await device.Initialize(); adapter.Enqueue(Rx(0x8604, Hex("6CF010760000")));
        await Throws<InvalidOperationException>(() => device.ReceiveMessage(), "stale setup reply underVPW context");
        Require(!device.AdapterSetupAccepted && device.ReceivedMessageCount == 0, "setup echo cannot become plausible ACK payload");
        Require(adapter.Completed.Count == 5, "rejection emits no new command");
    }

    private static async Task Oversize()
    {
        foreach (bool broadcast in new[] { false, true })
        {
            using var adapter = AdapterWithStartup(); using var device = Device(adapter);
            await device.Initialize();
            byte[] payload = new byte[AutoCalDevice.ObservedMaximumReceiveBytes + 1];
            Array.Copy(Hex("6CF01060"), payload, 4); adapter.Enqueue(Rx(0, payload));
            if (broadcast) await Throws<InvalidOperationException>(() => device.IsCommandBroadcasting(0x60), "broadcast oversize");
            else await Throws<InvalidOperationException>(() => device.ReceiveMessage(), "receive oversize");
            Require(device.ReceivedMessageCount == 0 && !device.AdapterSetupAccepted, "oversize halts without enqueuing");
        }
        using (var adapter = AdapterWithStartup())
        using (var device = Device(adapter))
        {
            await device.Initialize(); int writes = adapter.WriteCalls;
            await Throws<ArgumentException>(() => device.SendMessage(new Message(new byte[1773])), "TX oversize");
            Require(adapter.WriteCalls == writes, "oversized TX rejected before I/O");
        }
    }

    private static async Task SpeedAndStop()
    {
        using var adapter = AdapterWithStartup(); using var device = Device(adapter);
        await device.Initialize(); int writes = adapter.WriteCalls;
        Require(!device.Supports4X && !device.Enable4xReadWrite, "4x capability disabled");
        device.Enable4xReadWrite = true;
        Require(!await device.SetVpwSpeed(VpwSpeed.FourX) && adapter.WriteCalls == writes, "forced4x request still refuses without I/O");
        adapter.Expect(Tx(0x8604, new byte[6]), Rx(0x8604, Array.Empty<byte>()));
        adapter.Expect(Tx(0x8B01, Hex("00010000")), Rx(0x8B01, Array.Empty<byte>()));
        adapter.Expect(Tx(0x8B01, Hex("01010000")), Rx(0x8B01, Array.Empty<byte>()));
        adapter.WriteBarrier = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task stopping = device.StopRecordedSessionAsync();
        await adapter.WriteStarted.Task;
        Require(!device.AdapterSetupAccepted, "cleanup starts by blocking vehicle traffic");
        await Throws<InvalidOperationException>(() => device.SendMessage(new Message(Hex("6C10F020"))), "send during cleanup");
        adapter.WriteBarrier.SetResult(true); await stopping;
        Require(adapter.ExpectedRemaining == 0 && adapter.Completed.Count == 8, "exact recorded cleanup sequence");
        Require(!await device.Initialize(), "stopped session cannot restart silently");
    }

    private static async Task Disposal()
    {
        var adapter = AdapterWithStartup(); var device = Device(adapter);
        await device.Initialize();
        adapter.Expect(Tx(0x8A00, Hex("6C10F020"), 0x10), Array.Empty<byte>());
        adapter.WriteBarrier = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task send = device.SendMessage(new Message(Hex("6C10F020")));
        await adapter.WriteStarted.Task;
        device.Dispose();
        Require(!device.AdapterSetupAccepted && adapter.DisposeCalls == 0, "dispose immediately blocks use and defers active handle cleanup");
        int writes = adapter.WriteCalls;
        await Throws<InvalidOperationException>(() => device.SendMessage(new Message(Hex("6C10F020"))), "send after dispose request");
        Require(adapter.WriteCalls == writes, "disposal prevents additional transport calls");
        adapter.WriteBarrier.SetResult(true); await send; await Task.Delay(20);
        Require(device.Channel.IsTransportDisposed && adapter.DisposeCalls == 1, "owned pending I/O completes before transport close");

        var failClose = AdapterWithStartup(); var retryDevice = Device(failClose);
        await retryDevice.Initialize(); failClose.FailDisposeOnce = true;
        retryDevice.Dispose();
        Require(!retryDevice.AdapterSetupAccepted && retryDevice.Channel.CleanupException != null,
            "failed close leaves device unavailable and cleanup evidence owned");
        retryDevice.Dispose();
        Require(retryDevice.Channel.IsTransportDisposed && failClose.DisposeCalls == 2, "explicit repeated disposal retries retained cleanup");
        Require(failClose.Completed.Count == 5, "disposal sends no setup or vehicle commands");
    }

    private sealed class Script : IAutoCalByteTransport
    {
        private readonly Queue<(byte[] expected, byte[] response)> steps = new Queue<(byte[], byte[])>();
        private readonly Queue<byte> inbound = new Queue<byte>();
        private int stepOffset;
        public readonly List<byte[]> Completed = new List<byte[]>();
        public int ReadChunk = int.MaxValue, WriteChunk = int.MaxValue;
        public int WriteCalls, ReadCalls, DisposeCalls;
        public bool FailDisposeOnce;
        public TaskCompletionSource<bool>? WriteBarrier;
        public readonly TaskCompletionSource<bool> WriteStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        public int ExpectedRemaining => steps.Count;
        public int PendingByteCount => inbound.Count;
        public void Expect(byte[] expected, byte[] response) => steps.Enqueue((expected, response));
        public void Enqueue(byte[] bytes) { foreach (byte value in bytes) inbound.Enqueue(value); }
        public Task<int> Read(byte[] buffer, int offset, int count, int timeoutMs, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); ReadCalls++;
            int size = Math.Min(count, Math.Min(ReadChunk, inbound.Count));
            for (int i = 0; i < size; i++) buffer[offset + i] = inbound.Dequeue();
            return Task.FromResult(size);
        }
        public async Task<int> Write(byte[] buffer, int offset, int count, int timeoutMs, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); WriteCalls++;
            if (WriteBarrier != null) { WriteStarted.TrySetResult(true); await WriteBarrier.Task; }
            if (steps.Count == 0) throw new Exception("Unexpected outbound command; no scripted response may be invented.");
            var step = steps.Peek();
            int size = Math.Min(count, WriteChunk);
            if (size > step.expected.Length - stepOffset) throw new Exception("Outbound transfer crosses expected command boundary.");
            for (int i = 0; i < size; i++)
                if (buffer[offset + i] != step.expected[stepOffset + i])
                    throw new Exception("Outbound byte mismatch at offset " + (stepOffset + i));
            stepOffset += size;
            if (stepOffset == step.expected.Length)
            {
                steps.Dequeue(); stepOffset = 0; Completed.Add((byte[])step.expected.Clone()); Enqueue(step.response);
            }
            return size;
        }
        public void Dispose()
        {
            DisposeCalls++;
            if (FailDisposeOnce) { FailDisposeOnce = false; throw new InvalidOperationException("Synthetic native close failure"); }
        }
    }

    private sealed class Log : ILogger
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
