// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using PcmHacking;

internal static class AutoCalChannelTest
{
    private static int assertions;
    private static byte[] Model => Convert.FromHexString("015201820000000000000500414356320026B419");
    private static byte[] ModelTx => Convert.FromHexString("0154018207000000000000008177");

    public static async Task Main()
    {
        Encoder();
        await FragmentationAndCoalescing();
        await PartialWrites();
        await RejectionsAndErrors();
        await ReadTimeoutsAndDrain();
        await RepeatedIdleDeadlineBoundaries();
        await CancellationAndOwnedPendingIo();
        await SerializedExchangeAndDeadline();
        await OneDeadlineAcrossSendAndReceive();
        await TransportFailuresAndCleanup();
        Console.WriteLine(JsonSerializer.Serialize(new { assertions, adapterOpened = false, liveWriteEnabled = false,
            pcmLibraryAssembly = typeof(AutoCalChannel).Assembly.Location,
            scope = "In-memory transports only; stream, deadline, partial-transfer and ownership semantics" }));
    }

    private static void Require(bool value, string description)
    {
        assertions++;
        if (!value) throw new Exception(description);
    }
    private static void Same(byte[] a, byte[] b, string description) => Require(a.SequenceEqual(b), description);
    private static async Task<T> Throws<T>(Func<Task> action, string description) where T : Exception
    {
        try { await action(); }
        catch (T error) { assertions++; return error; }
        throw new Exception("Expected " + typeof(T).Name + ": " + description);
    }
    private static byte[] Frame(ushort marker, byte[] payload, byte trailer = 0x19)
    {
        var result = new byte[payload.Length + 15];
        result[0] = 1; result[1] = 0x52; result[2] = (byte)marker; result[3] = (byte)(marker >> 8);
        result[10] = (byte)payload.Length; result[11] = (byte)(payload.Length >> 8);
        Array.Copy(payload, 0, result, 12, payload.Length);
        ushort crc = 0;
        for (int index = 0; index < result.Length - 3; index++)
        {
            crc ^= result[index];
            for (int bit = 0; bit < 8; bit++) crc = (ushort)((crc & 1) == 0 ? crc >> 1 : (crc >> 1) ^ 0xA001);
        }
        result[result.Length - 3] = (byte)crc; result[result.Length - 2] = (byte)(crc >> 8);
        result[result.Length - 1] = trailer;
        return result;
    }

    private static void Encoder()
    {
        Same(ModelTx, AutoCalHostFrame.EncodeLongHeader(0x8201, 7, 0, Array.Empty<byte>()), "saved model query exact encoder");
        var source = new byte[] { 0x6c, 0x10, 0xf0, 0x20 };
        byte[] encoded = AutoCalHostFrame.EncodeLongHeader(0x8a00, 7, 0x10, source);
        var parsed = AutoCalHostFrame.ParseLongHeader(AutoCalHostDirection.HostToDevice, encoded);
        Require(parsed.CrcMatches, "encoded frame CRC valid");
        Same(source, parsed.Payload, "no VPW prefix or CRC alteration");
        Same(Convert.FromHexString("008A070010000000"), parsed.OpaqueHeaderBytes, "explicit fields preserved");
        source[0] = 0;
        Require(parsed.Payload[0] == 0x6c, "encoded payload independent of caller buffer");
        Require(AutoCalHostFrame.EncodeLongHeader(1, 0, 0, new byte[65535]).Length == 65549, "wire length bound");
        try { AutoCalHostFrame.EncodeLongHeader(1, 0, 0, new byte[65536]); throw new Exception("oversize encoder accepted"); }
        catch (ArgumentOutOfRangeException) { assertions++; }
    }

    private static async Task FragmentationAndCoalescing()
    {
        using (var fake = new Fake(Model) { ReadChunk = 1 })
        using (var channel = new AutoCalChannel(fake))
        {
            var reply = await channel.ReadAsync(0x8201, 1000);
            Same(Model, reply.Frame.RawBytes, "all single-byte fragments assembled");
            Require(fake.ReadCalls == Model.Length && fake.Writes.Count == 0, "read never sends poll");
        }
        var first = Frame(0x10, Convert.FromHexString("6CF010760000"));
        var second = Frame(0, Convert.FromHexString("6CF01060"));
        using (var fake = new Fake(first.Concat(second).ToArray()))
        using (var channel = new AutoCalChannel(fake))
        {
            Same(first, (await channel.ReadAsync(0x8a00, 1000)).Frame.RawBytes, "first coalesced frame");
            Require(channel.BufferedByteCount == second.Length, "second coalesced frame retained");
            Same(second, (await channel.ReadAsync(0x8a00, 1000)).Frame.RawBytes, "second coalesced frame");
            Require(fake.ReadCalls == 1 && fake.Writes.Count == 0, "buffered receive avoids another I/O or poll TX");
        }
        using (var fake = new Fake(Frame(0, new byte[0xC000])))
        using (var channel = new AutoCalChannel(fake))
            Require((await channel.ReadAsync(0x8a00, 1000)).Payload!.Length == 0xC000, "maximum native receive extent assembled");
    }

    private static async Task PartialWrites()
    {
        using var fake = new Fake(Model) { WriteChunk = 3 };
        using var channel = new AutoCalChannel(fake);
        var reply = await channel.ExchangeAsync(0x8201, 7, 0, Array.Empty<byte>(), 1000);
        Same(ModelTx, fake.Writes.ToArray(), "short writes send remaining suffix exactly once");
        Require(fake.WriteCalls == 5 && !reply.IsCommandError, "partial completion is counted");
        Same(new byte[] { 65, 67, 86, 50, 0 }, reply.Payload!, "model response payload");
    }

    private static async Task RejectionsAndErrors()
    {
        byte[] corrupt = (byte[])Model.Clone(); corrupt[corrupt.Length - 3] ^= 1;
        byte[] tooLong = Frame(0, Array.Empty<byte>()).Take(12).ToArray(); tooLong[10] = 1; tooLong[11] = 0xc0;
        foreach (var item in new[] {
            (corrupt, AutoCalChannelFailure.InvalidCrc),
            (Frame(0x8201, Array.Empty<byte>(), 0x18), AutoCalChannelFailure.InvalidTrailer),
            (Frame(0x8604, Array.Empty<byte>()), AutoCalChannelFailure.ContextMismatch),
            (Frame(0xff00, new byte[] { 1, 0x82, 0 }), AutoCalChannelFailure.MalformedError),
            (Frame(0xff00, new byte[] { 4, 0x86, 0, 0 }), AutoCalChannelFailure.ContextMismatch),
            (tooLong, AutoCalChannelFailure.UnsupportedLength),
            (new byte[] { 0, 0x52 }, AutoCalChannelFailure.InvalidPrefix) })
        {
            using var fake = new Fake(item.Item1);
            using var channel = new AutoCalChannel(fake);
            var error = await Throws<AutoCalChannelException>(() => channel.ReadAsync(0x8201, 1000), "strict rejection");
            Require(error.Failure == item.Item2 && channel.IsFaulted, "rejection reason and fault state");
            Same(item.Item1, error.BufferedReceiveBytes, "rejected bytes retained without resync");
            await Throws<InvalidOperationException>(() => channel.SendCommandAsync(0x8201, 7, 0, Array.Empty<byte>(), 1000), "fault blocks TX");
            Require(fake.WriteCalls == 0, "no TX after corrupt input");
        }
        using (var fake = new Fake(Frame(0xff00, new byte[] { 4, 0x86, 0, 0 })))
        using (var channel = new AutoCalChannel(fake))
        {
            var error = await channel.ReadAsync(0x8604, 1000);
            Require(error.IsCommandError && error.ExceptionStatus == 0 && error.Payload == null,
                "zero status error marker stays an error");
            Require(!channel.IsFaulted, "well-formed device error does not corrupt stream alignment");
        }
        using (var fake = new Fake(Frame(0x8604, Array.Empty<byte>())))
        using (var channel = new AutoCalChannel(fake))
            Require((await channel.ReadAsync(0x8604, 1000)).Payload!.Length == 0, "empty ordinary setup reply accepted");
    }

    private static async Task ReadTimeoutsAndDrain()
    {
        using (var fake = new Fake())
        using (var channel = new AutoCalChannel(fake))
        {
            await Throws<AutoCalReadTimeoutException>(() => channel.ReadAsync(0x8a00, 20), "empty ordinary read timeout");
            Require(!channel.IsFaulted && fake.Writes.Count == 0, "ordinary idle timeout is reusable and passive");
            fake.Enqueue(Frame(0x10, new byte[] { 1 }));
            Require((await channel.ReadAsync(0x8a00, 1000)).Payload![0] == 1, "receive recovers after idle timeout");
        }
        using (var fake = new Fake(new byte[] { 1, 0x52, 0x10 }))
        using (var channel = new AutoCalChannel(fake))
        {
            var failure = await Throws<AutoCalChannelException>(() => channel.ReadAsync(0x8a00, 20), "partial frame timeout");
            Require(channel.IsFaulted && failure.BufferedReceiveBytes.Length == 3, "partial frame preserved and faults");
        }
        using (var fake = new Fake())
        using (var channel = new AutoCalChannel(fake))
        {
            await Throws<AutoCalChannelException>(() => channel.ExchangeAsync(0x8a00, 7, 16, new byte[] { 1 }, 20), "exchange timeout faults");
            Require(channel.IsFaulted && fake.WriteCalls == 1, "exchange not confused with passive timeout");
        }
        byte[] complete = Frame(0x10, new byte[] { 2 });
        using (var fake = new Fake(complete.Concat(complete).ToArray()))
        using (var channel = new AutoCalChannel(fake))
        {
            var drained = await channel.DrainAvailableVpwAsync(1000);
            Require(drained.Count == 2 && channel.LastDrainReplies.Count == 2 && channel.PendingByteCount == 0,
                "complete available frames drained with evidence");
            Require(fake.WriteCalls == 0, "drain sends nothing");
        }
        using (var fake = new Fake(complete.Concat(new byte[] { 1, 0x52 }).ToArray()))
        using (var channel = new AutoCalChannel(fake))
        {
            await Throws<AutoCalChannelException>(() => channel.DrainAvailableVpwAsync(20), "partial available frame faults");
            Require(channel.LastDrainReplies.Count == 1 && channel.BufferedByteCount == 2,
                "completed drain records survive later partial failure");
        }
    }

    private static async Task CancellationAndOwnedPendingIo()
    {
        using (var cancel = new CancellationTokenSource())
        using (var fake = new Fake())
        using (var channel = new AutoCalChannel(fake))
        {
            fake.WriteOverride = (_, _, _, _, _) => { cancel.Cancel(); return Task.FromResult(3); };
            var failure = await Throws<AutoCalChannelException>(() => channel.SendCommandAsync(0x8201, 7, 0, Array.Empty<byte>(), 1000, cancel.Token), "partial cancellation");
            Require(failure.DeliveryUncertain && channel.IsFaulted && fake.WriteCalls == 1, "cancelled write not replayed");
            Require(failure.Transfer!.ReturnedByteCount == 3, "returned partial count remains evidence");
        }
        var pending = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        var slow = new Fake { WriteOverride = (_, _, _, _, _) => pending.Task };
        var owned = new AutoCalChannel(slow);
        var timeout = await Throws<AutoCalChannelException>(() => owned.SendCommandAsync(0x8201, 7, 0, Array.Empty<byte>(), 20), "in-flight timeout");
        owned.Dispose();
        Require(slow.DisposeCalls == 0 && !timeout.Transfer!.IsCompleted, "timed-out task retains native resource ownership");
        pending.SetResult(ModelTx.Length);
        await Task.Delay(30);
        Require(slow.DisposeCalls == 1 && owned.IsTransportDisposed, "dispose deferred until I/O actually ends");
        Same(ModelTx, timeout.Transfer!.Bytes, "late write completion bytes retained");

        var readPending = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        byte[]? held = null;
        using var readFake = new Fake { ReadOverride = (b, _, _, _, _) => { held = b; return readPending.Task; } };
        using var readChannel = new AutoCalChannel(readFake);
        var lateRead = await Throws<AutoCalChannelException>(() => readChannel.ReadAsync(0x8a00, 20), "pending read timeout faults");
        Array.Copy(Model, held!, Model.Length);
        readPending.SetResult(Model.Length);
        await Task.Delay(20);
        Same(Model, lateRead.Transfer!.Bytes, "late read data is not silently lost");
        Require(readChannel.IsFaulted, "late completion never reopens faulted session");
    }

    private static async Task RepeatedIdleDeadlineBoundaries()
    {
        using var fake = new Fake();
        using var channel = new AutoCalChannel(fake);
        // Repeated 1ms windows exercise expiry between the caller's check and
        // IoAsync's pre-call check; every prior driver task has completed zero.
        for (int attempt = 0; attempt < 150; attempt++)
            await Throws<AutoCalReadTimeoutException>(() => channel.ReadAsync(0x8a00, 1), "idle deadline boundary remains reusable");
        Require(!channel.IsFaulted && fake.WriteCalls == 0, "idle stress never faults or transmits");
        fake.Enqueue(Frame(0x10, new byte[] { 3 }));
        Require((await channel.ReadAsync(0x8a00, 1000)).Payload![0] == 3, "channel works after repeated idle expiries");
    }

    private static async Task SerializedExchangeAndDeadline()
    {
        var pending = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        byte[]? held = null;
        using var fake = new Fake { ReadOverride = (b, _, _, _, _) => { held = b; return pending.Task; } };
        using var channel = new AutoCalChannel(fake);
        Task<AutoCalChannelReply> first = channel.ExchangeAsync(0x8201, 7, 0, Array.Empty<byte>(), 1000);
        await Throws<TimeoutException>(() => channel.ExchangeAsync(0x8201, 7, 0, Array.Empty<byte>(), 20), "gate uses same operation deadline");
        Require(fake.WriteCalls == 1 && !channel.IsFaulted, "second exchange never interleaves TX or faults first");
        Array.Copy(Model, held!, Model.Length); pending.SetResult(Model.Length);
        Require(!(await first).IsCommandError, "first serialized exchange completes");
    }

    private static async Task TransportFailuresAndCleanup()
    {
        foreach (int result in new[] { 0, -1, 100 })
        {
            using var fake = new Fake { WriteOverride = (_, _, _, _, _) => Task.FromResult(result) };
            using var channel = new AutoCalChannel(fake);
            var failure = await Throws<AutoCalChannelException>(() => channel.SendCommandAsync(0x8201, 7, 0, Array.Empty<byte>(), 1000), "invalid/no-progress write");
            Require(channel.IsFaulted && failure.DeliveryUncertain, "invalid count fails closed");
        }
        var flaky = new Fake { FailDisposeOnce = true };
        var owner = new AutoCalChannel(flaky);
        owner.Dispose();
        Require(owner.CleanupException != null && !owner.IsTransportDisposed, "failed cleanup remains visible and owned");
        owner.Dispose();
        Require(owner.CleanupException == null && owner.IsTransportDisposed && flaky.DisposeCalls == 2, "cleanup retry closes owned transport");
        using (var fake = new Fake { ReadOverride = (_, _, _, _, _) => Task.FromException<int>(new InvalidOperationException("synthetic driver failure")) })
        using (var channel = new AutoCalChannel(fake))
        {
            var failure = await Throws<AutoCalChannelException>(() => channel.ReadAsync(0x8a00, 1000), "driver task failure");
            Require(failure.Failure == AutoCalChannelFailure.TransportFailure && failure.InnerException != null,
                "native failure remains a typed transport fault with cause");
        }
        using (var fake = new Fake { ReadOverride = (_, _, count, _, _) => Task.FromResult(count + 1) })
        using (var channel = new AutoCalChannel(fake))
        {
            var failure = await Throws<AutoCalChannelException>(() => channel.ReadAsync(0x8a00, 1000), "invalid read count");
            Require(failure.Failure == AutoCalChannelFailure.InvalidTransferCount && failure.Transfer!.ReturnedByteCount == 4097,
                "invalid read count retained without indexing beyond buffer");
        }
    }

    private static async Task OneDeadlineAcrossSendAndReceive()
    {
        int readBudget = 0;
        var pending = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var fake = new Fake {
            WriteOverride = async (_, _, count, _, _) => { await Task.Delay(40); return count; },
            ReadOverride = (_, _, _, timeout, _) => { readBudget = timeout; return pending.Task; }
        };
        using var channel = new AutoCalChannel(fake);
        var failure = await Throws<AutoCalChannelException>(() => channel.ExchangeAsync(0x8201, 7, 0, Array.Empty<byte>(), 150), "single exchange deadline");
        Require(readBudget > 0 && readBudget < 130, "receive inherits remaining deadline after send");
        Require(failure.Failure == AutoCalChannelFailure.DeadlineExceeded && fake.WriteCalls == 1,
            "receive cannot reset the exchange deadline or replay the command");
        pending.SetResult(0);
        await Task.Delay(10);
    }

    private sealed class Fake : IAutoCalByteTransport
    {
        private readonly Queue<byte> inbound = new Queue<byte>();
        public readonly List<byte> Writes = new List<byte>();
        public int ReadChunk = int.MaxValue, WriteChunk = int.MaxValue;
        public int ReadCalls, WriteCalls, DisposeCalls;
        public bool FailDisposeOnce;
        public Func<byte[], int, int, int, CancellationToken, Task<int>>? ReadOverride;
        public Func<byte[], int, int, int, CancellationToken, Task<int>>? WriteOverride;
        public Fake(params byte[] initial) { Enqueue(initial); }
        public void Enqueue(byte[] data) { foreach (byte value in data) inbound.Enqueue(value); }
        public int PendingByteCount => inbound.Count;
        public Task<int> Read(byte[] buffer, int offset, int count, int timeoutMs, CancellationToken token)
        {
            ReadCalls++;
            if (ReadOverride != null) return ReadOverride(buffer, offset, count, timeoutMs, token);
            int size = Math.Min(inbound.Count, Math.Min(ReadChunk, count));
            for (int i = 0; i < size; i++) buffer[offset + i] = inbound.Dequeue();
            return Task.FromResult(size);
        }
        public Task<int> Write(byte[] buffer, int offset, int count, int timeoutMs, CancellationToken token)
        {
            WriteCalls++;
            if (WriteOverride != null) return WriteOverride(buffer, offset, count, timeoutMs, token);
            int size = Math.Min(count, WriteChunk);
            Writes.AddRange(buffer.Skip(offset).Take(size));
            return Task.FromResult(size);
        }
        public void Dispose()
        {
            DisposeCalls++;
            if (FailDisposeOnce) { FailDisposeOnce = false; throw new InvalidOperationException("synthetic close failure"); }
        }
    }
}
