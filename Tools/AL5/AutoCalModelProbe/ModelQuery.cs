// SPDX-License-Identifier: GPL-3.0-only
using System.Diagnostics;
using PcmHacking;

namespace AutoCalModelProbe;

internal static class FixedModel
{
    internal const string Serial = "AC3NCHH5";
    internal const uint Identifier = 0x0403E4A3;
    internal const uint DeviceType = 5;
    internal const int ReplyBytes = 20;
    internal const int MaxReads = 8;
    internal const uint ReadTimeoutMs = 250;
    internal const uint WriteTimeoutMs = 1000;
    internal static byte[] Query() => Convert.FromHexString("0154018207000000000000008177");
    internal static readonly string[] ExportNames = ["FT_CreateDeviceInfoList", "FT_GetDeviceInfoDetail",
        "FT_OpenEx", "FT_SetTimeouts", "FT_GetQueueStatus", "FT_Write", "FT_Read", "FT_Close"];
}

internal sealed record Identity(uint Index, uint Status, uint Flags, uint Type, uint Identifier,
    uint Location, string SerialHex, string SerialRawHex, bool SerialTerminated,
    string DescriptionRawHex, bool PreexistingHandlePresentUnused);
internal sealed record Enumeration(uint Status, uint ReportedCount, IReadOnlyList<Identity> Entries);
internal sealed record OpenResult(uint Status, bool HandleReturned);
internal sealed record CountResult(uint Status, uint Count);
internal sealed record ReadResult(uint Status, uint ReportedCount, byte[] Data);
internal sealed record ProbeEvent(string Stage, object? Data = null);

// Deliberately no arbitrary Send, generic port configuration, reset or purge.
internal interface IModelDevice
{
    bool OwnsHandle { get; }
    Enumeration Enumerate();
    OpenResult OpenExactSerial();
    uint SetFixedTimeouts();
    CountResult GetQueueStatus();
    CountResult WriteFixedModelQuery();
    ReadResult Read(int count);
    uint CloseOwnedHandle();
}

internal sealed class ProbeBudget
{
    private readonly Func<double> seconds;
    private readonly double deadline;
    private readonly CancellationToken cancellation;
    internal ProbeBudget(Func<double> seconds, CancellationToken cancellation)
    {
        this.seconds = seconds;
        deadline = seconds() + 20.0;
        this.cancellation = cancellation;
    }
    internal static double MonotonicSeconds() => (double)Stopwatch.GetTimestamp() / Stopwatch.Frequency;
    internal void Check()
    {
        cancellation.ThrowIfCancellationRequested();
        if (seconds() >= deadline) throw new TimeoutException("20-second deadline reached; only owned cleanup is allowed.");
    }
}

internal sealed class ModelResult
{
    public bool ModelVerified { get; internal set; }
    public bool OwnedHandleClosed { get; internal set; }
    public bool CleanupPending { get; internal set; }
    public int ApplicationWriteAttempts { get; internal set; }
    public int ReadCalls { get; internal set; }
    public string ReceivedHex { get; internal set; } = "";
    public string? Error { get; internal set; }
    public List<string> TelemetryErrors { get; } = [];
    public List<ProbeEvent> Events { get; } = [];
    public bool Successful => ModelVerified && OwnedHandleClosed && !CleanupPending
        && Error == null && TelemetryErrors.Count == 0;
}

internal static class ModelQuery
{
    internal static ModelResult Run(IModelDevice device, ProbeBudget budget, Action<ProbeEvent> observe)
    {
        ModelResult result = new();
        List<byte> received = [];
        void Emit(string stage, object? data = null)
        {
            ProbeEvent item = new(stage, data);
            result.Events.Add(item);
            try { observe(item); }
            catch (Exception error) { result.TelemetryErrors.Add($"{stage}: {error.GetType().Name}: {error.Message}"); }
        }
        void BeforeCall()
        {
            if (result.TelemetryErrors.Count != 0)
                throw new IOException("Journal failed; no new operation except owned close is allowed.");
            budget.Check();
        }
        try
        {
            BeforeCall();
            Enumeration enumeration = device.Enumerate();
            Emit("enumeration", enumeration);
            if (enumeration.Status != 0 || enumeration.ReportedCount > 64
                || enumeration.Entries.Count != enumeration.ReportedCount
                || enumeration.Entries.Any(item => item.Status != 0))
                throw new InvalidOperationException("Enumeration failed or was incomplete.");
            string serialHex = Convert.ToHexString(System.Text.Encoding.ASCII.GetBytes(FixedModel.Serial));
            Identity[] matching = enumeration.Entries.Where(item => item.SerialHex.Equals(serialHex, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (matching.Length != 1) throw new InvalidOperationException("Exactly one matching serial is required.");
            Identity identity = matching[0];
            if (identity.Identifier != FixedModel.Identifier || identity.Type != FixedModel.DeviceType
                || (identity.Flags & 1) != 0 || !identity.SerialTerminated)
                throw new InvalidOperationException("Adapter is busy or serial/ID/type is not the reviewed identity.");

            Emit("open_started", new { FixedModel.Serial, Flags = 1 });
            BeforeCall();
            OpenResult opened = device.OpenExactSerial();
            // The boundary owns the handle immediately on successful OpenEx,
            // before any logging or state-machine code can throw.
            Emit("open_result", opened);
            if (opened.Status != 0 || !opened.HandleReturned || !device.OwnsHandle)
                throw new IOException("FT_OpenEx did not return a successfully owned handle.");
            BeforeCall();
            uint timeoutStatus = device.SetFixedTimeouts();
            Emit("timeouts", new { Status = timeoutStatus, FixedModel.ReadTimeoutMs, FixedModel.WriteTimeoutMs });
            if (timeoutStatus != 0) throw new IOException("FT_SetTimeouts failed.");
            BeforeCall();
            CountResult before = device.GetQueueStatus();
            Emit("prewrite_queue", before);
            if (before.Status != 0 || before.Count != 0)
                throw new IOException("Receive queue is unavailable or nonempty; no query sent.");
            Emit("write_started", new { Hex = Convert.ToHexString(FixedModel.Query()), Bytes = 14 });
            BeforeCall();
            result.ApplicationWriteAttempts = 1;
            CountResult write = device.WriteFixedModelQuery();
            Emit("write_result", write);
            if (write.Status != 0 || write.Count != 14)
                throw new IOException("Fixed query write failed or was partial; no retry is permitted.");

            for (int index = 0; index < FixedModel.MaxReads && received.Count < FixedModel.ReplyBytes; index++)
            {
                int count = FixedModel.ReplyBytes - received.Count;
                BeforeCall();
                ReadResult read = device.Read(count);
                result.ReadCalls++;
                received.AddRange(read.Data);
                Emit("read_result", new { Index = index, Requested = count, read.Status,
                    read.ReportedCount, RawHex = Convert.ToHexString(read.Data) });
                if (read.Status != 0 || read.ReportedCount > count || read.ReportedCount != read.Data.Length)
                    throw new IOException("Read failed or returned an invalid byte count.");
            }
            if (received.Count != FixedModel.ReplyBytes)
                throw new IOException("Incomplete fixed model reply; partial bytes retained.");
            AutoCalHostFrame frame = AutoCalHostFrame.ParseLongHeader(AutoCalHostDirection.DeviceToHost, received.ToArray());
            byte[] header = frame.OpaqueHeaderBytes;
            Emit("reply_validation", new { frame.CrcMatches, frame.StoredCrc, frame.ComputedCrc,
                RouteHex = Convert.ToHexString(header.AsSpan(0, 2)), OpaqueHeaderHex = Convert.ToHexString(header),
                PayloadHex = Convert.ToHexString(frame.Payload), frame.RxTrailingByte });
            if (!frame.CrcMatches || header[0] != 1 || header[1] != 0x82
                || !frame.Payload.AsSpan().SequenceEqual("ACV2\0"u8))
                throw new IOException("Reply route, CRC or model payload does not match ACV2.");
            BeforeCall();
            CountResult after = device.GetQueueStatus();
            Emit("postread_queue", after);
            if (after.Status != 0 || after.Count != 0)
                throw new IOException("Unexpected additional receive bytes or queue-status failure.");
            result.ModelVerified = true;
        }
        catch (Exception error)
        {
            result.Error = $"{error.GetType().Name}: {error.Message}";
            Emit("session_failed", new { result.Error });
        }
        finally
        {
            result.ReceivedHex = Convert.ToHexString(received.ToArray());
            if (device.OwnsHandle)
            {
                Emit("close_started");
                try
                {
                    uint status = device.CloseOwnedHandle();
                    result.OwnedHandleClosed = status == 0 && !device.OwnsHandle;
                    Emit("close_result", new { Status = status, result.OwnedHandleClosed });
                }
                catch (Exception error) { Emit("close_exception", new { Error = error.ToString() }); }
            }
            result.CleanupPending = device.OwnsHandle;
        }
        return result;
    }
}
