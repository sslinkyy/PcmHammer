// SPDX-License-Identifier: GPL-3.0-only
// Offline synthetic data only. No native DLL, serial port, controller or tune file is opened.
using System.Security.Cryptography;
using System.Text.Json;
using PcmHacking;
using Tests;

internal static class Program
{
    const uint Osid = 15189044;
    static void Check(bool value, string detail) { if (!value) throw new Exception(detail); }

    // The signatures/checksums only make the in-memory fixture parseable. This is not firmware.
    static byte[] Image()
    {
        byte[] data = new byte[512 * 1024];
        data[0x1FFFE] = data[0x7FFFE] = 0x4A;
        data[0x1FFFF] = data[0x7FFFF] = 0xFC;
        Put32(data, 0x20004, Osid);
        foreach (var range in new[] {(0x20002,0x6FFFF,0x20000),(0x8002,0x19FFF,0x8000),
            (0x1A002,0x1C7FF,0x1A000),(0x1C002,0x1DFFF,0x1C000),(0x1E002,0x1EFFF,0x1E000),(0x1F002,0x1FFEF,0x1F000)})
        {
            ushort sum = 0;
            for (int i = range.Item1; i <= range.Item2; i += 2) sum = unchecked((ushort)(sum + (data[i] << 8) + data[i + 1]));
            sum = unchecked((ushort)-sum); data[range.Item3] = (byte)(sum >> 8); data[range.Item3 + 1] = (byte)sum;
        }
        return data;
    }
    static void Put32(byte[] b, int at, uint value) { for (int n = 0; n < 4; n++) b[at + n] = (byte)(value >> (24 - 8 * n)); }
    static uint Read24(byte[] b, int at) => (uint)((b[at] << 16) | (b[at + 1] << 8) | b[at + 2]);

    sealed class ScriptedDevice : Device
    {
        readonly byte[] image;
        public readonly List<byte[]> Sent = new();
        public readonly List<uint> Erases = new();
        public readonly List<(uint Address, int Bytes, bool Test)> Blocks = new();
        public readonly List<string> Events = new();
        public int CrcQueries, ResetCommands, SyntheticKernelUploads;
        public Func<int, bool?> CrcMatches = _ => true;
        public Action<int>? AfterCrc;
        public Action? AfterErase;
        public bool RejectErase, ThrowErase, ThrowProgram, ReturnNoChip;
        public uint ReturnedOsid = Osid;
        public ScriptedDevice(byte[] image, ILogger log) : base(log)
        { this.image = image; MaxSendSize = 1036; MaxReceiveSize = 1036; Supports4X = false; }
        public override Task<bool> SendMessage(Message message)
        {
            byte[] b = message.GetBytes(); Sent.Add(b);
            if (b.Length >= 5 && b[3] == 0x3D)
            {
                switch (b[4])
                {
                    case 0x00: Reply(new byte[] { 0x6C, 0xF0, 0x10, 0x7D, 0, 0x6A, 0xB1, 0x78, 0xEC, 0x36 }); break;
                    case 0x01: if (!ReturnNoChip) Reply(new byte[] { 0x6C, 0xF0, 0x10, 0x7D, 1, 0, 0x89, 0x44, 0x71 }); break;
                    case 0x03:
                        byte[] os = new byte[] { 0x6C, 0xF0, 0x10, 0x7D, 3, 0, 0, 0, 0 }; Put32(os, 5, ReturnedOsid); Reply(os); break;
                    case 0x02:
                        CrcQueries++; Events.Add("compare"); bool? match = CrcMatches(CrcQueries);
                        if (match.HasValue)
                        {
                            uint crc = new Crc().GetCrc(image, Read24(b, 8), Read24(b, 5));
                            if (!match.Value) crc ^= 1;
                            byte[] reply = new byte[15]; Array.Copy(b, reply, 11); reply[1] = 0xF0; reply[2] = 0x10; reply[3] = 0x7D;
                            Put32(reply, 11, crc); Reply(reply);
                        }
                        AfterCrc?.Invoke(CrcQueries); break;
                    case 0x05:
                        Erases.Add(Read24(b, 5)); Events.Add("erase");
                        if (ThrowErase) throw new IOException("synthetic erase exception");
                        Reply(new byte[] { 0x6C, 0xF0, 0x10, 0x7D, 5, (byte)(RejectErase ? 1 : 0), 0 }); AfterErase?.Invoke(); break;
                    default: throw new Exception("Unexpected kernel command " + b[4]);
                }
            }
            else if (b.Length >= 4 && b[3] == 0x34)
            {
                Reply(new byte[] { 0x6C, 0xF0, 0x10, 0x74, 0, 0x44 });
            }
            else if (b.Length >= 10 && b[3] == 0x36 && b[4] == 0x80)
            {
                Check(b.Length == 28 && b.AsSpan(10, 16).ToArray().All(value => value == 0), "only generated stub upload");
                SyntheticKernelUploads++;
                Reply(new byte[] { 0x6C, 0xF0, 0x10, 0x76, 0x80, 0 });
            }
            else if (b.Length >= 10 && b[3] == 0x36)
            {
                if (ThrowProgram) throw new IOException("synthetic program exception");
                int count = (b[5] << 8) | b[6]; uint address = Read24(b, 7);
                Check(b.Length == count + 12, "block length");
                Check(b.AsSpan(10, count).SequenceEqual(image.AsSpan((int)address, count)), "exact source payload");
                Blocks.Add((address, count, b[4] == 0x44)); Events.Add("block");
                Reply(new byte[] { 0x6C, 0xF0, 0x10, 0x76, b[4], 0 });
            }
            else if (b.Length >= 4 && b[3] == 0x20) { ResetCommands++; Events.Add("reset"); }
            // Other messages are tool-present, chatter suppression, ordinary OS query or cleanup.
            return Task.FromResult(true);
        }
        void Reply(byte[] b) => Enqueue(new Message(b));
        public override Task<bool> Initialize() => Task.FromResult(true);
        public override Task<TimeoutScenario> SetTimeout(TimeoutScenario scenario)
        { var previous = currentTimeoutScenario; currentTimeoutScenario = scenario; return Task.FromResult(previous); }
        public override Task<bool> IsCommandBroadcasting(byte command) => Task.FromResult(false);
        public override string GetDeviceType() => "Offline scripted device";
        public override Task<bool> CheckDeviceConnection() => Task.FromResult(true);
        public override void ClearMessageBuffer() { }
        protected override Task<bool> SetVpwSpeedInternal(VpwSpeed speed) => Task.FromResult(true);
        protected override Task Receive() => Task.CompletedTask;
        protected override void Dispose(bool disposing) { }
    }

    sealed class Fixture : IDisposable
    {
        public readonly byte[] Data = Image();
        public readonly TestLogger Log = new();
        public readonly ScriptedDevice Device;
        public readonly Vehicle Vehicle;
        public readonly CancellationTokenSource Cancel = new();
        public readonly Protocol Protocol = new();
        public readonly OSIDInfo Info;
        readonly string? stubDirectory;
        readonly string? stubFile;
        public Fixture(PcmType type = PcmType.E54, bool freshKernel = false)
        {
            Device = new ScriptedDevice(Data, Log); Info = new OSIDInfo(type);
            if (freshKernel)
            {
                Check(type == PcmType.E54 && !Info.LoaderRequired, "fresh stub supports E54 only");
                stubDirectory = Path.Combine(AppContext.BaseDirectory, "synthetic-kernel-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(stubDirectory);
                stubFile = Path.Combine(stubDirectory, Info.KernelFileName);
                File.WriteAllBytes(stubFile, new byte[16]);
            }
            Vehicle = new Vehicle(Device, Protocol, Log, new ToolPresentNotifier(Device, Protocol, Log), stubDirectory ?? "unused-offline");
        }
        public Task<bool> Run(CKernelWriter? writer = null, WriteType type = WriteType.Calibration, byte[]? image = null, ulong kernelVersion = 1)
            => (writer ?? new CKernelWriter(Vehicle, Info, Protocol, type, Log)).Write(image ?? Data, kernelVersion,
                new FileValidator(Data, Log, PcmType.E54), true, Cancel.Token);
        public bool FlashSuccess => Log.UserMessages.ToString().Contains("Flash successful!");
        public void Dispose()
        {
            Cancel.Dispose(); Device.Dispose();
            if (stubFile != null) File.Delete(stubFile);
            if (stubDirectory != null) Directory.Delete(stubDirectory); // Empty owned directory only; never recursive.
        }
    }

    // Narrow virtual operations allow impossible result contracts without a second writer loop.
    sealed class BoundaryWriter : CKernelWriter
    {
        readonly Fixture fixture;
        public int Compares, RangeWrites;
        public Func<int, CrcVerificationResult?>? OverrideCompare;
        public Func<Response<bool>>? OverrideWrite;
        public bool FastWrite;
        public BoundaryWriter(Fixture f, WriteType type = WriteType.Calibration) : base(f.Vehicle, f.Info, f.Protocol, type, f.Log) { fixture = f; }
        protected override async Task<CrcVerificationResult> CompareRanges(CKernelVerifier verifier, byte[] image, BlockType blocks, CancellationToken token)
        {
            Compares++; var result = OverrideCompare?.Invoke(Compares);
            return result ?? await base.CompareRanges(verifier, image, blocks, token);
        }
        protected override Task<Response<bool>> WriteMemoryRange(MemoryRange range, byte[] image, bool justTest,
            DateTime start, uint total, uint remaining, CancellationToken token)
        {
            RangeWrites++; Check(range.Address == 0x8000 && range.Size == 0x18000, "calibration range only");
            if (OverrideWrite != null) return Task.FromResult(OverrideWrite());
            if (FastWrite) return Task.FromResult(Response.Create(ResponseStatus.Success, true));
            return base.WriteMemoryRange(range, image, justTest, start, total, remaining, token);
        }
    }

    static IEnumerable<(string, Func<Task>)> Cases()
    {
        yield return ("ordinary equal performs no erase", async () =>
        {
            using var f = new Fixture();
            Check(await f.Run(), "success");
            Check(f.Device.Erases.Count == 0 && f.Device.Blocks.Count == 0 && f.Device.ResetCommands == 1, "no write, one cleanup");
        }
        );
        yield return ("real protocol calibration write and verification", async () =>
        {
            using var f = new Fixture();
            f.Device.CrcMatches = n => n > 1;
            Check(await f.Run(), "success");
            Check(f.Device.CrcQueries == 2 && f.Device.Erases.SequenceEqual(new uint[] { 0x8000 }), "one pass then CRC");
            Check(f.Device.Blocks.Count == 96 && f.Device.Blocks.All(b => !b.Test && b.Bytes == 1024) && f.Device.Blocks.Select(b => b.Address).SequenceEqual(Enumerable.Range(0, 96).Select(n => 0x8000u + (uint)n * 1024)), "all 96 exact calibration blocks");
            Check(f.Device.Events.LastIndexOf("compare") < f.Device.Events.IndexOf("reset"), "verify before reset");
        }
        );
        yield return ("fifth pass gets final verification", async () =>
        {
            using var f = new Fixture();
            f.Device.CrcMatches = n => n > 5;
            var w = new BoundaryWriter(f) { FastWrite = true };
            Check(await f.Run(w), "fifth pass success");
            Check(f.Device.CrcQueries == 6 && f.Device.Erases.Count == 5 && w.RangeWrites == 5 && f.Device.ResetCommands == 1, "five writes then sixth comparison");
        }
        );
        yield return ("exhausted E54 mismatch adds no erase or reset", async () =>
        {
            using var f = new Fixture();
            f.Device.CrcMatches = _ => false;
            var w = new BoundaryWriter(f) { FastWrite = true };
            Check(!await f.Run(w), "failure");
            Check(f.Device.Erases.Count == 5 && w.RangeWrites == 5 && f.Device.CrcQueries == 6 && f.Device.ResetCommands == 0 && !f.FlashSuccess, "bounded failure");
        }
        );
        yield return ("timeout after write cannot reset", async () =>
        {
            using var f = new Fixture();
            f.Device.CrcMatches = n => n == 1 ? false : null;
            var w = new BoundaryWriter(f) { FastWrite = true };
            Check(!await f.Run(w), "timeout false");
            Check(f.Device.Erases.Count == 1 && f.Device.ResetCommands == 0 && !f.FlashSuccess, "retain uncertain state");
        }
        );
        yield return ("cancel during successful final CRC cannot succeed", async () =>
        {
            using var f = new Fixture();
            f.Device.CrcMatches = n => n > 1;
            f.Device.AfterCrc = n =>
            {
                if (n == 2) f.Cancel.Cancel();
            };
            var w = new BoundaryWriter(f) { FastWrite = true };
            Check(!await f.Run(w), "cancel false");
            Check(f.Device.ResetCommands == 0 && !f.FlashSuccess, "no reset or success");
        }
        );
        yield return ("cancel before entry sends nothing", async () =>
        {
            using var f = new Fixture();
            f.Cancel.Cancel();
            Check(!await f.Run(), "cancel false");
            Check(f.Device.Sent.Count == 0, "no messages");
        }
        );
        yield return ("erase refusal stops before programming", async () =>
        {
            using var f = new Fixture();
            f.Device.CrcMatches = _ => false;
            f.Device.RejectErase = true;
            Check(!await f.Run(), "erase false");
            Check(f.Device.Erases.Count == 1 && f.Device.Blocks.Count == 0 && f.Device.ResetCommands == 0, "no extra erase/reset");
        }
        );
        yield return ("erase exception stops before programming", async () =>
        {
            using var f = new Fixture();
            f.Device.CrcMatches = _ => false;
            f.Device.ThrowErase = true;
            Check(!await f.Run(), "erase exception false");
            Check(f.Device.Erases.Count == 1 && f.Device.ResetCommands == 0, "no extra erase/reset");
        }
        );
        yield return ("cancel after erase prevents programming", async () =>
        {
            using var f = new Fixture();
            f.Device.CrcMatches = _ => false;
            f.Device.AfterErase = () => f.Cancel.Cancel();
            Check(!await f.Run(), "cancel false");
            Check(f.Device.Erases.Count == 1 && f.Device.Blocks.Count == 0 && f.Device.ResetCommands == 0, "no program/reset after cancellation");
        }
        );
        yield return ("program exception cannot succeed", async () =>
        {
            using var f = new Fixture();
            f.Device.CrcMatches = _ => false;
            f.Device.ThrowProgram = true;
            Check(!await f.Run(), "write exception false");
            Check(f.Device.Erases.Count == 1 && f.Device.ResetCommands == 0 && !f.FlashSuccess, "no reset/success");
        }
        );
        yield return ("Success false write result stops", async () =>
        {
            using var f = new Fixture();
            f.Device.CrcMatches = n => n > 1;
            var w = new BoundaryWriter(f) { OverrideWrite = () => Response.Create(ResponseStatus.Success, false) };
            Check(!await f.Run(w), "false contract");
            Check(w.RangeWrites == 1 && f.Device.CrcQueries == 1 && f.Device.ResetCommands == 0, "no verification success after failed write");
        }
        );
        yield return ("error write result stops", async () =>
        {
            using var f = new Fixture();
            f.Device.CrcMatches = n => n > 1;
            var w = new BoundaryWriter(f) { OverrideWrite = () => Response.Create(ResponseStatus.Error, true) };
            Check(!await f.Run(w), "error contract");
            Check(w.RangeWrites == 1 && f.Device.ResetCommands == 0 && !f.FlashSuccess, "no reset/success");
        }
        );
        yield return ("unknown CRC result fails closed", async () =>
        {
            using var f = new Fixture();
            var w = new BoundaryWriter(f) { OverrideCompare = _ => (CrcVerificationResult)777 };
            Check(!await f.Run(w), "unknown false");
            Check(f.Device.Erases.Count == 0 && f.Device.ResetCommands == 0 && !f.FlashSuccess, "existing kernel retained");
        }
        );
        yield return ("cancelled CRC result fails closed", async () =>
        {
            using var f = new Fixture();
            var w = new BoundaryWriter(f) { OverrideCompare = _ => CrcVerificationResult.Cancelled };
            Check(!await f.Run(w), "cancelled false");
            Check(f.Device.Erases.Count == 0 && f.Device.ResetCommands == 0, "existing kernel retained");
        }
        );
        yield return ("OS mismatch prevents erase", async () =>
        {
            using var f = new Fixture();
            f.Device.ReturnedOsid = 15189045;
            Check(!await f.Run(), "OS false");
            Check(f.Device.Erases.Count == 0 && f.Device.ResetCommands == 0, "no erase/reset");
        }
        );
        yield return ("existing E54 kernel retained on image size mismatch", async () =>
        {
            using var f = new Fixture();
            Check(!await f.Run(image: new byte[256 * 1024]), "size false");
            Check(f.Device.ResetCommands == 0 && f.Device.Erases.Count == 0, "no reset/erase");
        }
        );
        yield return ("existing E54 kernel retained on flash ID timeout", async () =>
        {
            using var f = new Fixture();
            f.Device.ReturnNoChip = true;
            Check(!await f.Run(), "chip false");
            Check(f.Device.ResetCommands == 0 && f.Device.Erases.Count == 0, "no reset/erase");
        }
        );
        yield return ("fresh kernel erase exception is marked uncertain before call", async () =>
        {
            using var f = new Fixture(freshKernel: true);
            f.Device.CrcMatches = _ => false;
            f.Device.ThrowErase = true;
            Check(!await f.Run(kernelVersion: 0), "erase exception false");
            Check(f.Device.SyntheticKernelUploads == 1 && f.Device.Erases.Count == 1 && f.Device.ResetCommands == 0 && f.Log.UserMessages.ToString().Contains("E54 flash contents are not verified"), "new uncertain erase retained");
        }
        );
        yield return ("fresh kernel pre-erase size rejection cleans once", async () =>
        {
            using var f = new Fixture(freshKernel: true);
            Check(!await f.Run(image: new byte[256 * 1024], kernelVersion: 0), "size false");
            Check(f.Device.SyntheticKernelUploads == 1 && f.Device.Erases.Count == 0 && f.Device.ResetCommands == 1, "fresh pre-erase cleanup once");
        }
        );
        yield return ("non E54 size mismatch keeps cleanup", async () =>
        {
            using var f = new Fixture(PcmType.P01);
            Check(!await f.Run(image: new byte[256 * 1024]), "size false");
            Check(f.Device.ResetCommands == 1, "existing nonE54 cleanup");
        }
        );
        yield return ("non E54 exhausted calibration retains extra erase policy", async () =>
        {
            using var f = new Fixture(PcmType.P01);
            f.Device.CrcMatches = _ => false;
            var w = new BoundaryWriter(f) { FastWrite = true };
            Check(!await f.Run(w), "failure");
            Check(f.Device.Erases.Count == 6 && f.Device.ResetCommands == 0, "old nonE54 extra erase behavior");
        }
        );
        yield return ("TestWrite never erases", async () =>
        {
            using var f = new Fixture();
            var w = new BoundaryWriter(f, WriteType.TestWrite) { FastWrite = true };
            Check(await f.Run(w), "test success");
            Check(f.Device.Erases.Count == 0 && w.RangeWrites == 1 && f.Device.CrcQueries == 2 && f.Device.ResetCommands == 1, "test control");
        }
        );
        yield return ("Compare mismatch never writes", async () =>
        {
            using var f = new Fixture();
            f.Device.CrcMatches = _ => false;
            Check(await f.Run(type: WriteType.Compare), "compare completes");
            Check(f.Device.Erases.Count == 0 && f.Device.Blocks.Count == 0 && f.Device.ResetCommands == 1, "compare control");
        }
        );
        yield return ("manager propagates actual writer failure", async () =>
        {
            using var f = new Fixture();
            Check(new FileValidator(f.Data, f.Log).IsValid(), "synthetic image validates");
            f.Device.CrcMatches = _ => null;
            var manager = new WriteManager(f.Log, f.Vehicle, WriteType.Calibration, (_, _) => Task.CompletedTask, (_, _) => Task.FromResult(true), f.Cancel.Token);
            Check(!await manager.Write(f.Data), "manager false");
            Check(f.Device.CrcQueries >= 6 && f.Log.UserMessages.ToString().Contains("PCM stopped responding during CRC check"), "reached actual writer timeout");
            Check(f.Device.ResetCommands == 0 && !f.FlashSuccess, "failure preserved");
        }
        );
        yield return ("AL5 segment rejected before device access", async () =>
        {
            using var f = new Fixture();
            var manager = new WriteManager(f.Log, f.Vehicle, WriteType.Calibration, (_, _) => Task.CompletedTask, (_, _) => Task.FromResult(true), f.Cancel.Token);
            Check(!await manager.Write(new byte[AL5CalibrationReader.Length], PcmType.E54), "AL5 false");
            Check(f.Device.Sent.Count == 0, "AL5 gate precedes queries");
        }
        );
    }

    static async Task<int> Main(string[] args)
    {
        if (args.Length != 2 || args[0] != "--receipt") throw new ArgumentException("Use --receipt <new JSON path>. This executable has no hardware mode.");
        using var output = new FileStream(args[1], FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        var results = new List<object>(); int failures = 0;
        foreach (var (name, run) in Cases())
        {
            try { await run(); results.Add(new { name, passed = true }); Console.WriteLine("PASS " + name); }
            catch (Exception error) { failures++; results.Add(new { name, passed = false, error = error.ToString() }); Console.WriteLine("FAIL " + name + ": " + error.Message); }
        }
        string library = typeof(CKernelWriter).Assembly.Location;
        var receipt = new
        {
            schema = "ckernel-writer-safety-offline-v1",
            hardware_access = false,
            library,
            library_sha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(library))).ToLowerInvariant(),
            count = results.Count,
            failed = failures,
            results
        };
        JsonSerializer.Serialize(output, receipt, new JsonSerializerOptions { WriteIndented = true }); output.Flush(true);
        Console.WriteLine($"{results.Count} tests, {failures} failed; no hardware."); return failures == 0 ? 0 : 1;
    }
}
