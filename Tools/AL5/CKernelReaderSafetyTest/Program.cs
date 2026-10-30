// SPDX-License-Identifier: GPL-3.0-only
// In-memory Device only. The generated 16-byte kernel stub is never executed.
using System.Security.Cryptography;
using System.Text.Json;
using PcmHacking;
using Tests;

internal static class Program
{
    static void Check(bool value, string detail) { if (!value) throw new Exception(detail); }
    static uint Read24(byte[] b, int at) => (uint)((b[at] << 16) | (b[at + 1] << 8) | b[at + 2]);
    static void Put32(byte[] b, int at, uint value)
    { for (int n = 0; n < 4; n++) b[at + n] = (byte)(value >> (24 - 8 * n)); }

    sealed class ScriptedDevice : Device
    {
        readonly byte[] image;
        public readonly List<(uint Address, int Length)> Reads = new();
        public int CrcQueries, Resets, StubUploads;
        public Func<int, bool?> CrcMatches = _ => true;
        public Action<int>? AfterCrc, AfterRead;
        public bool DropReadReplies, CorruptReadChecksum;
        public ScriptedDevice(byte[] image, ILogger log) : base(log)
        { this.image = image; MaxSendSize = 1772; MaxReceiveSize = 4108; Supports4X = false; Enable4xReadWrite = false; }
        public override Task<bool> SendMessage(Message message)
        {
            byte[] b = message.GetBytes();
            if (b.Length >= 5 && b[3] == 0x3D)
            {
                switch (b[4])
                {
                    case 0: Reply(Convert.FromHexString("6CF0107D006AB178EC36")); break;
                    case 1: Reply(Convert.FromHexString("6CF0107D0100894471")); break;
                    case 2:
                        CrcQueries++; bool? matches = CrcMatches(CrcQueries);
                        if (matches.HasValue)
                        {
                            uint crc = new Crc().GetCrc(image, Read24(b, 8), Read24(b, 5));
                            if (!matches.Value) crc ^= 1;
                            byte[] reply = new byte[15]; Array.Copy(b, reply, 11);
                            reply[1] = 0xF0; reply[2] = 0x10; reply[3] = 0x7D;
                            Put32(reply, 11, crc); Reply(reply);
                        }
                        AfterCrc?.Invoke(CrcQueries); break;
                    default: throw new Exception("Unpermitted kernel command in reader: " + b[4]);
                }
            }
            else if (b.Length >= 4 && b[3] == 0x34)
                Reply(Convert.FromHexString("6CF010740044"));
            else if (b.Length >= 10 && b[3] == 0x36)
            {
                Check(b[4] == 0x80 && b.Length == 28 && b.AsSpan(10, 16).ToArray().All(x => x == 0),
                    "only generated 16-byte execute stub; no flash programming");
                StubUploads++; Reply(Convert.FromHexString("6CF010768000"));
            }
            else if (b.Length == 10 && b[3] == 0x35 && b[4] == 1)
            {
                int length = (b[5] << 8) | b[6]; uint address = Read24(b, 7);
                Check(length == 4096 && address + length <= image.Length, "bounded full-image block");
                Reads.Add((address, length));
                if (!DropReadReplies)
                {
                    byte[] reply = new byte[length + 12]; Array.Copy(b, reply, 10);
                    reply[1] = 0xF0; reply[2] = 0x10; reply[3] = 0x36;
                    Array.Copy(image, (int)address, reply, 10, length);
                    VpwUtilities.AddBlockChecksum(reply);
                    if (CorruptReadChecksum) reply[reply.Length - 1] ^= 1;
                    Reply(reply);
                }
                AfterRead?.Invoke(Reads.Count);
            }
            else if (b.Length >= 5 && b[3] == 0x27 && b[4] == 1)
                Reply(Convert.FromHexString("6CF01067010000")); // Already unlocked seed, no key search.
            else if (b.Length >= 4 && b[3] == 0x20) Resets++;
            // Remaining production messages are tool-present, chatter suppression and DTC cleanup.
            return Task.FromResult(true);
        }
        void Reply(byte[] bytes) => Enqueue(new Message(bytes));
        public override Task<bool> Initialize() => Task.FromResult(true);
        public override Task<TimeoutScenario> SetTimeout(TimeoutScenario scenario)
        { var old = currentTimeoutScenario; currentTimeoutScenario = scenario; return Task.FromResult(old); }
        public override Task<bool> IsCommandBroadcasting(byte command) => Task.FromResult(false);
        public override string GetDeviceType() => "In-memory reader test device";
        public override Task<bool> CheckDeviceConnection() => Task.FromResult(true);
        public override void ClearMessageBuffer() { }
        protected override Task<bool> SetVpwSpeedInternal(VpwSpeed speed) => Task.FromResult(false);
        protected override Task Receive() => Task.CompletedTask;
        protected override void Dispose(bool disposing) { }
    }

    sealed class Fixture : IDisposable
    {
        public readonly byte[] Data = Enumerable.Range(0, 512 * 1024).Select(i => (byte)((i * 37 + i / 4096) & 255)).ToArray();
        public readonly TestLogger Log = new();
        public readonly OSIDInfo Info = new(PcmType.E54);
        public readonly ScriptedDevice Device;
        public readonly Vehicle Vehicle;
        public readonly CancellationTokenSource Cancel = new();
        readonly string directory, kernel;
        public string Output => Path.Combine(directory, "result.bin");
        public string BadRead => Path.Combine(directory, "result_badread.bin");
        public Fixture()
        {
            directory = Path.Combine(AppContext.BaseDirectory, "synthetic-reader-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory); kernel = Path.Combine(directory, Info.KernelFileName);
            File.WriteAllBytes(kernel, new byte[16]);
            Device = new(Data, Log); var protocol = new Protocol();
            Vehicle = new(Device, protocol, Log, new ToolPresentNotifier(Device, protocol, Log), directory);
        }
        public CKernelReader Reader() => new(Vehicle, Info, Log) { CrcPollingDelayMs = 0 };
        public ReadManager Manager() => new(Log, Vehicle, a => { a(); return Task.CompletedTask; },
            () => Task.FromResult<string?>(null), () => Task.FromResult(15189044u),
            (_, _) => Task.CompletedTask, (_, _) => Task.FromResult(false), Cancel.Token) { CrcPollingDelayMs = 0 };
        public void CheckFullRead()
        {
            Check(Device.Reads.Count == 128 && Device.Reads.Select(x => x.Address).SequenceEqual(
                Enumerable.Range(0, 128).Select(n => (uint)n * 4096)), "exact 512KiB coverage");
            Check(Device.StubUploads == 1 && Device.Resets == 1, "one synthetic upload and one existing cleanup reset");
        }
        public void Dispose()
        {
            Cancel.Dispose(); Device.Dispose();
            foreach (string path in new[] { kernel, Output, BadRead }) if (File.Exists(path)) File.Delete(path);
            Directory.Delete(directory); // Owned empty fixture directory, never recursive.
        }
    }

    // Inject only contracts that real CRC parsing cannot produce. All upload/read/cleanup stays real.
    sealed class BoundaryReader : CKernelReader
    {
        readonly Func<CrcVerificationResult> compare;
        public BoundaryReader(Fixture f, Func<CrcVerificationResult> compare) : base(f.Vehicle, f.Info, f.Log) { this.compare = compare; }
        protected override Task<CrcVerificationResult> CompareRanges(CKernelVerifier verifier, byte[] image, CancellationToken token)
            => Task.FromResult(compare());
    }
    static async Task Status(Fixture f, ResponseStatus expected, CKernelReader? reader = null, bool full = true)
    {
        var result = await (reader ?? f.Reader()).ReadContents(f.Cancel.Token);
        Check(result.Status == expected, "expected " + expected + ", got " + result.Status);
        if (expected == ResponseStatus.Success || expected == ResponseStatus.Unverified)
        {
            Check(result.Value != null, "read stream retained");
            using var stream = result.Value!; using var copy = new MemoryStream();
            await stream.CopyToAsync(copy); Check(copy.ToArray().SequenceEqual(f.Data), "exact synthetic image");
        }
        else Check(result.Value == null, "failed/cancelled verification exposes no successful stream");
        if (full) f.CheckFullRead();
    }

    static IEnumerable<(string, Func<Task>)> Cases()
    {
        yield return ("verified full read returns exact image", async () =>
        { using var f = new Fixture(); await Status(f, ResponseStatus.Success); Check(f.Device.CrcQueries == 7, "seven CRC ranges"); });
        yield return ("CRC mismatch cannot return success", async () =>
        { using var f = new Fixture(); f.Device.CrcMatches = n => n != 4; await Status(f, ResponseStatus.Error); Check(f.Device.CrcQueries == 7, "all seven CRC ranges inspected"); });
        yield return ("CRC timeout remains Unverified", async () =>
        { using var f = new Fixture(); f.Device.CrcMatches = _ => null; await Status(f, ResponseStatus.Unverified); Check(f.Device.CrcQueries == 42, "six bounded attempts for each of seven ranges"); });
        yield return ("cancel during CRC returns Cancelled", async () =>
        { using var f = new Fixture(); f.Device.AfterCrc = n => f.Cancel.Cancel(); await Status(f, ResponseStatus.Cancelled); Check(f.Device.CrcQueries == 1, "no further CRC request"); });
        yield return ("cancel with final matching CRC cannot succeed", async () =>
        { using var f = new Fixture(); f.Device.AfterCrc = n => { if (n == 7) f.Cancel.Cancel(); }; await Status(f, ResponseStatus.Cancelled); });
        yield return ("unknown verifier result fails closed", async () =>
        { using var f = new Fixture(); await Status(f, ResponseStatus.Error, new BoundaryReader(f, () => (CrcVerificationResult)987)); });
        yield return ("Cancelled verifier contract without token fails closed", async () =>
        { using var f = new Fixture(); await Status(f, ResponseStatus.Cancelled, new BoundaryReader(f, () => CrcVerificationResult.Cancelled)); });
        yield return ("cancellation overrides timeout salvage", async () =>
        { using var f = new Fixture(); await Status(f, ResponseStatus.Cancelled, new BoundaryReader(f, () => { f.Cancel.Cancel(); return CrcVerificationResult.Timeout; })); });
        yield return ("cancel on final data block cannot produce a file", async () =>
        { using var f = new Fixture(); f.Device.AfterRead = n => { if (n == 128) f.Cancel.Cancel(); }; await Status(f, ResponseStatus.Cancelled); Check(f.Device.CrcQueries == 0, "no verification after cancelled transfer"); });
        yield return ("cancelled transport task reports cancellation", async () =>
        { using var f = new Fixture(); f.Device.AfterCrc = n => { f.Cancel.Cancel(); throw new OperationCanceledException(f.Cancel.Token); }; await Status(f, ResponseStatus.Cancelled); });
        yield return ("missing data reply cannot succeed", async () =>
        { using var f = new Fixture(); f.Device.DropReadReplies = true; await Status(f, ResponseStatus.Error, full: false); Check(f.Device.CrcQueries == 0, "no verification of incomplete image"); });
        yield return ("bad block checksum cannot succeed", async () =>
        { using var f = new Fixture(); f.Device.CorruptReadChecksum = true; await Status(f, ResponseStatus.Error, full: false); Check(f.Device.CrcQueries == 0, "no verification of corrupt transfer"); });
        yield return ("ReadManager mismatch saves no file", async () =>
        { using var f = new Fixture(); f.Device.CrcMatches = _ => false; Check(!await f.Manager().Read(f.Output, PcmType.E54), "manager reports failure"); Check(!File.Exists(f.Output) && !File.Exists(f.BadRead), "no file saved"); f.CheckFullRead(); });
        yield return ("ReadManager cancellation saves no file", async () =>
        { using var f = new Fixture(); f.Device.AfterCrc = _ => f.Cancel.Cancel(); Check(!await f.Manager().Read(f.Output, PcmType.E54), "manager reports cancellation failure"); Check(!File.Exists(f.Output) && !File.Exists(f.BadRead), "no file saved"); });
        yield return ("ReadManager timeout keeps badread convention", async () =>
        { using var f = new Fixture(); f.Device.CrcMatches = _ => null; Check(await f.Manager().Read(f.Output, PcmType.E54), "manager retains diagnostic read"); Check(!File.Exists(f.Output) && File.ReadAllBytes(f.BadRead).SequenceEqual(f.Data), "only exact _badread image saved"); });
        yield return ("ReadManager verified read saves normal file", async () =>
        { using var f = new Fixture(); Check(await f.Manager().Read(f.Output, PcmType.E54), "manager reports success"); Check(File.ReadAllBytes(f.Output).SequenceEqual(f.Data) && !File.Exists(f.BadRead), "exact normal file only"); });
    }

    static async Task<int> Main(string[] args)
    {
        if (args.Length != 2 || args[0] != "--receipt" || File.Exists(args[1]))
            throw new ArgumentException("Use --receipt NEW.json; this harness has no hardware mode.");
        var results = new List<object>(); int failed = 0;
        foreach (var (name, test) in Cases())
        {
            try { await test(); results.Add(new { name, passed = true }); Console.WriteLine("PASS " + name); }
            catch (Exception error) { failed++; results.Add(new { name, passed = false, error = error.ToString() }); Console.WriteLine("FAIL " + name + ": " + error.Message); }
        }
        string library = typeof(CKernelReader).Assembly.Location;
        var receipt = new { schema = "ckernel-reader-safety-offline-v1", hardware_access = false, library,
            library_sha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(library))).ToLowerInvariant(),
            count = results.Count, failed, results,
            scope = "Production reader, Vehicle, CRC verifier, block parser and ReadManager with scripted in-memory Device and generated 512KiB image. Unknown/cancelled result contracts use only the CompareRanges seam. Generated 16-byte kernel stub is never executed." };
        using var output = new FileStream(args[1], FileMode.CreateNew, FileAccess.Write);
        JsonSerializer.Serialize(output, receipt, new JsonSerializerOptions { WriteIndented = true });
        Console.WriteLine($"Reader safety tests: {results.Count - failed}/{results.Count} passed.");
        return failed == 0 ? 0 : 1;
    }
}
